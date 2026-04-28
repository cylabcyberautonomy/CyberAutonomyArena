import asyncio
import heapq
import json
import logging
import os
import shutil
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

from .attacker import run_attacker
from .defender import run_defender
from .environment import DeployedEnvironment
from .environment.deployer import provision_environment, configure_environment
from .environment.teardown import teardown_environment
from .config import ExperimentManagerConfig
from .experiment import Experiment, ExperimentSpecs, ExperimentStatus, Registry
from .experiment_log import get_logger, init_logger, log

logger = logging.getLogger(__name__)


class _PriorityLock:
    """Priority semaphore that serves waiters in priority order (lower number = higher priority)."""

    def __init__(self, capacity: int = 1):
        self._capacity = capacity
        self._count = 0
        self._waiters: list[tuple[int, int, asyncio.Future]] = []
        self._seq = 0

    @asynccontextmanager
    async def acquire(self, priority: int = 0):
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._seq += 1
        heapq.heappush(self._waiters, (priority, self._seq, fut))
        self._wake_next()
        await fut
        try:
            yield
        finally:
            self._count -= 1
            self._wake_next()

    def _wake_next(self):
        while self._count < self._capacity and self._waiters:
            _, _, fut = heapq.heappop(self._waiters)
            if not fut.done():
                self._count += 1
                fut.set_result(None)


_PRIORITY_TEARDOWN = 0
_PRIORITY_DEPLOY = 1

cfg: ExperimentManagerConfig
registry: Registry
_openstack_lock: _PriorityLock


@asynccontextmanager
async def lifespan(app: FastAPI):
    global cfg, registry, _openstack_lock
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = ExperimentManagerConfig.load()
    registry = Registry(cfg.registry_path)
    _openstack_lock = _PriorityLock(cfg.max_concurrent_experiments)
    await _clean_slate()
    yield


async def _openstack_clean_slate() -> None:
    """Tear down all OpenStack resources except external networks and their subnets."""

    async def _run(*args: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "openstack", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()

    async def _exec(*args: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "openstack", *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0

    logger.info("Collecting external network IDs...")
    ext_raw = await _run("network", "list", "--external", "-f", "value", "-c", "ID")
    external_net_ids = set(ext_raw.splitlines()) if ext_raw else set()
    if external_net_ids:
        logger.info("External networks (will be preserved): %s", external_net_ids)

    logger.info("=== Deleting servers ===")
    for sid in (await _run("server", "list", "--all-projects", "-f", "value", "-c", "ID")).splitlines():
        if not sid:
            continue
        logger.info("Deleting server %s", sid)
        if not await _exec("server", "delete", sid, "--wait"):
            logger.warning("Failed to delete server %s", sid)

    logger.info("=== Releasing floating IPs ===")
    for fid in (await _run("floating", "ip", "list", "-f", "value", "-c", "ID")).splitlines():
        if not fid:
            continue
        logger.info("Deleting floating IP %s", fid)
        if not await _exec("floating", "ip", "delete", fid):
            logger.warning("Failed to delete floating IP %s", fid)

    logger.info("=== Cleaning up routers ===")
    for rid in (await _run("router", "list", "-f", "value", "-c", "ID")).splitlines():
        if not rid:
            continue
        gw = await _run("router", "show", rid, "-f", "value", "-c", "external_gateway_info")
        if gw and gw != "None":
            logger.info("Unsetting gateway on router %s", rid)
            if not await _exec("router", "unset", "--external-gateway", rid):
                logger.warning("Failed to unset gateway on router %s", rid)
        for port_id in (await _run("port", "list", "--router", rid, "-f", "value", "-c", "ID")).splitlines():
            if not port_id:
                continue
            logger.info("Removing port %s from router %s", port_id, rid)
            if not await _exec("router", "remove", "port", rid, port_id):
                logger.warning("Failed to remove port %s from router %s", port_id, rid)
        logger.info("Deleting router %s", rid)
        if not await _exec("router", "delete", rid):
            logger.warning("Failed to delete router %s", rid)

    logger.info("=== Deleting orphaned internal ports ===")
    port_raw = await _run("port", "list", "-f", "value", "-c", "ID", "-c", "network_id", "-c", "device_owner")
    for line in port_raw.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        pid, net_id = parts[0], parts[1]
        device_owner = parts[2] if len(parts) > 2 else ""
        if net_id in external_net_ids:
            continue
        if device_owner in {
            "network:dhcp",
            "network:router_interface",
            "network:router_interface_distributed",
            "network:router_gateway",
            "network:ha_router_replicated_interface",
        }:
            continue
        logger.info("Deleting port %s (owner: %s)", pid, device_owner)
        if not await _exec("port", "delete", pid):
            logger.warning("Failed to delete port %s", pid)

    logger.info("=== Deleting internal subnets ===")
    subnet_raw = await _run("subnet", "list", "-f", "value", "-c", "ID", "-c", "Name")
    for line in subnet_raw.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        sid = parts[0]
        sname = parts[1] if len(parts) > 1 else ""
        if "external" in sname.lower():
            logger.warning("Skipping external subnet: %s (%s)", sname, sid)
            continue
        logger.info("Deleting subnet %s (%s)", sname, sid)
        if not await _exec("subnet", "delete", sid):
            logger.warning("Failed to delete subnet %s", sid)

    logger.info("=== Deleting internal networks ===")
    for nid in (await _run("network", "list", "-f", "value", "-c", "ID")).splitlines():
        if not nid:
            continue
        if nid in external_net_ids:
            logger.warning("Skipping external network %s", nid)
            continue
        logger.info("Deleting network %s", nid)
        if not await _exec("network", "delete", nid):
            logger.warning("Failed to delete network %s", nid)

    logger.info("=== Deleting security groups ===")
    sg_raw = await _run("security group", "list", "-f", "value", "-c", "ID", "-c", "Name")
    for line in sg_raw.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        sgid = parts[0]
        sgname = parts[1] if len(parts) > 1 else ""
        if sgname.strip().lower() == "default":
            continue
        logger.info("Deleting security group %s (%s)", sgname, sgid)
        if not await _exec("security group", "delete", sgid):
            logger.warning("Failed to delete security group %s", sgid)

    logger.info("=== OpenStack teardown complete ===")


async def _clean_slate() -> None:
    """On startup, kill all running processes, stop C2 containers, tear down environments."""
    experiments = registry.load()

    for experiment in experiments:
        if experiment.pid:
            try:
                os.kill(experiment.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        if experiment.attacker and experiment.c2c_container_id:
            try:
                await experiment.attacker.stop_c2c(experiment.c2c_container_id)
            except Exception:
                logger.exception("Failed to stop C2 container for '%s'", experiment.experiment_name)

    await _openstack_clean_slate()

    for experiment in experiments:
        try:
            await registry.remove(experiment.experiment_name)
        except Exception:
            logger.exception("Failed to remove '%s' from registry", experiment.experiment_name)


async def _teardown(experiment: Experiment) -> None:
    experiment.teardown_started_at = datetime.now(timezone.utc)
    await registry.update(experiment)

    if experiment.attacker and experiment.c2c_container_id:
        try:
            c2c_log_path = cfg.output_dir / experiment.experiment_name / "attacker" / "c2c_server.log"
            c2c_log_path.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "docker", "logs", experiment.c2c_container_id,
                stdout=open(c2c_log_path, "w"), stderr=asyncio.subprocess.STDOUT,
            )
            await proc.wait()
        except Exception:
            get_logger(experiment.experiment_name).exception("Failed to save C2 container logs for '%s'", experiment.experiment_name)
        try:
            await experiment.attacker.stop_c2c(experiment.c2c_container_id)
        except Exception:
            get_logger(experiment.experiment_name).exception("Failed to stop C2 container for '%s'", experiment.experiment_name)

    try:
        async with _openstack_lock.acquire(_PRIORITY_TEARDOWN):
            try:
                await teardown_environment(experiment, cfg)
                experiment.teardown_finished_at = datetime.now(timezone.utc)
                await registry.update(experiment)
            except Exception:
                get_logger(experiment.experiment_name).exception("Failed to tear down environment for '%s'", experiment.experiment_name)
                return  # skip registry removal so we can investigate

    except Exception:
        get_logger(experiment.experiment_name).exception("Teardown failed for experiment '%s'", experiment.experiment_name)

async def _schedule_retry(experiment: Experiment) -> None:
    if cfg.max_retries <= 0:
        return

    base = experiment.base_name or experiment.experiment_name
    next_retry_count = experiment.retry_count + 1

    if next_retry_count > cfg.max_retries:
        get_logger(experiment.experiment_name).warning(
            "[%s] Retry budget exhausted (%d/%d), giving up.",
            experiment.experiment_name, experiment.retry_count, cfg.max_retries,
        )
        return

    src = cfg.output_dir / experiment.experiment_name
    dst = cfg.output_dir / "failed" / experiment.experiment_name
    src.mkdir(parents=True, exist_ok=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        shutil.rmtree(str(dst))
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, shutil.move, str(src), str(dst))
    get_logger(experiment.experiment_name).info(
        "[%s] Moved failed output to %s", experiment.experiment_name, dst
    )

    retry_name = f"{base}_{next_retry_count}"
    now = datetime.now(timezone.utc)
    retry_experiment = Experiment(
        experiment_name=retry_name,
        status=ExperimentStatus.QUEUED,
        environment_spec=experiment.environment_spec,
        attacker=experiment.attacker,
        defender=experiment.defender,
        retry_count=next_retry_count,
        base_name=base,
        created_at=now,
        updated_at=now,
    )

    try:
        await registry.add(retry_experiment)
    except ValueError:
        get_logger(experiment.experiment_name).exception(
            "[%s] Failed to register retry '%s' (name collision?)",
            experiment.experiment_name, retry_name,
        )
        return

    asyncio.create_task(_run_experiment(retry_experiment))
    get_logger(experiment.experiment_name).info(
        "[%s] Retry %d/%d scheduled as '%s'",
        experiment.experiment_name, next_retry_count, cfg.max_retries, retry_name,
    )


async def _run_experiment(experiment: Experiment) -> None:
    name = experiment.experiment_name
    exp_log = init_logger(name, cfg.output_dir)

    config_path = cfg.output_dir / name / "experiment" / "experiment_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(experiment.model_dump_json(indent=2))

    kali_c2c_url = None
    local_c2c_url = None

    try:
        container_id, kali_c2c_url, local_c2c_url = await experiment.attacker.launch_c2c(experiment.experiment_name, cfg)
        if container_id:
            experiment.c2c_container_id = container_id
            await registry.update(experiment)
        if local_c2c_url:
            await experiment.attacker.wait_c2c_ready(local_c2c_url, experiment.experiment_name)
    except Exception:
        exp_log.exception("Failed to start C2 server for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        await _teardown(experiment)
        await _schedule_retry(experiment)
        return

    experiment.deployed_environment = DeployedEnvironment(
        topology_spec=str(cfg.mhbench_dir / "environments" / f"{experiment.environment_spec}.json"),
    )
    await registry.update(experiment)

    mgmt_ip = None
    try:
        async with _openstack_lock.acquire(_PRIORITY_DEPLOY):

            experiment.status = ExperimentStatus.DEPLOYING
            experiment.environment_deploy_started_at = datetime.now(timezone.utc)
            await registry.update(experiment)

            try:
                deployed, mgmt_ip = await provision_environment(experiment, kali_c2c_url, cfg)
                experiment.deployed_environment = deployed
                await registry.update(experiment)
            except NotImplementedError:
                experiment.deployed_environment = None
                exp_log.warning("Deployer stub hit — proceeding without environment for '%s'", experiment.experiment_name)

            await configure_environment(experiment, mgmt_ip, kali_c2c_url, cfg)
            experiment.environment_deploy_finished_at = datetime.now(timezone.utc)
            await registry.update(experiment)

    except Exception:
        exp_log.exception("Failed to provision/configure environment for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        await _teardown(experiment)
        await _schedule_retry(experiment)
        return

    try:
        if local_c2c_url:
            await experiment.attacker.wait_c2c_agent(local_c2c_url, experiment.experiment_name)
    except Exception:
        exp_log.exception("No agent beaconed for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        tore_down = await _teardown(experiment)  # disabled for debugging
        if tore_down:
            await _schedule_retry(experiment)
        return

    defender_process = None
    if experiment.defender:
        try:
            defender_process = await run_defender(
                experiment.defender,
                experiment.deployed_environment,
                experiment.experiment_name,
                cfg,
            )
            experiment.defender_started_at = datetime.now(timezone.utc)
            await registry.update(experiment)
        except Exception:
            exp_log.exception("Failed to start defender for '%s'", experiment.experiment_name)

    try:
        process = await run_attacker(experiment.attacker, experiment.deployed_environment, experiment.experiment_name, cfg, c2c_server=kali_c2c_url)
    except Exception:
        exp_log.exception("Failed to start attacker for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        if defender_process:
            try:
                defender_process.terminate()
                await defender_process.wait()
            except Exception:
                pass
        tore_down = await _teardown(experiment)  # disabled for debugging
        if tore_down:
            await _schedule_retry(experiment)
        return

    experiment.pid = process.pid
    experiment.status = ExperimentStatus.RUNNING
    experiment.attacker_started_at = datetime.now(timezone.utc)
    await registry.update(experiment)

    returncode = None
    try:
        returncode = await process.wait()
        status = ExperimentStatus.FINISHED if returncode == 0 else ExperimentStatus.ERROR
    except Exception:
        exp_log.exception("Error waiting on attacker process for '%s'", experiment.experiment_name)
        status = ExperimentStatus.ERROR
    finally:
        if defender_process:
            try:
                defender_process.terminate()
                await defender_process.wait()
                experiment.defender_finished_at = datetime.now(timezone.utc)
            except Exception:
                exp_log.exception("Error stopping defender for '%s'", experiment.experiment_name)

    experiment.attacker_finished_at = datetime.now(timezone.utc)
    exp_log.info("[%s] Attacker finished (exit code %s, status: %s)", name, returncode, status)
    result_file = cfg.output_dir / experiment.experiment_name / "experiment" / "result.json"
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps({"status": status}))

    experiment.status = status
    await registry.update(experiment)
    await _teardown(experiment)  # disabled for debugging
    if status == ExperimentStatus.ERROR:
        await _schedule_retry(experiment)


app = FastAPI(title="Experiment Manager", lifespan=lifespan)


@app.post("/experiments", status_code=201)
async def add_experiment(data: ExperimentSpecs):
    now = datetime.now(timezone.utc)
    experiment = Experiment(
        experiment_name=data.experiment_name,
        status=ExperimentStatus.QUEUED,
        environment_spec=data.environment,
        attacker=data.attacker,
        defender=data.defender,
        created_at=now,
        updated_at=now,
    )

    try:
        await registry.add(experiment)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    asyncio.create_task(_run_experiment(experiment))
    return {"experiment_name": experiment.experiment_name, "status": experiment.status}


@app.get("/experiments")
async def list_experiments():
    return registry.load()


@app.get("/experiments/{experiment_name}")
async def get_experiment(experiment_name: str):
    try:
        return registry.get(experiment_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="Experiment not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("experiment_manager.main:app", reload=True)
