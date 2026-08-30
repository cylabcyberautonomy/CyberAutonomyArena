import asyncio
import heapq
import json
import logging
import os
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException

from .attacker import run_attacker
from .defender import run_defender
from .environment import DeployedEnvironment
from .environment.capacity import CapacityTracker, count_vm_specs
from .environment.deployer import provision_environment, configure_environment
from .environment.teardown import teardown_environment
from .environment.collect import collect_environment
from .environment.rotate import rotate_environment
from .config import ExperimentManagerConfig
from .experiment import Experiment, ExperimentSpecs, ExperimentStatus, Registry
from .experiment_log import get_logger, init_logger, log, output_root, register_output_root

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
_ACTIVE_STATUSES = {  # non-terminal / in-flight: their C2 must survive other experiments' launches — only ERROR/FINISHED C2s are stale
    ExperimentStatus.QUEUED, ExperimentStatus.DEPLOYING, ExperimentStatus.DEPLOYED,
    ExperimentStatus.CONFIGURING, ExperimentStatus.CONFIGURED, ExperimentStatus.RUNNING,
    ExperimentStatus.RETRYING,
}
_NUKE_BATCH = 20  # clean-slate deletes servers this many at a time — a whole-cluster batch overwhelmed nova/neutron

cfg: ExperimentManagerConfig
registry: Registry
_openstack_lock: _PriorityLock
_configure_lock: _PriorityLock
_deploy_buffer: asyncio.Semaphore
_capacity: CapacityTracker
_tasks: dict[str, asyncio.Task] = {}  # experiment_name -> its _run_experiment task; lets a single run be cancelled/evicted (rerun) without a whole-harness restart


@asynccontextmanager
async def lifespan(app: FastAPI):
    global cfg, registry, _openstack_lock, _configure_lock, _deploy_buffer, _capacity
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = ExperimentManagerConfig.load()
    load_dotenv(cfg.incalmo_dir / ".env")  # LLM keys into os.environ so the Incalmo subprocess (env={**os.environ,…}) always inherits them, however the harness was launched (bare uvicorn or main.sh). override=False → an already-exported key still wins.
    os.environ["OS_CLOUD"] = cfg.os_cloud
    registry = Registry(cfg.registry_path)
    _openstack_lock = _PriorityLock(cfg.max_concurrent_openstack_ops)     # concurrent PROVISION (active nova spin-up)
    _configure_lock = _PriorityLock(cfg.max_concurrent_configures)        # concurrent CONFIGURE (active ansible)
    _deploy_buffer = asyncio.Semaphore(cfg.max_deployed)                  # DEPLOYING+DEPLOYED cap — back-pressure: held from provision-start until configure-start, so provisioning halts when configure backs up (no infinite host pile-up)
    await _clean_slate()
    _capacity = CapacityTracker()
    await _capacity.initialize()
    yield
    await _shutdown_cleanup()  # Ctrl-C / SIGTERM → nuke the tester's infra + flush logs before exit


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
    sids = [s for s in (await _run("server", "list", "--all-projects", "-f", "value", "-c", "ID")).splitlines() if s]
    if sids:
        # Delete in chunks of _NUKE_BATCH, each `server delete ... --wait` blocking until that chunk is gone
        # before the next starts — so nova/neutron tear down at most _NUKE_BATCH VMs at once. A single
        # whole-cluster batch overwhelmed them (VIF-unplug + volume-detach storm). The CLI attempts every ID
        # in the chunk and reports failures at the end, so a straggler doesn't abort the rest of its chunk.
        logger.info("Deleting %d servers in batches of %d", len(sids), _NUKE_BATCH)
        for i in range(0, len(sids), _NUKE_BATCH):
            batch = sids[i:i + _NUKE_BATCH]
            logger.info("Deleting servers %d–%d of %d", i + 1, i + len(batch), len(sids))
            if not await _exec("server", "delete", *batch, "--wait"):
                logger.warning("Batch server delete reported a failure (some servers may remain)")

    logger.info("=== Releasing floating IPs ===")
    fids = [f for f in (await _run("floating", "ip", "list", "-f", "value", "-c", "ID")).splitlines() if f]
    if fids:
        logger.info("Deleting %d floating IPs in one batch", len(fids))
        if not await _exec("floating", "ip", "delete", *fids):
            logger.warning("Batch floating IP delete reported a failure")

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
    orphan_pids = []
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
        orphan_pids.append(pid)
    if orphan_pids:
        logger.info("Deleting %d orphaned ports in one batch", len(orphan_pids))
        if not await _exec("port", "delete", *orphan_pids):
            logger.warning("Batch port delete reported a failure")

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
    # Reap MHBench provision/configure/collect subprocesses (+ their ansible children) left over from a
    # prior harness that died without cleaning up: orphaned to init, they keep hammering torn-down bastions
    # for the full check_if_host_up timeout (~18 min) and write stale host-logs into reused same-name output
    # dirs, polluting the fresh run. A fresh start has no legit ones running, so a blunt pkill is safe here.
    for pattern in ("MHBench/cli.py", "ansible"):  # cli.py parents first, then their ansible children
        try:
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-9", "-f", pattern,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await proc.wait()
        except Exception:
            logger.exception("Failed to pkill '%s' on clean-slate", pattern)

    experiments = registry.load()

    for experiment in experiments:
        if experiment.attacker:
            try:
                await experiment.attacker.stop(experiment, cfg)
            except Exception:
                logger.exception("Failed to stop attacker process for '%s'", experiment.experiment_name)
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


async def _shutdown_cleanup() -> None:
    """On Ctrl-C / SIGTERM: leave nothing behind. _clean_slate reaps stray MHBench/ansible subprocesses,
    kills attacker procs + C2 containers, and tears down OpenStack (external survives); then flush all logs."""
    try:
        await _clean_slate()  # pkills MHBench/ansible subprocs, attacker procs, C2 containers, OpenStack teardown
    except Exception:
        logger.exception("Clean-slate on shutdown failed")
    logging.shutdown()  # flush + close every log handler so the run's logs are fully dumped to disk


async def _teardown(experiment: Experiment, delete_c2: bool = True) -> bool:  # True iff the env was cleanly destroyed
    if not experiment.teardown:  # leave env + C2 standing to run an exploit by hand
        get_logger(experiment.experiment_name).info(
            "teardown=False — preserving environment + C2 for '%s'", experiment.experiment_name
        )
        return False  # env NOT destroyed: stops _handle_failure from redeploying over the standing host
    experiment.teardown_started_at = datetime.now(timezone.utc)
    await registry.update(experiment)

    if experiment.attacker and experiment.c2c_container_id:
        try:
            c2c_log_path = output_root(experiment.experiment_name, cfg) / experiment.experiment_name / "attacker" / "c2c_server.log"
            c2c_log_path.parent.mkdir(parents=True, exist_ok=True)
            proc = await asyncio.create_subprocess_exec(
                "docker", "logs", experiment.c2c_container_id,
                stdout=open(c2c_log_path, "w"), stderr=asyncio.subprocess.STDOUT,
            )
            await proc.wait()
        except Exception:
            get_logger(experiment.experiment_name).exception("Failed to save C2 container logs for '%s'", experiment.experiment_name)
        if delete_c2:
            try:
                await experiment.attacker.stop_c2c(experiment.c2c_container_id)
            except Exception:
                get_logger(experiment.experiment_name).exception("Failed to stop C2 container for '%s'", experiment.experiment_name)
        else:
            get_logger(experiment.experiment_name).info(
                "Preserving C2 container %s for '%s' (delete_c2=False)",
                experiment.c2c_container_id,
                experiment.experiment_name,
            )

    # Pull ground-truth host logs while the range is still up. Best-effort: a collection failure
    # must never block teardown (leaking VMs is worse than losing logs), and it needs no op-slot
    # (SSH via the bastion, not an OpenStack API call), so it runs before we acquire one.
    try:
        await collect_environment(experiment, cfg)
    except Exception:
        get_logger(experiment.experiment_name).exception("Host-log collection failed for '%s'", experiment.experiment_name)

    if experiment.attacker:
        try:
            await experiment.attacker.collect_logs(
                experiment, cfg,
                output_root(experiment.experiment_name, cfg) / experiment.experiment_name / "attacker",
            )
        except Exception:
            get_logger(experiment.experiment_name).exception("Attacker-log collection failed for '%s'", experiment.experiment_name)

    # Teardown is UNCAPPED (no _openstack_lock): a failed/finished env must reclaim its VMs immediately
    # instead of queueing behind provisions — deletion is far lighter than creation (no image pull/expand),
    # and an env sitting on its VMs while it waits for a slot is exactly what starves the next batch's attacker.
    try:
        await teardown_environment(experiment, cfg)
        experiment.teardown_finished_at = datetime.now(timezone.utc)
        await registry.update(experiment)
        if experiment.vcpus_reserved is not None:
            _capacity.release(experiment.experiment_name)
        return True
    except Exception:
        get_logger(experiment.experiment_name).exception("Failed to tear down environment for '%s'", experiment.experiment_name)
        return False  # env not cleanly destroyed — caller must not redeploy over it


async def _teardown_stale_c2_before_launch(experiment: Experiment) -> None:
    """Stop stale C2 containers before launching a new C2 for this experiment."""
    if not experiment.attacker:
        return

    for previous in registry.load():
        if not previous.c2c_container_id:
            continue

        # Keep currently active experiments untouched. Clean up stale/finished ones,
        # and always clean up leftovers with the same experiment name.
        should_stop = (
            previous.experiment_name == experiment.experiment_name
            or previous.status not in _ACTIVE_STATUSES
        )
        if not should_stop:
            continue

        stopper = previous.attacker or experiment.attacker
        if not stopper:
            continue

        try:
            await stopper.stop_c2c(previous.c2c_container_id)
            get_logger(experiment.experiment_name).info(
                "Stopped stale C2 container %s from '%s'",
                previous.c2c_container_id,
                previous.experiment_name,
            )
            previous.c2c_container_id = None
            await registry.update(previous)
        except Exception:
            get_logger(experiment.experiment_name).exception(
                "Failed to stop stale C2 container %s from '%s'",
                previous.c2c_container_id,
                previous.experiment_name,
            )

def _write_result(experiment: Experiment) -> None:
    """Runtime record (status + all timestamps, grouped) → experiment/experiment_result.json."""
    p = output_root(experiment.experiment_name, cfg) / experiment.experiment_name / "experiment" / "experiment_result.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(experiment.result_json())


async def _handle_failure(experiment: Experiment, reason: Optional[str] = None) -> None:
    """One attempt failed. Tear it down, then retry IN PLACE (same name, so the polling caller keeps
    tracking it) as status RETRYING — until the retry budget is spent, at which point escalate a terminal
    ERROR. RETRYING tells phdpt the harness is handling it and the caller should just keep polling.
    `reason` is the human-readable cause, surfaced on the experiment record (and the dashboard)."""
    name = experiment.experiment_name
    if reason:
        experiment.error = reason
    tore_down = await _teardown(experiment)  # frees VMs + capacity; keeps the registry row
    _write_result(experiment)  # capture this attempt's timeline before it's archived

    # archive this attempt's output so the retry starts clean and each try stays inspectable
    src = output_root(name, cfg) / name
    if src.exists():
        dst = output_root(name, cfg) / "failed" / f"{name}_{experiment.retry_count}"
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            shutil.rmtree(str(dst))
        await asyncio.get_event_loop().run_in_executor(None, shutil.move, str(src), str(dst))

    # retry only over a CLEANLY torn-down env — never redeploy on top of a half-destroyed one
    if tore_down and cfg.max_retries > 0 and experiment.retry_count < cfg.max_retries:
        experiment.retry_count += 1
        experiment.status = ExperimentStatus.RETRYING
        experiment.error = None  # fresh attempt — clear the prior failure reason
        experiment.deployed_environment = experiment.c2c_container_id = experiment.pid = None
        experiment.vcpus_reserved = experiment.ram_mb_reserved = None
        for f in ("environment_deploy_started_at", "environment_deploy_finished_at",
                  "defender_started_at", "defender_finished_at", "attacker_started_at",
                  "attacker_finished_at", "teardown_started_at", "teardown_finished_at"):
            setattr(experiment, f, None)
        await registry.update(experiment)
        get_logger(name).info("[%s] Attempt failed — retry %d/%d (harness-handled)",
                              name, experiment.retry_count, cfg.max_retries)
        _tasks[name] = asyncio.create_task(_run_experiment(experiment))
    else:
        experiment.status = ExperimentStatus.ERROR  # escalate to the caller (phdpt)
        await registry.update(experiment)
        reason = "teardown failed, not retrying" if not tore_down else f"failed after {experiment.retry_count} retries"
        get_logger(name).warning("[%s] Escalating ERROR — %s", name, reason)


async def _cancel_and_remove(name: str) -> None:
    """Cancel one experiment and free its name — the no-restart path behind DELETE and overwrite-rerun.
    Cancels its task, kills its in-flight MHBench subprocess (scoped by --project-name, so peers are
    untouched), stops its attacker + C2, tears down its VMs BY NAME (robust even mid-provision, since it's
    name-based not from the in-memory object), releases capacity, then drops it from the registry."""
    task = _tasks.pop(name, None)
    if task and not task.done():
        task.cancel()
        try:
            await task  # let its finally blocks release the deploy/configure locks
        except BaseException:
            pass
    try:
        experiment = registry.get(name)
    except KeyError:
        return  # already gone
    try:  # kill only THIS experiment's provision/configure/collect subprocess (every stage tags --project-name)
        proc = await asyncio.create_subprocess_exec(
            "pkill", "-9", "-f", f"cli.py.*--project-name {name}( |$)",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await proc.wait()
    except Exception:
        logger.exception("Failed to kill MHBench subprocess for '%s'", name)
    if experiment.attacker:
        try:
            await experiment.attacker.stop(experiment, cfg)
        except Exception:
            logger.exception("Failed to stop attacker process for '%s'", name)
    if experiment.attacker and experiment.c2c_container_id:
        try:
            await experiment.attacker.stop_c2c(experiment.c2c_container_id)
        except Exception:
            logger.exception("Failed to stop C2 container for '%s'", name)
    try:
        await teardown_environment(experiment, cfg)  # deletes all VMs/networks by project name
    except Exception:
        logger.exception("Failed to tear down environment for '%s'", name)
    if experiment.vcpus_reserved is not None:
        _capacity.release(name)
    await registry.remove(name)


async def _docker_preflight() -> Optional[str]:
    """Return a human-readable reason if the local Docker daemon is not usable by this
    process, else None. Attackers that run a C2 container need it; checking here lets the
    harness fail an experiment immediately instead of after a full provision+configure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "info",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, stderr = await proc.communicate()
    except FileNotFoundError:
        return ("Docker CLI not found on PATH, but this attacker needs Docker to build/run "
                "its C2 container. Install Docker on the harness host.")
    if proc.returncode == 0:
        return None
    err = stderr.decode(errors="replace")
    if "permission denied" in err.lower() and "docker.sock" in err.lower():
        return ("This attacker needs Docker (for its C2 container), but the harness user cannot "
                "access the Docker daemon: permission denied on /var/run/docker.sock. Add the "
                "user to the 'docker' group and restart the manager: "
                "`sudo usermod -aG docker $USER` then log out/in (or restart the backend). "
                "To fix the already-running process without a restart: "
                "`sudo setfacl -m u:$USER:rw /var/run/docker.sock`.")
    last = next((l for l in reversed(err.splitlines()) if l.strip()), "").strip()
    return f"This attacker needs Docker, but the Docker daemon is not usable: {last or 'docker info failed'}"


async def _run_experiment(experiment: Experiment) -> None:
    name = experiment.experiment_name
    exp_log = init_logger(name, output_root(name, cfg))

    config_path = output_root(name, cfg) / name / "experiment" / "experiment_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(experiment.config_json())

    # Fail fast (before any provisioning) if this attacker needs Docker and it isn't usable,
    # so a missing docker-group membership doesn't waste a full deploy+configure.
    if experiment.attacker is not None and getattr(experiment.attacker, "requires_docker", False):
        docker_err = await _docker_preflight()
        if docker_err:
            exp_log.error("[%s] Docker preflight failed: %s", name, docker_err)
            experiment.error = docker_err
            experiment.status = ExperimentStatus.ERROR
            await registry.update(experiment)
            _write_result(experiment)
            return

    kali_c2c_url = None
    local_c2c_url = None
    prepared = None

    experiment.deployed_environment = DeployedEnvironment(
        topology_spec=str(cfg.mhbench_dir / "environments" / f"{experiment.environment_spec}.json"),
    )
    await registry.update(experiment)

    mgmt_ip = None
    deploy_slot_held = False
    try:
        topology_path = cfg.mhbench_dir / "environments" / f"{experiment.environment_spec}.json"
        vm_specs = await count_vm_specs(topology_path, cfg.mhbench_dir)
        vcpus_reserved, ram_reserved = await _capacity.reserve(vm_specs, name)
        experiment.vcpus_reserved = vcpus_reserved
        experiment.ram_mb_reserved = ram_reserved
        config_path.write_text(experiment.config_json())
        await registry.update(experiment)

        # Enter the deploy stage (DEPLOYING+DEPLOYED ≤ max_deployed). This slot is held until CONFIGURE
        # actually starts (below) — so when the configure gate is saturated, provisioned envs pile up here
        # and new provisions block, instead of spinning up hosts that then sit idle waiting to configure.
        await _deploy_buffer.acquire()
        deploy_slot_held = True

        async with _openstack_lock.acquire(_PRIORITY_DEPLOY):

            experiment.status = ExperimentStatus.DEPLOYING
            experiment.environment_deploy_started_at = datetime.now(timezone.utc)
            await registry.update(experiment)

            # Launch the C2 only now that we hold a deploy slot, so queued experiments don't each idle a
            # heavy Caldera container. On failure, re-raise so the OUTER handler runs _handle_failure AFTER
            # this lock releases — its teardown re-acquires the same semaphore, so doing it here deadlocks.
            try:
                deployed, mgmt_ip = await provision_environment(experiment, None, cfg)
                experiment.deployed_environment = deployed
                await registry.update(experiment)
            except NotImplementedError:
                experiment.deployed_environment = None
                exp_log.warning("Deployer stub hit — proceeding without environment for '%s'", experiment.experiment_name)

        # Provisioning done → DEPLOYED: VMs are up but we still hold the deploy slot while waiting for a
        # configure slot. The slot only frees once CONFIGURING actually starts (below), so a saturated
        # configure gate back-pressures onto provisioning (DEPLOYED experiments pile up, new provisions block).
        experiment.status = ExperimentStatus.DEPLOYED
        await registry.update(experiment)
        async with _configure_lock.acquire(_PRIORITY_DEPLOY):
            _deploy_buffer.release()   # DEPLOYED → CONFIGURING hand-off: free the deploy slot so a queued env can provision now
            deploy_slot_held = False
            experiment.status = ExperimentStatus.CONFIGURING
            await registry.update(experiment)
            await configure_environment(experiment, mgmt_ip, None, cfg)
            experiment.environment_deploy_finished_at = datetime.now(timezone.utc)
            experiment.status = ExperimentStatus.CONFIGURED   # configured; waiting for the attack to start
            await registry.update(experiment)

    except Exception as e:
        exp_log.exception("Failed to provision/configure environment for '%s'", experiment.experiment_name)
        await _handle_failure(experiment, f"Deploy/configure failed — {e}")
        return
    finally:
        if deploy_slot_held:
            _deploy_buffer.release()   # release the deploy slot on any exit before configure started (e.g. provision failure)

    # Attacker setup on the ready (attacker-neutral) env: bring up any C2, run the attacker's setup play on
    # kali, wait for its channel — before the pre-attack log rotation so setup noise is rotated away.
    try:
        await _teardown_stale_c2_before_launch(experiment)
    except Exception:
        exp_log.exception("Pre-launch stale C2 teardown failed for '%s'", experiment.experiment_name)
    try:
        prepared = await experiment.attacker.setup(experiment, cfg, mgmt_ip)
        kali_c2c_url, local_c2c_url = prepared.remote_url, prepared.local_url
        if prepared.container_id:
            experiment.c2c_container_id = prepared.container_id
            await registry.update(experiment)
    except Exception as e:
        exp_log.exception("Attacker setup failed for '%s'", experiment.experiment_name)
        await _handle_failure(experiment, f"Attacker setup failed — {e}")
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

    # Reset host logs at the deploy->attack boundary so collected logs are attack-phase-only. Blocking
    # by construction (awaited before run_attacker). Best-effort: a rotation failure must not waste a
    # full deploy — that host just falls back to needing a timestamp trim at analysis time.
    try:
        await rotate_environment(experiment, cfg)
    except Exception:
        exp_log.exception("Pre-attack log rotation failed for '%s' — proceeding (logs may include pre-attack noise)", experiment.experiment_name)

    try:
        process = await run_attacker(experiment.attacker, experiment.deployed_environment, experiment.experiment_name, cfg, prepared, c2c_server=kali_c2c_url)
    except Exception as e:
        exp_log.exception("Failed to start attacker for '%s'", experiment.experiment_name)
        if defender_process:
            try:
                defender_process.terminate()
                await defender_process.wait()
            except Exception:
                pass
        await _handle_failure(experiment, f"Failed to start attacker — {e}")
        return

    experiment.pid = process.pid
    experiment.status = ExperimentStatus.RUNNING
    experiment.attacker_started_at = datetime.now(timezone.utc)
    await registry.update(experiment)

    returncode = None
    try:
        returncode = await asyncio.wait_for(process.wait(), cfg.attacker_timeout_seconds)
        status = ExperimentStatus.FINISHED if returncode == 0 else ExperimentStatus.ERROR
    except asyncio.TimeoutError:
        exp_log.info("[%s] Attacker exceeded timeout (%ss) — stopping", name, cfg.attacker_timeout_seconds)
        await experiment.attacker.stop(experiment, cfg)
        try:
            await asyncio.wait_for(process.wait(), 15)
        except asyncio.TimeoutError:
            pass
        status = ExperimentStatus.TIMEDOUT
    except Exception as e:
        exp_log.exception("Error waiting on attacker process for '%s'", experiment.experiment_name)
        status = ExperimentStatus.ERROR
        experiment.error = f"Error waiting on attacker process — {e}"
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
    # A provider guardrail refusal (e.g. OpenAI/Azure "flagged for possible cybersecurity risk") lets the
    # attacker end normally — usually exit 0 → FINISHED — which hides *why* nothing happened and looks like a
    # clean run. Detect it from the attacker's own logs and mark a distinct terminal state. It is not a harness
    # failure (the model refused, not us), so — like TimedOut — it does not retry and is not the red Error state.
    if status in (ExperimentStatus.FINISHED, ExperimentStatus.ERROR) and _attacker_guardrail_block(name, cfg):
        exp_log.info("[%s] Attacker LLM was refused by a provider guardrail — marking Blocked", name)
        status = ExperimentStatus.BLOCKED
        experiment.error = "Attacker LLM refused by a provider guardrail (content/safety policy) — see attacker llm.log"
    if status == ExperimentStatus.ERROR:  # a nonzero attacker exit is a failure — retry or escalate
        reason = experiment.error or f"Attacker exited with code {returncode} (see attacker.log)"
        await _handle_failure(experiment, reason)
        return

    experiment.status = status
    await registry.update(experiment)
    await _teardown(experiment)
    _write_result(experiment)  # after teardown, so experiment_result.json carries the full timestamp set


# High-precision phrases emitted by provider content/safety guardrails when they refuse a request.
# Kept deliberately specific to avoid flagging benign log text that merely mentions "policy" or "filter".
_GUARDRAIL_SIGNATURES = (
    "flagged for possible cybersecurity risk",   # OpenAI / Azure cyber-misuse gate
    "trusted access for cyber",                  # OpenAI cyber-program referral in the refusal
    "content_policy_violation",                  # OpenAI content policy
    "content management policy",                 # Azure OpenAI content filter
    "responsibleaipolicyviolation",              # Azure Responsible AI
)


def _attacker_guardrail_block(name: str, cfg) -> bool:
    """True if the attacker's LLM was refused by a provider content/safety guardrail. Such a refusal
    surfaces as an API error inside the attacker's own logs while the attacker process itself may still
    exit 0, so it must be detected from the logs rather than the exit code."""
    attacker_dir = output_root(name, cfg) / name / "attacker"
    for fname in ("llm.log", "attacker.log"):
        try:
            text = (attacker_dir / fname).read_text(errors="ignore").lower()
        except OSError:
            continue
        if any(sig in text for sig in _GUARDRAIL_SIGNATURES):
            return True
    return False


app = FastAPI(title="Experiment Manager", lifespan=lifespan)


@app.post("/experiments", status_code=201)
async def add_experiment(data: ExperimentSpecs):
    now = datetime.now(timezone.utc)
    name = data.experiment_name
    register_output_root(name, data.output_dir)  # route this run's output tree, if requested
    # Never silently clobber a prior run. A same-named experiment can linger in the registry (in-flight or
    # terminal) and/or on disk; require an explicit overwrite=true to replace either — otherwise reject.
    registered = any(e.experiment_name == name for e in registry.load())
    exp_out = output_root(name, cfg) / name
    if (registered or exp_out.exists()) and not data.overwrite:
        raise HTTPException(status_code=409, detail=f"'{name}' already exists; pass overwrite=true to cancel+replace it, or use a different name")
    if registered:
        await _cancel_and_remove(name)  # overwrite=true → cancel the prior run + free the name in place (no harness restart)
    if exp_out.exists():
        shutil.rmtree(exp_out, ignore_errors=True)  # replace the prior output tree
    experiment = Experiment(
        experiment_name=data.experiment_name,
        status=ExperimentStatus.QUEUED,
        environment_spec=data.environment,
        attacker=data.attacker,
        defender=data.defender,
        trial=data.trial,
        teardown=data.teardown,
        created_at=now,
        updated_at=now,
    )

    try:
        await registry.add(experiment)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    _tasks[experiment.experiment_name] = asyncio.create_task(_run_experiment(experiment))
    return {"experiment_name": experiment.experiment_name, "status": experiment.status}


@app.get("/experiments")
async def list_experiments():
    return [e.flat() for e in registry.load()]


@app.get("/experiments/{experiment_name}")
async def get_experiment(experiment_name: str):
    try:
        return registry.get(experiment_name).flat()
    except KeyError:
        raise HTTPException(status_code=404, detail="Experiment not found")


@app.delete("/experiments/{experiment_name}")
async def delete_experiment(experiment_name: str):
    """Cancel one experiment in place: stop its task + subprocess + attacker + C2, tear down its VMs, free
    its name — without a harness restart. Peers keep running. Idempotent-ish: 404 if the name isn't live."""
    if not any(e.experiment_name == experiment_name for e in registry.load()):
        raise HTTPException(status_code=404, detail="Experiment not found")
    await _cancel_and_remove(experiment_name)
    return {"experiment_name": experiment_name, "status": "cancelled"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("experiment_manager.main:app", reload=True)
