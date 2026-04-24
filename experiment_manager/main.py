import asyncio
import json
import logging
import os
import shutil
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

from .attacker import run_attacker
from .environment import DeployedEnvironment
from .environment.deployer import provision_environment, configure_environment
from .environment.teardown import teardown_environment
from .config import ExperimentManagerConfig
from .experiment import Experiment, ExperimentSpecs, ExperimentStatus, Registry
from .experiment_log import get_logger, init_logger, log

logger = logging.getLogger(__name__)

cfg: ExperimentManagerConfig
registry: Registry
_openstack_semaphore: asyncio.Semaphore
_experiment_semaphore: asyncio.Semaphore


@asynccontextmanager
async def lifespan(app: FastAPI):
    global cfg, registry, _openstack_semaphore, _experiment_semaphore
    cfg = ExperimentManagerConfig.load()
    registry = Registry(cfg.registry_path)
    _openstack_semaphore = asyncio.Semaphore(1)
    _experiment_semaphore = asyncio.Semaphore(cfg.max_concurrent_experiments)
    await _clean_slate()
    yield


async def _clean_slate() -> None:
    """On startup, kill all running processes, stop C2 containers, tear down environments."""
    for experiment in registry.load():
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

        try:
            await teardown_environment(experiment, cfg)
            await registry.remove(experiment.experiment_name)
        except Exception:
            logger.exception("Teardown failed for '%s' — leaving in registry", experiment.experiment_name)


async def _teardown(experiment: Experiment) -> None:
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
        async with _openstack_semaphore:
            try:
                await teardown_environment(experiment, cfg)
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
    async with _experiment_semaphore:
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
            async with _openstack_semaphore:

                experiment.status = ExperimentStatus.DEPLOYING
                await registry.update(experiment)

                try:
                    deployed, mgmt_ip = await provision_environment(experiment, kali_c2c_url, cfg)
                    experiment.deployed_environment = deployed
                    await registry.update(experiment)
                except NotImplementedError:
                    experiment.deployed_environment = None
                    exp_log.warning("Deployer stub hit — proceeding without environment for '%s'", experiment.experiment_name)

                await configure_environment(experiment, mgmt_ip, kali_c2c_url, cfg)

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

        try:
            process = await run_attacker(experiment.attacker, experiment.deployed_environment, experiment.experiment_name, cfg, c2c_server=kali_c2c_url)
        except Exception:
            exp_log.exception("Failed to start attacker for '%s'", experiment.experiment_name)
            experiment.status = ExperimentStatus.ERROR
            await registry.update(experiment)
            tore_down = await _teardown(experiment)  # disabled for debugging
            if tore_down:
                await _schedule_retry(experiment)
            return

        experiment.pid = process.pid
        experiment.status = ExperimentStatus.RUNNING
        await registry.update(experiment)

        returncode = None
        try:
            returncode = await process.wait()
            status = ExperimentStatus.FINISHED if returncode == 0 else ExperimentStatus.ERROR
        except Exception:
            exp_log.exception("Error waiting on attacker process for '%s'", experiment.experiment_name)
            status = ExperimentStatus.ERROR

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
