import asyncio
import json
import logging
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

from .attacker import run_attacker
from .c2c import start_c2c_server, stop_c2c_server
from .config import ExperimentManagerConfig
from .deployer import deploy_environment
from .experiment import Experiment, ExperimentSpecs, ExperimentStatus
from .experiment_registry import Registry
from .teardown import teardown_environment

logger = logging.getLogger(__name__)

cfg: ExperimentManagerConfig
registry: Registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    global cfg, registry
    cfg = ExperimentManagerConfig.load()
    registry = Registry(cfg.registry_path)
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

        if experiment.c2c_container_id:
            try:
                await stop_c2c_server(experiment.c2c_container_id)
            except Exception:
                logger.exception("Failed to stop C2 container for '%s'", experiment.experiment_name)

        try:
            await teardown_environment(experiment)
        except NotImplementedError:
            pass
        except Exception:
            logger.exception("Teardown failed for '%s' during clean slate", experiment.experiment_name)

    await registry.clear()


async def _teardown(experiment: Experiment) -> None:
    if experiment.c2c_container_id:
        try:
            await stop_c2c_server(experiment.c2c_container_id)
        except Exception:
            logger.exception("Failed to stop C2 container for '%s'", experiment.experiment_name)

    try:
        await teardown_environment(experiment)
    except NotImplementedError:
        logger.warning("Teardown stub hit — environment for '%s' not torn down", experiment.experiment_name)
    except Exception:
        logger.exception("Teardown failed for experiment '%s'", experiment.experiment_name)


async def _run_experiment(experiment: Experiment) -> None:
    try:
        container_id, c2c_server = await start_c2c_server(experiment.experiment_name, experiment.attacker.c2c_image, cfg)
        experiment.c2c_container_id = container_id
        await registry.update(experiment)
    except Exception:
        logger.exception("Failed to start C2 server for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        await _teardown(experiment)
        return

    try:
        process = await run_attacker(experiment.attacker, experiment.deployed_environment, experiment.experiment_name, cfg, c2c_server=c2c_server)
    except Exception:
        logger.exception("Failed to start attacker for '%s'", experiment.experiment_name)
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        await _teardown(experiment)
        return

    experiment.pid = process.pid
    experiment.status = ExperimentStatus.RUNNING
    await registry.update(experiment)

    try:
        returncode = await process.wait()
        status = ExperimentStatus.FINISHED if returncode == 0 else ExperimentStatus.ERROR
    except Exception:
        logger.exception("Error waiting on attacker process for '%s'", experiment.experiment_name)
        status = ExperimentStatus.ERROR

    result_file = cfg.output_dir / experiment.experiment_name / "result.json"
    result_file.parent.mkdir(parents=True, exist_ok=True)
    result_file.write_text(json.dumps({"status": status}))

    experiment.status = status
    await registry.update(experiment)
    await _teardown(experiment)


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

    try:
        deployed = await deploy_environment(experiment)
        experiment.deployed_environment = deployed
        experiment.status = ExperimentStatus.READY
        await registry.update(experiment)
    except NotImplementedError:
        logger.warning("Deployer stub hit — proceeding without environment for '%s'", experiment.experiment_name)
    except Exception as e:
        experiment.status = ExperimentStatus.ERROR
        await registry.update(experiment)
        raise HTTPException(status_code=500, detail=f"Deployment failed: {e}")

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
