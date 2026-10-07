from __future__ import annotations

import asyncio
import subprocess

from ....config import ExperimentManagerConfig
from .deployer import _mhb_config_args
from ....experiment import Experiment
from .deployer import resolve_topology_path
from ....experiment_log import init_logger, log, output_root


def _teardown_sync(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    name = experiment.experiment_name
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(experiment.environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"

    init_logger(name, output_root(name, cfg))
    mhbench_log = output_root(name, cfg) / name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(name, f"Tearing down environment via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(
            [str(python), str(cli), *_mhb_config_args(cfg), "teardown", "--yes", str(topology_path), "--project-name", name],
            cwd=str(mhbench_dir),
            stdout=lf, stderr=lf,
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"MHBench teardown exited with code {result.returncode}, see {mhbench_log}"
        )

    log(name, "Teardown complete.")


async def teardown_environment(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _teardown_sync, experiment, cfg)
