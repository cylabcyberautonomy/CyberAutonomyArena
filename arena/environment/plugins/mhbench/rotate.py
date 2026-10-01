from __future__ import annotations

import asyncio
import json
import subprocess

from ....config import ExperimentManagerConfig
from ....experiment import Experiment
from .deployer import resolve_topology_path
from ....experiment_log import init_logger, log, output_root


def _rotate_sync(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    name = experiment.experiment_name
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(experiment.environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    exp_dir = output_root(name, cfg) / name / "experiment"

    # mgmt_ip is not carried on the experiment — re-read it from where provisioning wrote it.
    provision_result = exp_dir / "provision_result.json"
    mgmt_ip = None
    if provision_result.exists():
        mgmt_ip = json.loads(provision_result.read_text()).get("mgmt_ip")
    if not mgmt_ip:
        log(name, "No mgmt_ip in provision_result.json; skipping pre-attack log rotation.")
        return

    init_logger(name, output_root(name, cfg))
    mhbench_log = exp_dir / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(name, f"Rotating host logs at the deploy->attack boundary (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(
            [str(python), str(cli), "rotate-logs", str(topology_path),
             "--project-name", name, "--mgmt-ip", mgmt_ip],
            cwd=str(mhbench_dir),
            stdout=lf, stderr=lf,
        )
    if result.returncode != 0:
        log(name, f"Warning: MHBench rotate-logs exited with code {result.returncode}, see {mhbench_log}")
    else:
        log(name, "Pre-attack log rotation complete.")


async def rotate_environment(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _rotate_sync, experiment, cfg)
