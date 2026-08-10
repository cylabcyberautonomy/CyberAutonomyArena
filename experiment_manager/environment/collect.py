from __future__ import annotations

import asyncio
import json
import subprocess

from ..config import ExperimentManagerConfig
from ..experiment import Experiment
from ..experiment_log import init_logger, log, output_root


def _collect_sync(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    name = experiment.experiment_name
    mhbench_dir = cfg.mhbench_dir
    topology_path = mhbench_dir / "environments" / f"{experiment.environment_spec}.json"
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    env_dir = output_root(name, cfg) / name / "environment"   # collected host logs land here (--dest)
    exp_dir = output_root(name, cfg) / name / "experiment"     # provision_result.json + mhbench.log live here

    # mgmt_ip is not carried on the experiment — re-read it from where provisioning wrote it.
    provision_result = exp_dir / "provision_result.json"
    mgmt_ip = None
    if provision_result.exists():
        mgmt_ip = json.loads(provision_result.read_text()).get("mgmt_ip")
    if not mgmt_ip:
        log(name, "No mgmt_ip in provision_result.json; skipping host-log collection.")
        return

    init_logger(name, output_root(name, cfg))
    mhbench_log = exp_dir / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    env_dir.mkdir(parents=True, exist_ok=True)  # --dest for collected logs; provisioning no longer creates environment/
    log(name, f"Collecting host logs via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(
            [str(python), str(cli), "collect", str(topology_path),
             "--project-name", name, "--mgmt-ip", mgmt_ip, "--dest", str(env_dir)],
            cwd=str(mhbench_dir),
            stdout=lf, stderr=lf,
        )
    if result.returncode != 0:
        log(name, f"Warning: MHBench collect exited with code {result.returncode}, see {mhbench_log}")
    else:
        log(name, "Host-log collection complete.")


async def collect_environment(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _collect_sync, experiment, cfg)
