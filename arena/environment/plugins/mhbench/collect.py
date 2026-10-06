from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess

from ....config import ExperimentManagerConfig
from ....experiment import Experiment
from .deployer import resolve_topology_path
from ....experiment_log import init_logger, log, output_root

_COLLECT_TIMEOUT_S = 600


def _collect_sync(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    name = experiment.experiment_name
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(experiment.environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    env_dir = output_root(name, cfg) / name / "environment"
    exp_dir = output_root(name, cfg) / name / "experiment"

    provision_result = exp_dir / "provision_result.json"
    bastion_ip = None
    if provision_result.exists():
        bastion_ip = json.loads(provision_result.read_text()).get("mgmt_ip")
    if not bastion_ip:
        log(name, "No bastion_ip in provision_result.json; skipping host-log collection.")
        return

    init_logger(name, output_root(name, cfg))
    mhbench_log = exp_dir / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    env_dir.mkdir(parents=True, exist_ok=True)
    log(name, f"Collecting host logs via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        proc = subprocess.Popen(
            [str(python), str(cli), "collect", str(topology_path),
             "--project-name", name, "--mgmt-ip", bastion_ip, "--dest", str(env_dir)],
            cwd=str(mhbench_dir),
            stdout=lf, stderr=lf,
            start_new_session=True,
        )
        try:
            rc = proc.wait(timeout=_COLLECT_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            log(name, f"Warning: MHBench collect exceeded {_COLLECT_TIMEOUT_S}s "
                      f"(bastion likely saturated) — killing it and proceeding to teardown; "
                      f"host logs may be incomplete.")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            rc = -1
    if rc != 0:
        log(name, f"Warning: MHBench collect exited with code {rc}, see {mhbench_log}")
    else:
        log(name, "Host-log collection complete.")


async def collect_environment(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _collect_sync, experiment, cfg)
