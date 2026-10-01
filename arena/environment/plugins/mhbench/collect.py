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

# Hard cap on host-log collection. Collection is best-effort (non-fatal), but it runs
# ansible over the experiment's bastion, which under the foothold C2 + high concurrency on a
# large topology (27-52 hosts) can saturate the bastion's sshd so the collect ansible
# hangs indefinitely — wedging the run in "Running" forever, pinning its VMs, and stalling
# the whole matrix (observed: 4 runs stuck ~1.5h holding 108 VMs). A bounded timeout kills
# a hung collect and lets the run proceed to teardown (freeing its VMs); a healthy collect
# of even the largest topology finishes well inside this.
_COLLECT_TIMEOUT_S = 600


def _collect_sync(experiment: Experiment, cfg: ExperimentManagerConfig) -> None:
    name = experiment.experiment_name
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(experiment.environment_spec, cfg)
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
    env_dir.mkdir(parents=True, exist_ok=True)  # --dest for collected logs (provisioning does not create environment/)
    log(name, f"Collecting host logs via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        # start_new_session so a timeout can SIGKILL the whole process GROUP (cli.py +
        # all its ansible children), not just the direct child — otherwise the ansible
        # grandchildren orphan and keep hanging on the bastion.
        proc = subprocess.Popen(
            [str(python), str(cli), "collect", str(topology_path),
             "--project-name", name, "--mgmt-ip", mgmt_ip, "--dest", str(env_dir)],
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
