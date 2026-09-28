"""Canary (diagnostic) defender — proves the defender-side plumbing works, then idles.

It deploys no decoys, calls no LLM, needs no Elasticsearch client library, no Perry repo and
no OpenStack SDK. Its runner is stdlib-only (SSH via subprocess, ES via urllib). So when it
fails you know the failure is *connectivity*, not detection logic; when it passes you know a
real defender could connect on this environment.

Checks (any subset via `checks`):
  ssh           - SSH from the harness through the bastion to every victim (root@, ProxyCommand
                  with UserKnownHostsFile=/dev/null on both hops), run `hostname`
  resolve       - compare each victim's real OS hostname to its topology model-name (the
                  FalcoLLM hostname-resolution trap: model 'webserver0' vs OS 'host2')
  telemetry     - GET <management_ip>:<port>/_cat/indices and confirm this run's
                  falco-<exp>/sysflow-<exp> indices exist (the same ES a real defender reads)
  canary_event  - read /etc/shadow on a victim, then confirm a new event lands in the falco
                  index within telemetry_timeout_s (proves victim -> sensor -> store -> reader)

`fail_closed: false` (default) always arms and just reports; `true` refuses to arm if a
required check fails, turning the canary into a hard gate.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import PrivateAttr

from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin

_ALL_CHECKS = ["ssh", "resolve", "telemetry", "canary_event"]


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> Path:
    """The private key MHBench injected into the hosts (same resolution the other
    self-contained plugins use)."""
    default = Path("~/.ssh/id_ed25519").expanduser()
    try:
        rel = getattr(cfg, "mhbench_config", None) or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return Path(os.path.expanduser(key)) if key else default
    except Exception:  # noqa: BLE001 — config shape drift must not break the canary; use the default
        return default


class CanaryDefenderPlugin(DefenderPlugin, config_type="canary"):
    """Diagnostic defender: verifies defender<->environment connectivity end to end."""

    type: Literal["canary"]
    checks: list[str] = list(_ALL_CHECKS)
    canary_host: Optional[str] = None       # victim name/role for the canary_event read; None = first victim
    telemetry_port: int = 9200
    telemetry_timeout_s: float = 60.0
    fail_closed: bool = False               # True = refuse to arm if a required check fails

    _ssh_key: Optional[str] = PrivateAttr(default=None)

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "canary",
            "label": "Canary (connectivity diagnostic)",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Checks",
                    "key": "checks",
                    "options": list(_ALL_CHECKS),
                    "default": list(_ALL_CHECKS),
                },
                {
                    "field_type": "bool",
                    "label": "Fail closed (refuse to arm on a failed check)",
                    "key": "fail_closed",
                    "default": False,
                },
            ],
        }

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        # Only needs the key path resolved; the runner does the real work at arm time.
        self._ssh_key = str(_mhbench_ssh_key(cfg))

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        # management_ip (harness ES), bastion_ip (this run's mgmt floating IP) and log_dir are
        # injected by defender.run_defender() right before the runner starts.
        return {
            "experiment_name": experiment_name,
            "topology_spec": environment.topology_spec if environment else None,
            "checks": self.checks,
            "canary_host": self.canary_host,
            "telemetry_port": self.telemetry_port,
            "telemetry_timeout_s": self.telemetry_timeout_s,
            "fail_closed": self.fail_closed,
            "ssh_key": self._ssh_key or str(Path("~/.ssh/id_ed25519").expanduser()),
        }

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        # stdlib-only runner: use the manager's own interpreter, no special PYTHONPATH/cwd.
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
