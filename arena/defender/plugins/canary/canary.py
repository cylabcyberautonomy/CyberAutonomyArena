"""Canary (diagnostic) defender — proves the defender-side plumbing works, then idles.

It deploys no decoys, calls no LLM, needs no Elasticsearch client library, no Perry repo and
no OpenStack SDK. Its runner is stdlib-only (SSH via subprocess, ES via urllib). So when it
fails you know the failure is *connectivity*, not detection logic; when it passes you know a
real defender could connect on this environment.

Checks (any subset via `checks`):
  ssh           - SSH through the bastion to every victim (using the SetupAccess the environment
                  produced: per-host key + routing), run `hostname`
  resolve       - compare each victim's real OS hostname to its DefenderEnvSpec model-name (the
                  FalcoLLM hostname-resolution trap: model 'webserver0' vs OS 'host2')
  telemetry     - GET <management_ip>:<port>/_cat/indices and confirm this run's
                  falco-<exp>/sysflow-<exp> indices exist (the same ES a real defender reads)
  canary_event  - read /etc/shadow on a victim, then confirm a new event lands in the falco
                  index within telemetry_timeout_s (proves victim -> sensor -> store -> reader)

`fail_closed: false` (default) always arms and just reports; `true` refuses to arm if a
required check fails, turning the canary into a hard gate.

The canary reads its hosts and per-host SSH access from the arena-produced DefenderEnvSpec +
SetupAccess (injected into its config by run_defender); it does not resolve an MHBench SSH key or
parse the topology itself.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin

_ALL_CHECKS = ["ssh", "resolve", "telemetry", "canary_event"]


class CanaryDefenderPlugin(DefenderPlugin, config_type="canary"):
    """Diagnostic defender: verifies defender<->environment connectivity end to end."""

    type: Literal["canary"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "checks", "fail_closed"})
    checks: list[str] = list(_ALL_CHECKS)
    canary_host: Optional[str] = None       # victim name/role for the canary_event read; None = first victim
    telemetry_port: int = 9200
    telemetry_timeout_s: float = 60.0
    fail_closed: bool = False               # True = refuse to arm if a required check fails

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

    def box_ingress(self) -> dict[str, list[int]]:
        # Only the telemetry/canary_event checks touch the box ES; ssh/resolve-only opens nothing.
        if any(c in self.checks for c in ("telemetry", "canary_event")):
            return {"telemetry": [9200]}
        return {}

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        env_spec=None,
        prepared=None,  # Phase-A baton; canary has no box telemetry, so it is unused
    ) -> dict:
        # management_ip (harness ES), bastion_ip, log_dir, defender_setup_access (per-host key + routing)
        # are injected by defender.run_defender(); defender_env_spec (host inventory) is emitted here from
        # the typed env_spec arg.
        built = {
            "experiment_name": experiment_name,
            "checks": self.checks,
            "canary_host": self.canary_host,
            "telemetry_port": self.telemetry_port,
            "telemetry_timeout_s": self.telemetry_timeout_s,
            "fail_closed": self.fail_closed,
        }
        built.update(self._env_spec_key(env_spec))   # agent-facing host inventory (typed arg)
        return built

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
