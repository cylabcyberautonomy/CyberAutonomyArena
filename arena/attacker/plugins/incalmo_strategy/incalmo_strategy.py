from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Optional

from pydantic import field_validator

from .c2 import (start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready,
                 sweep_stale_tunnels)
from . import foothold
from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ...env_spec import AttackerEnvSpec
from ....ui_schema import PluginUISchema
from ..base import AttackerPlugin, PreparedAttacker


def _require_access(access):
    """Return the AttackerSetupAccess list, or raise if the arena passed none."""
    if not access:
        raise RuntimeError("no AttackerSetupAccess passed to the attacker — the arena must pass it to run_setup()")
    return access


# Loads config from a path passed as argv[1], bypassing ConfigService's hardcoded path.
_RUNNER = """\
import asyncio, json, sys
from pathlib import Path
from config.attacker_config import AttackerConfig
from incalmo.c2server.state_store import StateStore
from incalmo.incalmo_runner import run_incalmo_strategy

config = AttackerConfig(**json.loads(Path(sys.argv[1]).read_text()))
StateStore.initialize()
asyncio.run(run_incalmo_strategy(config, task_id=sys.argv[2]))
"""


def _preflight_incalmo_host(incalmo_dir: Path, incalmo_python: Path) -> None:
    """Fail fast if the Incalmo host-side interpreter or config is missing."""
    py = incalmo_python
    if not py.exists():
        raise RuntimeError(
            f"Incalmo attacker interpreter not found: {py}\n"
            f"Build the Incalmo host virtualenv before running an Incalmo attacker:\n"
            f"    cd {incalmo_dir} && uv sync"
        )
    config_json = incalmo_dir / "config" / "config.json"
    if not config_json.exists():
        example = incalmo_dir / "config" / "config_example.json"
        if not example.exists():
            raise RuntimeError(
                f"Incalmo config missing: {config_json} (and no {example} to seed it from).\n"
                f"Create {config_json} with a valid AttackerConfig before running an Incalmo attacker."
            )
        shutil.copyfile(example, config_json)
    try:
        _cfg = json.loads(config_json.read_text())
        if _cfg.get("blacklist_ips") != ["172.17.0.0/16"]:
            _cfg["blacklist_ips"] = ["172.17.0.0/16"]
            config_json.write_text(json.dumps(_cfg, indent=4))
    except (OSError, ValueError):
        pass


@dataclass
class IncalmoPreparedC2(PreparedAttacker):
    """setup() baton carrying the C2 URLs for build_config()/run()."""
    remote_url: Optional[str] = None
    local_url: Optional[str] = None


# Strategies that drive Metasploit directly and need msfrpcd + pymetasploit3 installed on the foothold.
_MSF_STRATEGIES = {"MsfBindTestStrategy"}


class IncalmoStrategyAttacker(AttackerPlugin, config_type="incalmo_strategy"):
    type: Literal["incalmo_strategy"]

    requires_docker: ClassVar[bool] = True
    code_dir_field: ClassVar[str] = "incalmo_strategy_dir"
    code_python_field: ClassVar[str] = "incalmo_strategy_python"

    REQUIRED_CONFIG_KEYS = frozenset(
        {"name", "strategy", "environment", "c2c_server", "agent_c2c_server", "blacklist_ips"})
    strategy: str
    script_path: Optional[str] = None

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "GraphSearch"
        return value

    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    @classmethod
    def example_prepared(cls) -> PreparedAttacker:
        """Return a filled-in baton for offline tests."""
        return IncalmoPreparedC2(local_url="http://127.0.0.1:8888", remote_url="http://foothold:8888")

    @classmethod
    def sweep_stale_state(cls, cfg: ExperimentManagerConfig) -> None:
        """Reap orphaned foothold-C2 ssh -L tunnels left by a crashed prior manager."""
        sweep_stale_tunnels()

    async def setup(self, experiment, cfg: ExperimentManagerConfig, bastion_ip, access=None) -> PreparedAttacker:
        """Bring up the C2 on the foothold, prep it, and block until an agent beacons in."""
        _preflight_incalmo_host(self._code_dir(cfg), self._code_python(cfg))
        foothold_access = self.primary_access(access) if access else None
        if foothold_access is None:
            raise RuntimeError("the Incalmo C2 runs on the attacker foothold, but setup() got no AttackerSetupAccess")
        _sentinel, remote_url, local_url = await self.launch_c2c(
            experiment.experiment_name, cfg, bastion_ip, foothold_access=foothold_access)
        try:
            if local_url:
                await self.wait_c2c_ready(local_url, experiment.experiment_name)
            await self.prepare_foothold(experiment, cfg, bastion_ip, remote_url, access)
            if local_url:
                await self.wait_c2c_agent(local_url, experiment.experiment_name)
        except Exception:
            await self.teardown(experiment.experiment_name, cfg)
            raise
        return IncalmoPreparedC2(remote_url=remote_url, local_url=local_url)

    async def prepare_foothold(self, experiment, cfg: ExperimentManagerConfig, bastion_ip, remote_url, access=None):
        """Land the sandcat agent (and msf for msf strategies) on the attacker's foothold(s)."""
        await foothold.land_sandcat(_require_access(access), remote_url, cfg, experiment.experiment_name)
        if self.strategy in _MSF_STRATEGIES:
            await foothold.install_metasploit(_require_access(access), cfg, experiment.experiment_name)

    async def launch_c2c(
        self, experiment_name: str, cfg: ExperimentManagerConfig, bastion_ip: Optional[str] = None,
        foothold_access=None,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        return await start_c2c_server(experiment_name, cfg, bastion_ip, foothold_access=foothold_access,
                                      incalmo_dir=self._code_dir(cfg))

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        await wait_for_c2c_ready(local_url, experiment_name)

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        await wait_for_agent(local_url, experiment_name)

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        await stop_c2c_server(experiment_name)

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "incalmo_strategy",
            "label": "Incalmo Strategy",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": ["GraphSearch", "Darkside", "EquifaxStrategy", "MulvalOptimal", "OptimalReplayStrategy"],
                    "short_names": {
                        "GraphSearch": "graphsrch",
                        "Darkside": "darkside",
                        "EquifaxStrategy": "eq_strategy",
                        "MulvalOptimal": "mulval_opt",
                        "OptimalReplayStrategy": "opt_replay",
                    },
                },
                {
                    "field_type": "text_with_suggestions",
                    "label": "Script path (OptimalReplayStrategy only)",
                    "key": "script_path",
                    "suggestions": [],
                    "default": "",
                },
            ],
        }

    def build_config(self, experiment_name: str, env_spec: AttackerEnvSpec, prepared: PreparedAttacker) -> dict:
        strategy = {"name": self.strategy}
        if self.script_path:
            strategy["script_path"] = self.script_path
        return {
            "name": experiment_name,
            "strategy": strategy,
            "environment": env_spec.objective,
            "c2c_server": prepared.local_url,
            "agent_c2c_server": prepared.remote_url,
            "blacklist_ips": ["172.17.0.0/16"],
        }

    async def run(self, prepared: PreparedAttacker, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(self._code_python(cfg)), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(self._code_dir(cfg)),
            env={
                **os.environ,
                "C2C_SERVER": prepared.local_url,
                "C2C_SERVER_AGENTS": prepared.remote_url or prepared.local_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(self._code_dir(cfg) / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
