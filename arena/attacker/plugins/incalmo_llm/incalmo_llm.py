from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Optional

from .c2 import (start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready,
                 sweep_stale_tunnels)
from . import foothold
from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ...env_spec import AttackerEnvSpec
from ....ui_schema import PluginUISchema
from ..base import AttackerPlugin, PreparedAttacker

# Incalmo C2 attacker driven by a free-form LLM planning loop.


def _require_access(access):
    """Return the AttackerSetupAccess list, raising if the arena passed none."""
    if not access:
        raise RuntimeError("no AttackerSetupAccess passed to the attacker — the arena must pass it to run_setup()")
    return access

# Suggested models for the dashboard dropdowns. planning_llm/execution_llm are free-form strings.
_LLM_GROUPS = [
    {"group_label": "Anthropic (needs ANTHROPIC_API_KEY)", "options": [
        "claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6",
        "claude-4.5-sonnet", "claude-3.7-sonnet", "claude-3.5-sonnet", "claude-3.5-haiku",
    ]},
    {"group_label": "OpenAI (needs OPENAI_API_KEY)", "options": [
        "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
        "gpt-4o", "gpt-4o-mini",
        "o4-mini", "o3-mini", "o3",
        "gpt-5", "gpt-5-mini",
    ]},
    {"group_label": "Google (needs GOOGLE_API_KEY)", "options": [
        "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash",
    ]},
    {"group_label": "DeepSeek (needs DEEPSEEK_API_KEY)", "options": ["deepseek-v3", "deepseek-r1"]},
    {"group_label": "OpenRouter (needs OPENROUTER_API_KEY)", "options": [
        "kimi-k3", "glm-5.2", "kimi-k2-base", "qwen3-235b-non-thinking", "glm-4.5",
        "qwen3.8-max", "qwen3-8",
    ]},
]

# Abstraction levels that drive an on-host LLM sub-agent and consume execution_llm.
_AGENT_ABSTRACTIONS = [
    "agent_scan", "agent_lateral_move", "agent_privilege_escalation",
    "agent_exfiltrate_data", "agent_find_information", "agent_all",
]

_ABSTRACTION_LEVELS = [
    "incalmo", "shell", "low_level_actions", "no_services",
    *_AGENT_ABSTRACTIONS,
]

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
    """Fail fast if the Incalmo host-side prerequisites (interpreter, config) are missing."""
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
    """Incalmo's setup() output: the C2's URLs carried on the baton."""
    remote_url: Optional[str] = None
    local_url: Optional[str] = None


class IncalmoLLMAttacker(AttackerPlugin, config_type="incalmo_llm"):
    type: Literal["incalmo_llm"]

    requires_docker: ClassVar[bool] = True
    code_dir_field: ClassVar[str] = "incalmo_llm_dir"
    code_python_field: ClassVar[str] = "incalmo_llm_python"

    REQUIRED_CONFIG_KEYS = frozenset(
        {"name", "strategy", "environment", "c2c_server", "agent_c2c_server", "blacklist_ips"})
    planning_llm: str
    execution_llm: str = ""
    abstraction: str = "incalmo"

    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    @classmethod
    def example_prepared(cls) -> PreparedAttacker:
        """Return a filled-in prepared baton for offline tests."""
        return IncalmoPreparedC2(local_url="http://127.0.0.1:8888", remote_url="http://foothold:8888")

    @classmethod
    def sweep_stale_state(cls, cfg: ExperimentManagerConfig) -> None:
        """Reap orphaned foothold-C2 tunnels left by a crashed prior manager."""
        sweep_stale_tunnels()

    async def setup(self, experiment, cfg: ExperimentManagerConfig, bastion_ip, access=None) -> PreparedAttacker:
        """Launch the C2 on the foothold, prep it, and block until an agent beacons in."""
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
        """Land the sandcat agent and install Metasploit on the attacker's foothold(s)."""
        await foothold.land_sandcat(_require_access(access), remote_url, cfg, experiment.experiment_name)
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
        llm_groups = _LLM_GROUPS
        return {
            "config_type": "incalmo_llm",
            "label": "Incalmo LLM",
            "cartesian_product": True,
            "fields": [
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Planning LLM",
                    "key": "planning_llm",
                    "groups": llm_groups,
                },
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Execution LLM",
                    "key": "execution_llm",
                    "groups": llm_groups,
                    "show_when": {"abstraction": _AGENT_ABSTRACTIONS},
                },
                {
                    "field_type": "flat_checkboxes",
                    "label": "Abstraction",
                    "key": "abstraction",
                    "options": _ABSTRACTION_LEVELS,
                    "short_names": {
                        "incalmo": "incalmo",
                        "shell": "shell",
                        "low_level_actions": "lowlevel",
                        "no_services": "no_svcs",
                        "agent_scan": "agent_scan",
                        "agent_lateral_move": "agent_latmv",
                        "agent_privilege_escalation": "agent_privesc",
                        "agent_exfiltrate_data": "agent_exfil",
                        "agent_find_information": "agent_find",
                        "agent_all": "agent_all",
                    },
                },
            ],
        }

    def build_config(self, experiment_name: str, env_spec: AttackerEnvSpec, prepared: PreparedAttacker) -> dict:
        return {
            "name": experiment_name,
            "strategy": {
                "planning_llm": self.planning_llm,
                "execution_llm": self.execution_llm or self.planning_llm,
                "abstraction": self.abstraction,
            },
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
