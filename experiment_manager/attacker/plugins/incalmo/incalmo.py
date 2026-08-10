from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from .c2c import start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready
from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema
from ..base import AttackerPlugin

_LLM_GROUPS = [
    {"group_label": "Anthropic", "options": [
        "claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6",
        "claude-4.5-sonnet", "claude-3.7-sonnet", "claude-3.5-sonnet", "claude-3.5-haiku",
    ]},
    {"group_label": "OpenAI", "options": [
        "gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
        "gpt-4o", "gpt-4o-mini",
        "o4-mini", "o3-mini", "o3",
        "gpt-5", "gpt-5-mini",
    ]},
    {"group_label": "Google", "options": [
        "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash",
    ]},
    {"group_label": "DeepSeek", "options": ["deepseek-v3", "deepseek-r1"]},
]

_ABSTRACTION_LEVELS = [
    "incalmo", "shell", "low_level_actions", "no_services",
    "agent_scan", "agent_lateral_move", "agent_privilege_escalation",
    "agent_exfiltrate_data", "agent_find_information", "agent_all",
]

# Bypasses ConfigService (which hardcodes ./config/config.json) by loading
# config from a path passed as argv[1].
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


class _IncalmoAttacker(AttackerPlugin):
    """Shared C2C lifecycle for all Incalmo-based attackers."""

    async def launch_c2c(
        self, experiment_name: str, cfg: ExperimentManagerConfig
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        return await start_c2c_server(experiment_name, cfg)

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        await wait_for_c2c_ready(local_url, experiment_name)

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        await wait_for_agent(local_url, experiment_name)

    async def stop_c2c(self, container_id: str) -> None:
        await stop_c2c_server(container_id)


class IncalmoStrategyAttacker(_IncalmoAttacker, config_type="incalmo_strategy"):
    type: Literal["incalmo_strategy"]
    strategy: str  # e.g. "GraphSearch", "Darkside", "EquifaxStrategy"
    script_path: Optional[str] = None  # action_script.json path, required by OptimalReplayStrategy

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "GraphSearch"
        return value

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

    def build_config(self, experiment_name: str, environment: Optional[DeployedEnvironment], c2c_url: str) -> dict:
        strategy = {"name": self.strategy}
        if self.script_path:
            strategy["script_path"] = self.script_path
        return {
            "name": experiment_name,
            "strategy": strategy,
            "environment": environment.spec if environment else "none",
            "c2c_server": c2c_url,
            "blacklist_ips": [],
        }

    async def run(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig, c2c_url: str) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(cfg.incalmo_dir / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )


class IncalmoLLMAttacker(_IncalmoAttacker, config_type="incalmo_llm"):
    type: Literal["incalmo_llm"]
    planning_llm: str
    execution_llm: str
    abstraction: str = "incalmo"

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "incalmo_llm",
            "label": "Incalmo LLM",
            "cartesian_product": True,
            "fields": [
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Planning LLM",
                    "key": "planning_llm",
                    "groups": _LLM_GROUPS,
                },
                {
                    "field_type": "grouped_checkboxes",
                    "label": "Execution LLM",
                    "key": "execution_llm",
                    "groups": _LLM_GROUPS,
                },
                {
                    "field_type": "flat_checkboxes",
                    "label": "Abstraction",
                    "key": "abstraction",
                    "options": _ABSTRACTION_LEVELS,
                },
            ],
        }

    def build_config(self, experiment_name: str, environment: Optional[DeployedEnvironment], c2c_url: str) -> dict:
        return {
            "name": experiment_name,
            "strategy": {
                "planning_llm": self.planning_llm,
                "execution_llm": self.execution_llm,
                "abstraction": self.abstraction,
            },
            "environment": environment.spec if environment else "none",
            "c2c_server": c2c_url,
            "blacklist_ips": [],
        }

    async def run(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig, c2c_url: str) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                "INCALMO_OUTPUT_DIR": str(output_root(experiment_name, cfg) / experiment_name / "attacker"),
                "PYTHONPATH": str(cfg.incalmo_dir / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
