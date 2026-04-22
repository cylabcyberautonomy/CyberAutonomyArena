from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path
from typing import Literal, Optional

from .c2c import start_c2c_server, stop_c2c_server, wait_for_agent, wait_for_c2c_ready
from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ..base import AttackerPlugin

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

    def build_config(self, experiment_name: str, environment: Optional[DeployedEnvironment], c2c_url: str) -> dict:
        return {
            "name": experiment_name,
            "strategy": {"name": self.strategy},
            "environment": environment.spec if environment else "none",
            "c2c_server": c2c_url,
            "blacklist_ips": [],
        }

    async def run(self, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig, c2c_url: str) -> asyncio.subprocess.Process:
        log_path = cfg.output_dir / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                "INCALMO_OUTPUT_DIR": str(cfg.output_dir / experiment_name / "attacker"),
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
        log_path = cfg.output_dir / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        return await asyncio.create_subprocess_exec(
            str(cfg.get_incalmo_python()), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={
                **os.environ,
                "C2C_SERVER": c2c_url,
                "INCALMO_OUTPUT_DIR": str(cfg.output_dir / experiment_name / "attacker"),
                "PYTHONPATH": str(cfg.incalmo_dir / ".venv" / "lib" / "python3.13" / "site-packages"),
            },
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
