import asyncio
import os
from pathlib import Path
from typing import ClassVar, Literal, Optional

from ..config import ExperimentManagerConfig
from ..environment import DeployedEnvironment
from .base import AttackerPlugin

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


class IncalmoStrategyAttacker(AttackerPlugin, config_type="incalmo_strategy"):
    c2c_image: ClassVar[str] = "experiment-harness/c2c:latest"
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
        return await asyncio.create_subprocess_exec(
            str(cfg.incalmo_dir / ".venv" / "bin" / "python"), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={**os.environ, "C2C_SERVER": c2c_url},
        )


class IncalmoLLMAttacker(AttackerPlugin, config_type="incalmo_llm"):
    c2c_image: ClassVar[str] = "experiment-harness/c2c:latest"
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
        return await asyncio.create_subprocess_exec(
            str(cfg.incalmo_dir / ".venv" / "bin" / "python"), "-c", _RUNNER,
            str(config_path), experiment_name,
            cwd=str(cfg.incalmo_dir),
            env={**os.environ, "C2C_SERVER": c2c_url},
        )
