import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from .config import ExperimentManagerConfig
from .models import DeployedEnvironment

# Inline runner: bypasses ConfigService (which hardcodes ./config/config.json)
# by importing Incalmo internals directly and loading config from a given path.
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


async def run_attacker(
    strategy: str,
    environment: Optional[DeployedEnvironment],
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    c2c_server: Optional[str] = None,  # TEST ONLY: bypasses environment-derived URL
) -> asyncio.subprocess.Process:
    """
    Spawn an Incalmo attacker strategy as a subprocess against the deployed OpenStack environment.
    Returns the Process so the caller can await its exit code and track its PID.
    EM writes result.json after process.wait() returns.
    """
    resolved_c2c = c2c_server or f"http://{environment.ip}:{cfg.c2c_port}"
    config = {
        "name": experiment_name,
        "strategy": {"name": strategy},
        "environment": environment.spec if environment else "none",
        "c2c_server": resolved_c2c,
        "blacklist_ips": [],
    }

    config_path = cfg.output_dir / experiment_name / "incalmo_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))

    incalmo_python = cfg.incalmo_dir / ".venv" / "bin" / "python"

    env = {**os.environ, "C2C_SERVER": resolved_c2c}

    return await asyncio.create_subprocess_exec(
        str(incalmo_python), "-c", _RUNNER,
        str(config_path), experiment_name,
        cwd=str(cfg.incalmo_dir),
        env=env,
    )
