import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"


class ExperimentManagerConfig(BaseModel):
    mhbench_dir: Path
    arena_host_ip: str
    output_dir: Path = _HERE / "output"
    ansible_log_dir: str = "experiment/ansible"
    registry_path: Path = _HERE / "experiment_registry.yaml"
    env_action_socket: Optional[str] = None
    max_concurrent_openstack_ops: int = 3
    max_concurrent_configures: int = 5
    max_concurrent_collects: int = 2
    max_concurrent_attacker_setups: int = 2
    max_retries: int = 3
    max_active_experiments: int = 25
    max_active_vms: Optional[int] = None
    max_active_cpus: Optional[int] = None
    max_deployed: int = 10
    attacker_timeout_seconds: Optional[float] = None
    experiment_timeout_seconds: Optional[float] = None
    ansible_verbosity: int = int(os.environ.get("ANSIBLE_VERBOSITY", "0"))
    defender_ready_timeout_seconds: float = 1800
    attacker_setup_started_timeout_seconds: float = 120

    incalmo_strategy_dir: Optional[Path] = None
    incalmo_strategy_python: Optional[Path] = None
    incalmo_llm_dir: Optional[Path] = None
    incalmo_llm_python: Optional[Path] = None
    sliver_llm_dir: Optional[Path] = None
    sliver_llm_python: Optional[Path] = None
    llm_soc_dir: Optional[Path] = None
    llm_soc_python: Optional[Path] = None
    deception_dir: Optional[Path] = None
    deception_python: Optional[Path] = None
    prompt_injection_dir: Optional[Path] = None
    prompt_injection_python: Optional[Path] = None
    velociraptor_dir: Optional[Path] = None

    def plugin_dir(self, field: str) -> Path:
        """The external code checkout for the plugin whose dir field is `field`."""
        d = getattr(self, field, None)
        if d is None:
            raise ValueError(f"cfg.{field} is unset — set it to the plugin's code checkout in config.yaml")
        return Path(d)

    def plugin_python(self, dir_field: str, python_field: str) -> Path:
        """Interpreter for that plugin's venv: the explicit *_python override, else <dir>/.venv/bin/python."""
        explicit = getattr(self, python_field, None)
        return Path(explicit) if explicit else (self.plugin_dir(dir_field) / ".venv" / "bin" / "python")

    def get_sliver_dir(self) -> Path:
        return Path(self.sliver_llm_dir) if self.sliver_llm_dir else (self.output_dir / ".sliver")

    def get_sliver_python(self) -> Path:
        return Path(self.sliver_llm_python) if self.sliver_llm_python else (self.get_sliver_dir() / ".venv" / "bin" / "python")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ExperimentManagerConfig":
        """Load config from an explicit path, else $EXPERIMENT_MANAGER_CONFIG, else config.yaml."""
        if path is None:
            env = os.environ.get("EXPERIMENT_MANAGER_CONFIG")
            path = Path(env) if env else _DEFAULT_CONFIG_PATH
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
