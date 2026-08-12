import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"


class ExperimentManagerConfig(BaseModel):
    incalmo_dir: Path
    incalmo_python: Optional[Path] = None
    mhbench_dir: Path
    host_ip: str
    output_dir: Path = _HERE / "output"
    ansible_log_dir: str = "experiment/ansible"  # per-experiment subpath under output_dir/<exp>/ for per-host ansible logs
    registry_path: Path = _HERE / "experiment_registry.yaml"
    os_cloud: str = "openstack"
    max_concurrent_openstack_ops: int = 3   # concurrent PROVISION (VM spin-up) + teardown — compute-heavy, keep tight
    max_concurrent_configures: int = 5       # concurrent ansible CONFIGURE — light, gate wider than provision
    max_retries: int = 3
    max_deployed: int = 10  # back-pressure: cap experiments in the deploy stage (DEPLOYING+DEPLOYED). A deploy slot is held from provision-start until configure-start, so when configure backs up, provisioning halts instead of piling up idle hosts.
    attacker_timeout_seconds: Optional[float] = None  # harness-enforced attacker wall-clock cap; None = no cap. On timeout the harness stops the attacker and marks status TimedOut (terminal, no retry).
    ansible_verbosity: int = int(os.environ.get("ANSIBLE_VERBOSITY", "0"))  # 0-4 (-vvvv); default from $ANSIBLE_VERBOSITY (main.sh), config.yaml overrides
    deception_dir: Optional[Path] = None
    deception_python: Optional[Path] = None

    def get_incalmo_python(self) -> Path:
        return self.incalmo_python or (self.incalmo_dir / ".venv" / "bin" / "python")

    def get_deception_python(self) -> Path:
        return self.deception_python or (self.deception_dir / ".venv" / "bin" / "python")

    @classmethod
    def load(cls, path: Path = _DEFAULT_CONFIG_PATH) -> "ExperimentManagerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
