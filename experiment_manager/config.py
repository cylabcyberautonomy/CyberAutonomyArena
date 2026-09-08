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
    # How long to wait for a defender to finish arming (its strategy's initialize():
    # booting decoys, planting fake data and honey credentials) before the attacker
    # is allowed to start. Generous by default - arming is bounded by real VM boots
    # and ansible runs, and scales with the arsenal size. Exceeding it fails the
    # experiment rather than silently racing.
    defender_ready_timeout_seconds: float = 1800
    deception_python: Optional[Path] = None
    # Detection: Zircolite runs the shipped Sigma Linux ruleset over each host's collected auditd log.
    zircolite_dir: Path = Path.home() / "Zircolite"
    zircolite_python: Optional[Path] = None  # defaults to <zircolite_dir>/.venv/bin/python
    sigma_ruleset: str = "rules/rules_linux.json"  # relative to zircolite_dir; the Auditd/Sysmon-for-Linux ruleset
    # Custom Sigma rules for MHBench's high-value auditd keys (credential access, lateral movement,
    # evasion) that the stock ruleset doesn't cover. A dir of .yml Sigma rules, versioned with the harness.
    custom_sigma_rules_dir: Path = _HERE / "experiment_manager" / "detection" / "sigma_rules"

    def get_incalmo_python(self) -> Path:
        return self.incalmo_python or (self.incalmo_dir / ".venv" / "bin" / "python")

    def get_zircolite_python(self) -> Path:
        return self.zircolite_python or (self.zircolite_dir / ".venv" / "bin" / "python")

    def get_deception_python(self) -> Path:
        return self.deception_python or (self.deception_dir / ".venv" / "bin" / "python")

    @classmethod
    def load(cls, path: Path = _DEFAULT_CONFIG_PATH) -> "ExperimentManagerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
