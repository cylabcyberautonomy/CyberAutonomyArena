import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"

# Environment-backend settings (cloud_backend/os_cloud/mhbench_config/gcp_relay_ip/gcp_flavor_cpu_cost) are
# NOT arena config — they belong to the environment layer and live in arena/environment/config.py
# (EnvBackendConfig, loaded from config.yaml's `env_backend:` section). The arena is backend-neutral; it
# no longer carries these fields. Deprecated flat forms in config.yaml are ignored here (extra keys) and
# migrated by the env-layer loader for back-compat.


class ExperimentManagerConfig(BaseModel):
    mhbench_dir: Path  # the environment backend (MHBench) — always required; holds the topology specs + scoped keys
    arena_host_ip: str  # the arena/manager host's own IP as reachable from the deployed VMs; handed to defenders as their config's management_ip so their self-protection never acts against the harness host. NOT the per-experiment bastion (that is returned by the environment's provision()).
    output_dir: Path = _HERE / "output"
    ansible_log_dir: str = "experiment/ansible"  # per-experiment subpath under output_dir/<exp>/ for per-host ansible logs
    registry_path: Path = _HERE / "experiment_registry.yaml"
    env_action_socket: Optional[str] = None  # path of the UDS the defender→env action channel listens on. None = derived per-manager from a hash of output_dir (so two managers on one host don't collide). Never a TCP port: an in-env VM must not be able to reach it (see env_action_server.py).
    max_retries: int = 3
    # NOTE: this build is PURELY SEQUENTIAL — the arena runs exactly one experiment at a time. The
    # parallel-experiment admission knobs (max_active_experiments / max_active_vms / max_active_cpus /
    # max_deployed / max_concurrent_*) and the capacity tracker were removed.
    attacker_timeout_seconds: Optional[float] = None  # harness-enforced attacker wall-clock cap on REAL elapsed time; None = no cap. On timeout the harness SIGTERMs the attacker (escalating to a SIGKILL of its process group if it ignores that) and marks status TimedOut (terminal, no retry). No rate-limit backoff credit — a heavily-throttled run is measured on real time, so raise the cap if throttling pushes healthy runs over it.
    experiment_timeout_seconds: Optional[float] = None  # overall wall-clock cap on the WHOLE experiment lifecycle (provision -> configure -> attacker setup -> defender arm -> attack -> collect -> teardown); None = no cap. A backstop for a total hang the per-phase/handshake waits + attacker cap don't bound: on the deadline the arena cancels the run, force-kills the attacker, tears down (reclaims VMs + capacity), and marks status ExperimentTimedOut (terminal, no retry). Distinct from attacker_timeout_seconds, which is a SCORED attacker run cap; this is a safety abort of a hung run.
    ansible_verbosity: int = int(os.environ.get("ANSIBLE_VERBOSITY", "0"))  # 0-4 (-vvvv); default from $ANSIBLE_VERBOSITY (main.sh), config.yaml overrides
    # How long to wait for a defender to finish arming (its strategy's initialize():
    # booting decoys, planting fake data and honey credentials) before the attacker
    # is allowed to start. Generous by default - arming is bounded by real VM boots
    # and ansible runs, and scales with the arsenal size. Exceeding it fails the
    # experiment rather than silently racing.
    defender_ready_timeout_seconds: float = 1800
    attacker_setup_started_timeout_seconds: float = 120  # handshake backstop: how long the arena waits for the attacker's setup_started ack (emitted at the top of setup) before giving up. NOT the setup/ready cap — setup itself (C2 bring-up, foothold prep) is bounded by its own internal waits.

    # ---- Per-plugin code paths -----------------------------------------------------------------------
    # One *_dir per plugin that shells out to an external checkout; SET ONLY THE ONES FOR THE PLUGINS YOU
    # RUN (mhbench_dir above is the one always-required path — the environment backend). Each takes an
    # optional *_python override, defaulting to <its_dir>/.venv/bin/python. Redundancy is intentional:
    # plugins that share a repo (the two incalmo attackers; the three Defense/Perry defenders) each name it,
    # so no single field silently backs several plugins.
    incalmo_strategy_dir: Optional[Path] = None      # Incalmo repo — incalmo_strategy attacker
    incalmo_strategy_python: Optional[Path] = None
    incalmo_llm_dir: Optional[Path] = None           # Incalmo repo — incalmo_llm attacker
    incalmo_llm_python: Optional[Path] = None
    sliver_llm_dir: Optional[Path] = None            # Sliver operator venv — sliver_llm attacker; defaults to <output_dir>/.sliver
    sliver_llm_python: Optional[Path] = None
    llm_soc_dir: Optional[Path] = None               # Defense/Perry repo — llm_soc defender
    llm_soc_python: Optional[Path] = None
    deception_dir: Optional[Path] = None             # Defense/Perry repo — deception defender
    deception_python: Optional[Path] = None
    prompt_injection_dir: Optional[Path] = None      # Defense/Perry repo — prompt_injection defender
    prompt_injection_python: Optional[Path] = None
    velociraptor_dir: Optional[Path] = None          # Velociraptor repo — velociraptor defender (holds bin/velociraptor); a Go binary, no venv/python

    def plugin_dir(self, field: str) -> Path:
        """The external code checkout for the plugin whose dir field is `field` (per-plugin, set in
        config.yaml). Raises a clear error if unset — you set only the paths for the plugins you run."""
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
        # An explicit arg wins; else $EXPERIMENT_MANAGER_CONFIG (lets a second manager run a
        # non-default backend safely); else the default config.yaml. Without this a second
        # manager silently loads config.yaml (OpenStack) and its startup clean-slate wipes the
        # shared cloud — see the 2026-09-16 incident.
        if path is None:
            env = os.environ.get("EXPERIMENT_MANAGER_CONFIG")
            path = Path(env) if env else _DEFAULT_CONFIG_PATH
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
