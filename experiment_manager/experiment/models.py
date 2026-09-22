import json
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel

from ..attacker import AttackerConfig
from ..defender import DefenderConfig
from ..traffic import TrafficConfig


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    DEPLOYING = "Deploying"        # VMs being spun up by OpenStack
    DEPLOYED = "Deployed"          # VMs up; holding a deploy slot, waiting for a configure slot (back-pressure buffer)
    CONFIGURING = "Configuring"    # ansible playbooks running on the hosts
    CONFIGURED = "Configured"      # configure done; waiting to start the attack
    RUNNING = "Running"
    RETRYING = "Retrying"   # non-terminal: an attempt failed but the harness is auto-retrying it in place
    ERROR = "Error"
    FINISHED = "Finished"
    TIMEDOUT = "TimedOut"   # terminal: hit the harness-enforced attacker wall-clock cap (not a failure — no retry)
    BLOCKED = "Blocked"     # terminal: the attacker LLM was refused by a provider guardrail (not a harness failure — no retry)


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    traffic: Optional[TrafficConfig] = None  # third plugin class: benign background traffic on victim hosts
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup
    trial: int = 0
    output_dir: Optional[str] = None  # write this experiment's output tree here instead of cfg.output_dir
    teardown: bool = True  # set False to leave the env + C2 standing (success AND failure) to run an exploit by hand
    overwrite: bool = False  # if an output folder with this name already exists: false (default) → reject the request (409); true → replace it


def _json_default(o):
    if isinstance(o, datetime):
        return o.timestamp()  # epoch seconds (float, sub-second) — matches the host logs; format at analysis time
    if isinstance(o, BaseModel):  # attacker/defender configs, DeployedEnvironment
        return o.model_dump(mode="json")
    return str(o)


# Which metadata keys are input config (→ experiment_config.json). Everything else is runtime state
# (status + all timestamps + reservations/pid/c2c/deployed) and goes to experiment_result.json.
_CONFIG_KEYS = {
    "experiment": ("name", "trial", "teardown"),
    "environment": ("spec",),
    "attacker": ("config",),
    "defender": ("config",),
    "traffic": ("config",),
}


class _Field:
    """Descriptor proxying a flat attribute (`experiment.attacker_started_at`) onto
    `metadata[group][key]`, so every existing `experiment.<field>` read/write keeps working while the
    data lives in one grouped dict."""

    def __init__(self, group: str, key: str) -> None:
        self._group, self._key = group, key

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return obj.metadata[self._group][self._key]

    def __set__(self, obj, value) -> None:
        obj.metadata[self._group][self._key] = value


class Experiment:
    """One experiment. All state lives in `self.metadata`, grouped by concern
    (experiment / environment / attacker / defender). The flat accessors below are descriptors onto
    that dict — callers use `experiment.status`, `experiment.attacker_started_at`, etc. as before."""

    # --- experiment ---
    experiment_name = _Field("experiment", "name")
    trial = _Field("experiment", "trial")
    status = _Field("experiment", "status")
    error = _Field("experiment", "error")  # human-readable failure reason when status is Error/TimedOut; None otherwise
    retry_count = _Field("experiment", "retry_count")
    base_name = _Field("experiment", "base_name")
    teardown = _Field("experiment", "teardown")
    created_at = _Field("experiment", "created_at")
    updated_at = _Field("experiment", "updated_at")
    # --- environment ---
    environment_spec = _Field("environment", "spec")
    deployed_environment = _Field("environment", "deployed")
    vcpus_reserved = _Field("environment", "vcpus_reserved")
    ram_mb_reserved = _Field("environment", "ram_mb_reserved")
    environment_deploy_started_at = _Field("environment", "deploy_started_at")
    environment_deploy_finished_at = _Field("environment", "deploy_finished_at")
    teardown_started_at = _Field("environment", "teardown_started_at")
    teardown_finished_at = _Field("environment", "teardown_finished_at")
    # --- attacker ---
    attacker = _Field("attacker", "config")
    pid = _Field("attacker", "pid")
    c2c_container_id = _Field("attacker", "c2c_container_id")
    attacker_started_at = _Field("attacker", "started_at")
    attacker_finished_at = _Field("attacker", "finished_at")
    # --- defender ---
    defender = _Field("defender", "config")
    defender_started_at = _Field("defender", "started_at")
    defender_finished_at = _Field("defender", "finished_at")
    # --- traffic (third plugin class: background traffic on victim hosts) ---
    traffic = _Field("traffic", "config")
    traffic_started_at = _Field("traffic", "started_at")
    traffic_finished_at = _Field("traffic", "finished_at")

    def __init__(self, experiment_name, status, environment_spec, attacker=None, defender=None,
                 traffic=None, trial=0, teardown=True, created_at=None, updated_at=None):
        created_at = created_at or datetime.now(timezone.utc)
        self.metadata = {
            "experiment": {
                "name": experiment_name, "trial": trial, "status": status, "error": None,
                "retry_count": 0, "base_name": "", "teardown": teardown,
                "created_at": created_at, "updated_at": updated_at or created_at,
            },
            "environment": {
                "spec": environment_spec, "deployed": None,
                "vcpus_reserved": None, "ram_mb_reserved": None,
                "deploy_started_at": None, "deploy_finished_at": None,
                "teardown_started_at": None, "teardown_finished_at": None,
            },
            "attacker": {
                "config": attacker, "pid": None, "c2c_container_id": None,
                "started_at": None, "finished_at": None,
            },
            "defender": {
                "config": defender, "started_at": None, "finished_at": None,
            },
            "traffic": {
                "config": traffic, "started_at": None, "finished_at": None,
            },
        }

    def flat(self) -> dict:
        """The old flat shape, for the REST API — keeps the PhDPT contract stable while state is grouped."""
        return {name: getattr(self, name)
                for name, attr in vars(type(self)).items() if isinstance(attr, _Field)}

    def config_json(self, indent=2) -> str:
        """The immutable submission record (grouped): input config only, no runtime/timestamps."""
        d = {g: {k: self.metadata[g][k] for k in ks} for g, ks in _CONFIG_KEYS.items()}
        return json.dumps(d, indent=indent, default=_json_default)

    def result_json(self, indent=2) -> str:
        """The runtime record (grouped): status + all timestamps + reservations/pid/c2c/deployed."""
        d = {g: {k: v for k, v in grp.items() if k not in _CONFIG_KEYS.get(g, ())}
             for g, grp in self.metadata.items()}
        return json.dumps(d, indent=indent, default=_json_default)
