import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, field_validator, model_validator

from ..attacker import AttackerConfig
from ..defender import DefenderConfig
from ..traffic import TrafficConfig
from ..environment import build_environment
from ..environment.environment import EnvironmentConfig


def _load_spec_file(spec_path: Optional[str]) -> dict:
    """Read a plugin spec from a file path (JSON or YAML). A missing path means an empty spec
    (plugin defaults). The file must hold a mapping — the bespoke fields the plugin parses."""
    if not spec_path:
        return {}
    p = Path(spec_path).expanduser()
    if not p.exists():
        raise ValueError(f"spec file not found: {spec_path}")
    data = yaml.safe_load(p.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"spec file {spec_path} must contain a mapping, got {type(data).__name__}")
    return data


def _resolve_plugin(registry, plugin_name: str, spec_path: Optional[str]):
    """Resolve a (plugin, spec-file) pair to a validated plugin instance. The plugin selects the
    implementation; the spec file holds its bespoke input. `plugin_name` is injected as `type`, so
    the spec file need not repeat it (and cannot override the chosen plugin)."""
    cls = registry._registry.get(plugin_name)
    if cls is None:
        raise ValueError(f"Unknown plugin {plugin_name!r}. Available: {list(registry._registry)}")
    spec = _load_spec_file(spec_path)
    return cls.model_validate({**spec, "type": plugin_name})


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
    # environment (the 4th selectable system): {environment_plugin: mhbench, environment_spec: ...},
    # or a bare env-name string (→ mhbench). Explicit plugin+spec shape (environment only).
    environment: EnvironmentConfig
    # attacker as a (plugin, spec-file) pair. attacker_plugin selects the implementation; attacker_spec
    # is a PATH to a JSON/YAML file holding that plugin's bespoke spec. Resolved into `attacker` below.
    # The embedded `attacker: {type, ...}` form is also accepted.
    attacker_plugin: Optional[str] = None
    attacker_spec: Optional[str] = None
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    traffic: Optional[TrafficConfig] = None  # third plugin class: benign background traffic on victim hosts
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup
    trial: int = 0
    output_dir: Optional[str] = None  # write this experiment's output tree here instead of cfg.output_dir
    teardown: bool = True  # set False to leave the env + C2 standing (success AND failure) to run an exploit by hand
    overwrite: bool = False  # if an output folder with this name already exists: false (default) → reject the request (409); true → replace it
    priority: int = 0  # scheduling priority: higher = admitted from the queue sooner; 0 (default) = normal "whoever fits". Ties break FIFO.

    @field_validator("environment", mode="before")
    @classmethod
    def _coerce_environment(cls, v):
        # Accept the explicit {environment_plugin, environment_spec} shape, a bare env-name string, or
        # the legacy {type, spec} dict — all coerce to EnvironmentConfig.
        return EnvironmentConfig.coerce(v)

    @model_validator(mode="after")
    def _resolve_attacker_plugin_spec(self):
        """attacker_plugin + attacker_spec (file) -> the validated attacker plugin instance in
        `self.attacker`, so everything downstream (Experiment.attacker, build_config, ...) is
        unchanged. Give the pair OR the embedded form, not both.

        The experiment base is environment + attacker: both are required. defender and traffic are
        optional (None = the experiment simply runs without that system)."""
        if self.attacker_plugin:
            if self.attacker is not None:
                raise ValueError("provide attacker_plugin (+attacker_spec) OR the embedded 'attacker', not both")
            from ..attacker.plugins.base import AttackerPlugin
            self.attacker = _resolve_plugin(AttackerPlugin, self.attacker_plugin, self.attacker_spec)
        if self.attacker is None:
            raise ValueError(
                "an experiment requires an attacker: provide attacker_plugin (+attacker_spec) or an "
                "embedded 'attacker'. (environment + attacker are the required base; defender and "
                "traffic are optional.)"
            )
        return self


def _json_default(o):
    if isinstance(o, datetime):
        return o.timestamp()  # epoch seconds (float, sub-second) — matches the host logs; format at analysis time
    if isinstance(o, BaseModel):  # attacker/defender configs, DeployedEnvironment
        return o.model_dump(mode="json")
    return str(o)


# Which metadata keys are input config (→ experiment_config.json). Everything else is runtime state
# (status + all timestamps + reservations/pid/c2c/deployed) and goes to experiment_result.json.
_CONFIG_KEYS = {
    "experiment": ("name", "trial", "teardown", "priority"),
    "environment": ("config", "spec"),
    "attacker": ("config", "plugin", "spec_path"),
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
    priority = _Field("experiment", "priority")  # queue scheduling priority; higher = sooner (see reserve())
    created_at = _Field("experiment", "created_at")
    updated_at = _Field("experiment", "updated_at")
    # --- environment ---
    environment_config = _Field("environment", "config")  # EnvironmentConfig (environment_plugin + environment_spec)
    environment_spec = _Field("environment", "spec")  # the topology PATH, for the internal readers (deployer resolves it)
    deployed_environment = _Field("environment", "deployed")
    vcpus_reserved = _Field("environment", "vcpus_reserved")
    ram_mb_reserved = _Field("environment", "ram_mb_reserved")
    disk_gb_reserved = _Field("environment", "disk_gb_reserved")
    # VMs this experiment was admitted for (topology incl. mgmt host + estimated decoys).
    # Set under the CapacityTracker's lock at admission; cleared on retry. Together with
    # teardown_finished_at this is what decides whether the experiment currently HOLDS
    # VMs (see capacity._holds_vms) - the registry is the tracker's source of truth.
    vms_reserved = _Field("environment", "vms_reserved")
    environment_deploy_started_at = _Field("environment", "deploy_started_at")
    environment_deploy_finished_at = _Field("environment", "deploy_finished_at")
    teardown_started_at = _Field("environment", "teardown_started_at")
    teardown_finished_at = _Field("environment", "teardown_finished_at")
    # The environment system's OWN lifecycle signal (see environment/lifecycle.py): the plugin emits
    # Deploying/Deployed/Configuring/Configured/TearingDown/TornDown/Failed and the arena records the
    # latest here — distinct from the whole-experiment `status` above.
    environment_status = _Field("environment", "lifecycle_status")
    environment_last_command = _Field("environment", "last_command")  # last command the arena SENT (Provision/Configure/Teardown)
    # --- attacker ---
    attacker = _Field("attacker", "config")
    attacker_plugin = _Field("attacker", "plugin")     # provenance: the plugin name the user selected
    attacker_spec = _Field("attacker", "spec_path")    # provenance: path to the spec file (if the pair form was used)
    pid = _Field("attacker", "pid")
    c2c_container_id = _Field("attacker", "c2c_container_id")
    attacker_started_at = _Field("attacker", "started_at")
    attacker_finished_at = _Field("attacker", "finished_at")
    # Lifecycle handshake (see attacker/lifecycle.py): the arena records each attacker signal here
    # as it drives setup->ready->running->stopping->stopped, so an observer can see exactly which
    # phase the attacker is in (and a hang shows up as a stalled status, not a silent block).
    attacker_status = _Field("attacker", "lifecycle_status")
    attacker_last_command = _Field("attacker", "last_command")  # last command the arena SENT (StartSetup/StartRun/Stop)
    attacker_setup_started_at = _Field("attacker", "setup_started_at")
    attacker_ready_at = _Field("attacker", "ready_at")
    attacker_stopping_at = _Field("attacker", "stopping_at")
    attacker_stopped_at = _Field("attacker", "stopped_at")
    # --- defender ---
    defender = _Field("defender", "config")
    defender_started_at = _Field("defender", "started_at")
    defender_finished_at = _Field("defender", "finished_at")
    # Lifecycle handshake (see defender/lifecycle.py), symmetric with the attacker: the arena records
    # each defender signal here as it drives setup->ready->running->stopping->stopped, so an observer
    # sees which phase the defender is in (a hang shows as a stalled status, not one opaque "failed to
    # arm"). defender_started_at also serves as the RUNNING timestamp.
    defender_status = _Field("defender", "lifecycle_status")
    defender_setup_started_at = _Field("defender", "setup_started_at")
    defender_ready_at = _Field("defender", "ready_at")
    defender_stopping_at = _Field("defender", "stopping_at")
    defender_stopped_at = _Field("defender", "stopped_at")
    # --- traffic (third plugin class: background traffic on victim hosts) ---
    traffic = _Field("traffic", "config")
    traffic_started_at = _Field("traffic", "started_at")
    traffic_finished_at = _Field("traffic", "finished_at")

    def __init__(self, experiment_name, status, environment, attacker=None, defender=None,
                 traffic=None, trial=0, teardown=True, created_at=None, updated_at=None, priority=0):
        created_at = created_at or datetime.now(timezone.utc)
        # `environment` is an EnvironmentConfig, a dict, or a bare env-name string; coerce to the config
        # and derive the resolved name for the many internal readers of environment_spec.
        env_config = EnvironmentConfig.coerce(environment)
        self.metadata = {
            "experiment": {
                "name": experiment_name, "trial": trial, "status": status, "error": None,
                "retry_count": 0, "base_name": "", "teardown": teardown, "priority": priority,
                "created_at": created_at, "updated_at": updated_at or created_at,
            },
            "environment": {
                "config": env_config, "spec": env_config.resolved_name, "deployed": None,
                "lifecycle_status": None, "last_command": None,
                "vcpus_reserved": None, "ram_mb_reserved": None,
                "disk_gb_reserved": None, "vms_reserved": None,
                "deploy_started_at": None, "deploy_finished_at": None,
                "teardown_started_at": None, "teardown_finished_at": None,
            },
            "attacker": {
                "config": attacker, "plugin": None, "spec_path": None, "pid": None, "c2c_container_id": None,
                "started_at": None, "finished_at": None,
                "lifecycle_status": None, "last_command": None, "setup_started_at": None,
                "ready_at": None, "stopping_at": None, "stopped_at": None,
            },
            "defender": {
                "config": defender, "started_at": None, "finished_at": None,
                "lifecycle_status": None, "setup_started_at": None, "ready_at": None,
                "stopping_at": None, "stopped_at": None,
            },
            "traffic": {
                "config": traffic, "started_at": None, "finished_at": None,
            },
        }

    @property
    def environment(self):
        """The executable environment PLUGIN (built from the stored EnvironmentConfig) that the arena
        drives — provision/configure/collect/teardown/capacity. Stored state is the config
        (environment_plugin + environment_spec); the plugin is derived on access."""
        return build_environment(self.environment_config)

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
