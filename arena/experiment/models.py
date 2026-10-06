import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Union

import yaml
from pydantic import BaseModel, field_validator, model_validator

from ..attacker import AttackerConfig
from ..defender import DefenderConfig
from ..environment import build_environment
from ..environment.environment import EnvironmentConfig


def _load_spec(spec: Union[dict, str, None]) -> dict:
    """Read a plugin spec: an inline dict, a path to a JSON/YAML mapping, or None."""
    if spec is None:
        return {}
    if isinstance(spec, dict):
        return spec
    p = Path(spec).expanduser()
    if not p.exists():
        raise ValueError(f"spec file not found: {spec}")
    data = yaml.safe_load(p.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"spec file {spec} must contain a mapping, got {type(data).__name__}")
    return data


def _resolve_plugin(registry, plugin_name: str, spec: Union[dict, str, None]):
    """Resolve a (plugin, spec) pair to a validated plugin instance."""
    cls = registry._registry.get(plugin_name)
    if cls is None:
        raise ValueError(f"Unknown plugin {plugin_name!r}. Available: {list(registry._registry)}")
    fields = _load_spec(spec)
    return cls.model_validate({**fields, "type": plugin_name})


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    DEPLOYING = "Deploying"
    DEPLOYED = "Deployed"
    CONFIGURING = "Configuring"
    CONFIGURED = "Configured"
    RUNNING = "Running"
    RETRYING = "Retrying"
    ERROR = "Error"
    FINISHED = "Finished"
    TIMEDOUT = "TimedOut"
    BLOCKED = "Blocked"
    EXPERIMENT_TIMEOUT = "ExperimentTimedOut"


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: EnvironmentConfig
    attacker_plugin: Optional[str] = None
    attacker_spec: Optional[Union[dict, str]] = None
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    c2c_server: Optional[str] = None
    trial: int = 0
    output_dir: Optional[str] = None
    teardown: bool = True
    overwrite: bool = False
    priority: int = 0

    @field_validator("environment", mode="before")
    @classmethod
    def _require_explicit_environment(cls, v):
        if isinstance(v, EnvironmentConfig):
            return v
        if isinstance(v, dict) and "environment_plugin" in v:
            return v
        raise ValueError(
            "environment must be {environment_plugin, environment_spec} — environment_plugin names a "
            f"registered plugin and environment_spec is a path. Got: {v!r}")

    @model_validator(mode="after")
    def _resolve_attacker_plugin_spec(self):
        """Resolve attacker_plugin + attacker_spec into the validated plugin instance in `self.attacker`."""
        if self.attacker is not None:
            raise ValueError("select the attacker with attacker_plugin (+ attacker_spec), not an "
                             "embedded 'attacker' block ('attacker' is a derived field).")
        if not self.attacker_plugin:
            raise ValueError("an experiment requires attacker_plugin: the attacker is selected by a "
                             "plugin name plus its spec (attacker_spec, an inline dict or a file path).")
        from ..attacker.plugins.base import AttackerPlugin
        self.attacker = _resolve_plugin(AttackerPlugin, self.attacker_plugin, self.attacker_spec)
        return self


def _json_default(o):
    if isinstance(o, datetime):
        return o.timestamp()
    if isinstance(o, BaseModel):
        return o.model_dump(mode="json")
    return str(o)


_CONFIG_KEYS = {
    "experiment": ("name", "trial", "teardown", "priority"),
    "environment": ("config", "spec"),
    "attacker": ("config", "plugin", "spec_path"),
    "defender": ("config",),
}


class _Field:
    """Descriptor proxying a flat attribute onto `metadata[group][key]`."""

    def __init__(self, group: str, key: str) -> None:
        self._group, self._key = group, key

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return obj.metadata[self._group][self._key]

    def __set__(self, obj, value) -> None:
        obj.metadata[self._group][self._key] = value


class Experiment:
    """One experiment. All state lives in `self.metadata`, grouped by concern, with flat descriptor accessors."""

    experiment_name = _Field("experiment", "name")
    trial = _Field("experiment", "trial")
    status = _Field("experiment", "status")
    error = _Field("experiment", "error")
    retry_count = _Field("experiment", "retry_count")
    base_name = _Field("experiment", "base_name")
    teardown = _Field("experiment", "teardown")
    priority = _Field("experiment", "priority")
    created_at = _Field("experiment", "created_at")
    updated_at = _Field("experiment", "updated_at")
    environment_config = _Field("environment", "config")
    environment_spec = _Field("environment", "spec")
    deployed_environment = _Field("environment", "deployed")
    vcpus_reserved = _Field("environment", "vcpus_reserved")
    ram_mb_reserved = _Field("environment", "ram_mb_reserved")
    disk_gb_reserved = _Field("environment", "disk_gb_reserved")
    vms_reserved = _Field("environment", "vms_reserved")
    environment_deploy_started_at = _Field("environment", "deploy_started_at")
    environment_deploy_finished_at = _Field("environment", "deploy_finished_at")
    teardown_started_at = _Field("environment", "teardown_started_at")
    teardown_finished_at = _Field("environment", "teardown_finished_at")
    environment_status = _Field("environment", "lifecycle_status")
    environment_last_command = _Field("environment", "last_command")
    attacker = _Field("attacker", "config")
    attacker_plugin = _Field("attacker", "plugin")
    attacker_spec = _Field("attacker", "spec_path")
    pid = _Field("attacker", "pid")
    attacker_started_at = _Field("attacker", "started_at")
    attacker_finished_at = _Field("attacker", "finished_at")
    attacker_status = _Field("attacker", "lifecycle_status")
    attacker_last_command = _Field("attacker", "last_command")
    attacker_setup_started_at = _Field("attacker", "setup_started_at")
    attacker_ready_at = _Field("attacker", "ready_at")
    attacker_stopping_at = _Field("attacker", "stopping_at")
    attacker_stopped_at = _Field("attacker", "stopped_at")
    defender = _Field("defender", "config")
    defender_pid = _Field("defender", "pid")
    defender_started_at = _Field("defender", "started_at")
    defender_finished_at = _Field("defender", "finished_at")
    defender_status = _Field("defender", "lifecycle_status")
    defender_setup_started_at = _Field("defender", "setup_started_at")
    defender_ready_at = _Field("defender", "ready_at")
    defender_stopping_at = _Field("defender", "stopping_at")
    defender_stopped_at = _Field("defender", "stopped_at")

    def __init__(self, experiment_name, status, environment, attacker=None, defender=None,
                 trial=0, teardown=True, created_at=None, updated_at=None, priority=0):
        created_at = created_at or datetime.now(timezone.utc)
        env_config = environment if isinstance(environment, EnvironmentConfig) else EnvironmentConfig.model_validate(environment)
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
                "config": attacker, "plugin": None, "spec_path": None, "pid": None,
                "started_at": None, "finished_at": None,
                "lifecycle_status": None, "last_command": None, "setup_started_at": None,
                "ready_at": None, "stopping_at": None, "stopped_at": None,
            },
            "defender": {
                "config": defender, "pid": None, "started_at": None, "finished_at": None,
                "lifecycle_status": None, "setup_started_at": None, "ready_at": None,
                "stopping_at": None, "stopped_at": None,
            },
        }

    @property
    def environment(self):
        """The executable environment plugin built from the stored EnvironmentConfig."""
        return build_environment(self.environment_config)

    def flat(self) -> dict:
        """The flat shape for the REST API."""
        return {name: getattr(self, name)
                for name, attr in vars(type(self)).items() if isinstance(attr, _Field)}

    def config_json(self, indent=2) -> str:
        """The immutable submission record: input config only, no runtime/timestamps."""
        d = {g: {k: self.metadata[g][k] for k in ks} for g, ks in _CONFIG_KEYS.items()}
        return json.dumps(d, indent=indent, default=_json_default)

    def result_json(self, indent=2) -> str:
        """The runtime record: status + all timestamps + reservations/pid/c2c/deployed."""
        d = {g: {k: v for k, v in grp.items() if k not in _CONFIG_KEYS.get(g, ())}
             for g, grp in self.metadata.items()}
        return json.dumps(d, indent=indent, default=_json_default)
