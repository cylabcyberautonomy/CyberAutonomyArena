"""EnvironmentConfig — the environment section of an experiment submission."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, model_validator


class EnvironmentConfig(BaseModel):
    environment_plugin: str
    environment_spec: str

    @model_validator(mode="after")
    def _validate(self) -> "EnvironmentConfig":
        from .plugins.base import EnvironmentPlugin
        from . import plugins  # noqa: F401

        if self.environment_plugin not in EnvironmentPlugin._registry:
            raise ValueError(
                f"Unknown environment_plugin {self.environment_plugin!r}. "
                f"Available: {list(EnvironmentPlugin._registry)}"
            )
        return self

    @property
    def resolved_name(self) -> str:
        """The topology PATH the internal readers key off (experiment.environment_spec)."""
        return self.environment_spec


class DeployedEnvironment(BaseModel):
    """The provisioning result the environment hands back after provision()."""
    topology_spec: str
    ip: Optional[str] = None
    spec: Optional[str] = None
    project_name: Optional[str] = None


def build_environment(value):
    """Build the EnvironmentPlugin from an EnvironmentConfig, its explicit dict, or a built plugin."""
    from .plugins.base import EnvironmentPlugin
    from . import plugins  # noqa: F401

    if isinstance(value, EnvironmentPlugin):
        return value
    cfg = value if isinstance(value, EnvironmentConfig) else EnvironmentConfig.model_validate(value)
    plugin_cls = EnvironmentPlugin._registry.get(cfg.environment_plugin)
    if plugin_cls is None:
        raise ValueError(
            f"Unknown environment_plugin {cfg.environment_plugin!r}. "
            f"Available: {list(EnvironmentPlugin._registry)}"
        )
    return plugin_cls(type=cfg.environment_plugin, environment_spec=cfg.environment_spec)
