"""EnvironmentConfig — the environment section of an experiment submission.

Explicit shape (environment only; attacker/defender/traffic keep the embedded-selector idiom):

    environment:
      environment_plugin: mhbench          # which environment implementation
      environment_spec: equifax_small      # name/path of the env the plugin loads (always a file)

Back-compat: a bare env-name string ("equifax_small") coerces to
{environment_plugin: mhbench, environment_spec: "equifax_small"}, and the legacy embedded
{type: mhbench, spec: ...} dict is accepted too.
"""
from __future__ import annotations

from typing import Union

from pydantic import BaseModel, model_validator


class EnvironmentConfig(BaseModel):
    environment_plugin: str
    environment_spec: str  # name/path of the env the plugin loads (a file reference)

    @model_validator(mode="after")
    def _validate(self) -> "EnvironmentConfig":
        from .plugins.base import EnvironmentPlugin
        from . import plugins  # noqa: F401 — trigger plugin auto-discovery so the registry is populated

        if self.environment_plugin not in EnvironmentPlugin._registry:
            raise ValueError(
                f"Unknown environment_plugin {self.environment_plugin!r}. "
                f"Available: {list(EnvironmentPlugin._registry)}"
            )
        return self

    @classmethod
    def coerce(cls, value: Union["EnvironmentConfig", str, dict]) -> "EnvironmentConfig":
        """Accept the explicit shape, a bare env-name string, or a legacy {type, spec} dict."""
        if isinstance(value, EnvironmentConfig):
            return value
        if isinstance(value, str):
            return cls(environment_plugin="mhbench", environment_spec=value)
        if isinstance(value, dict):
            if "environment_plugin" in value:
                return cls(**value)
            if "type" in value:  # legacy embedded-selector {type: mhbench, spec: ...}
                return cls(environment_plugin=value["type"], environment_spec=value.get("spec"))
        raise ValueError(f"Cannot interpret environment config: {value!r}")

    @property
    def resolved_name(self) -> str:
        """The environment's name — the key the MHBench plugin deploys by (environments/<name>.json)."""
        return self.environment_spec
