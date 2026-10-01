"""EnvironmentConfig — the environment section of an experiment submission.

Explicit shape (environment only; attacker/defender/traffic keep the embedded-selector idiom),
consistent with the attacker's `attacker_plugin` + `attacker_spec`:

    environment:
      environment_plugin: mhbench                                          # which implementation
      environment_spec: environments/instrumented/equifax_small_instrumented.json  # PATH to a topology JSON

`environment_spec` is a PATH (absolute, or relative to mhbench_dir) — NOT a library name. The env
files live in subdirs (instrumented/, non-generated/, generated/), so a path points at the real file
regardless of layout.

Back-compat: a bare path string coerces to {environment_plugin: mhbench, environment_spec: <path>},
and the legacy embedded {type: mhbench, spec: <path>} dict is accepted (its `spec` must now be a path).
"""
from __future__ import annotations

from typing import Union

from pydantic import BaseModel, model_validator


class EnvironmentConfig(BaseModel):
    environment_plugin: str
    environment_spec: str  # PATH to a topology JSON (absolute, or relative to mhbench_dir)

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
        """The value the internal readers key off (experiment.environment_spec) — the topology PATH.
        The deployer resolves it via resolve_topology_path; the short label is its stem."""
        return self.environment_spec
