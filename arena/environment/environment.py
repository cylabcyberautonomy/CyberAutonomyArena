"""EnvironmentConfig — the environment section of an experiment submission.

Explicit shape (environment only; attacker/defender/traffic keep the embedded-selector idiom),
consistent with the attacker's `attacker_plugin` + `attacker_spec`:

    environment:
      environment_plugin: mhbench                                          # which implementation
      environment_spec: environments/instrumented/equifax_small_instrumented.json  # PATH to a topology JSON

`environment_spec` is a PATH (absolute, or relative to mhbench_dir) — NOT a library name. The env
files live in subdirs (instrumented/, non-generated/, generated/), so a path points at the real file
regardless of layout.

Only this explicit shape is accepted: `environment_plugin` must name a registered plugin, and
`environment_spec` is the path. There is no bare-string or legacy `{type, spec}` coercion — an
unrecognized shape or an unknown plugin is an error.
"""
from __future__ import annotations

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

    @property
    def resolved_name(self) -> str:
        """The value the internal readers key off (experiment.environment_spec) — the topology PATH.
        The deployer resolves it via resolve_topology_path; the short label is its stem."""
        return self.environment_spec
