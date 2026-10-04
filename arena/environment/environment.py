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

from typing import Optional

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


class DeployedEnvironment(BaseModel):
    """The provisioning RESULT the environment hands back after provision() — distinct from
    EnvironmentConfig above (the submission input). Backend-neutral: topology_spec is the resolved
    identifier; ip/spec are MHBench-specific carryovers (the foothold address + the short env name)."""
    topology_spec: str
    ip: Optional[str] = None    # kali floating IP (the attacker foothold address)
    spec: Optional[str] = None  # environment name passed to Incalmo as "environment"
    project_name: Optional[str] = None  # the backend project/prefix for this deploy (MHBench --project-name);
    #                                     the env resolves "<project_name>-<subnet>" network/sg names from it.


def build_environment(value):
    """Build the executable EnvironmentPlugin from an EnvironmentConfig, its explicit
    {environment_plugin, environment_spec} dict, or an already-built plugin. Lazy imports inside (the
    plugins import deployer/capacity) avoid an import cycle at module load. The env analog of
    attacker.run_attacker / defender.run_setup living beside its config (re-exported from __init__)."""
    from .plugins.base import EnvironmentPlugin
    from . import plugins  # noqa: F401 — triggers plugin auto-discovery

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
