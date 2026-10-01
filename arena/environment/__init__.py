from .models import DeployedEnvironment
from .lifecycle import EnvironmentLifecycle, EnvironmentSignal, EnvironmentCommand


def build_environment(value):
    """Build the executable EnvironmentPlugin from an EnvironmentConfig, its explicit
    {environment_plugin, environment_spec} dict, or an already-built plugin. Kept lazy (imports inside
    the function) so importing this package never eagerly pulls in the plugins (which import
    deployer/capacity) — avoids import cycles at load."""
    from .plugins.base import EnvironmentPlugin
    from . import plugins  # noqa: F401 — triggers plugin auto-discovery
    from .environment import EnvironmentConfig

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


__all__ = ["DeployedEnvironment", "EnvironmentLifecycle", "EnvironmentSignal",
           "EnvironmentCommand", "build_environment"]
