from .models import DeployedEnvironment
from .lifecycle import EnvironmentLifecycle, EnvironmentSignal


def build_environment(value):
    """Build an EnvironmentPlugin from a plugin instance, a {"type": ...} dict, or a bare
    environment-name string (→ mhbench). Triggers plugin auto-discovery on first call. Kept
    lazy (imports inside the function) so importing this package never eagerly pulls in the
    plugins, which import deployer/capacity (avoids import cycles at package load)."""
    from .plugins.base import EnvironmentPlugin
    from . import plugins  # noqa: F401 — triggers auto-discovery of EnvironmentPlugin subclasses

    if isinstance(value, EnvironmentPlugin):
        return value
    if isinstance(value, str):
        return EnvironmentPlugin._registry["mhbench"].model_validate({"type": "mhbench", "spec": value})
    if isinstance(value, dict):
        type_key = value.get("type", "mhbench")
        cls = EnvironmentPlugin._registry.get(type_key)
        if cls is None:
            raise ValueError(
                f"Unknown environment type: {type_key!r}. "
                f"Available: {list(EnvironmentPlugin._registry)}"
            )
        return cls.model_validate(value)
    raise ValueError(f"Expected str / dict / EnvironmentPlugin, got {type(value)}")


__all__ = ["DeployedEnvironment", "EnvironmentLifecycle", "EnvironmentSignal", "build_environment"]
