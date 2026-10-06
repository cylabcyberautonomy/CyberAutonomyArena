"""Environment-backend configuration — OWNED BY THE ENVIRONMENT LAYER.

The deployment-target settings (which cloud, the MHBench `--config`, the relay IP, the GCP flavor costs)
describe how the MHBench ENVIRONMENT plugin deploys. They are NOT arena behavior and NOT a defender concern
(the arena + defender are backend-neutral; the defender reads none of these), so they live here in the
environment layer rather than as fields of the arena's `ExperimentManagerConfig`.

They are read from the `env_backend:` section of the same `config.yaml` the arena loads (resolution mirrors
`ExperimentManagerConfig.load`: an explicit path, else `$EXPERIMENT_MANAGER_CONFIG`, else the default
`config.yaml`). The deprecated flat top-level forms (`cloud_backend:`/`os_cloud:`/… at the root) are still
accepted and migrated here for back-compat.

Readers call `env_backend(cfg)`: it prefers an `EnvBackendConfig` attached to `cfg` (a test / explicit
override) and otherwise loads from `config.yaml`. The arena core consumes only `os_cloud` (to set `OS_CLOUD`
for its OpenStack clean-slate + the MHBench subprocesses it spawns); everything else is read by the MHBench
plugin itself.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

import yaml
from pydantic import BaseModel

# config.yaml lives at the repo root; this file is arena/environment/config.py -> parents[2] is the root.
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"

# Deprecated flat top-level forms, migrated into the env_backend section for back-compat with older configs.
_FLAT_BACKEND_FIELDS = ("cloud_backend", "os_cloud", "mhbench_config", "gcp_relay_ip", "gcp_flavor_cpu_cost")


class EnvBackendConfig(BaseModel):
    """Environment-backend (MHBench) settings — the deployment target. Env-layer owned (see module docstring)."""
    cloud_backend: str = "openstack"          # "openstack" (default) or "gcp"
    os_cloud: str = "openstack"               # clouds.yaml cloud name for the OpenStack CLI/SDK
    mhbench_config: Optional[str] = None       # MHBench cli --config (relative to mhbench_dir), e.g. "config/config.gcp.yaml"
    gcp_relay_ip: str = "10.0.1.10"           # mgmt/bastion internal IP on the victim-reachable CIDR (telemetry relay + defender-box fallback). Named gcp_* for historical reasons.
    gcp_flavor_cpu_cost: Dict[str, int] = {}  # MHBench flavor -> GCP CPUS_ALL_REGIONS cost; feeds max_active_cpus


def _resolve_config_path(path: Optional[Path] = None) -> Path:
    """Mirror ExperimentManagerConfig.load's resolution so the env-backend section is read from the SAME file."""
    if path is not None:
        return Path(path)
    env = os.environ.get("EXPERIMENT_MANAGER_CONFIG")
    return Path(env) if env else _DEFAULT_CONFIG_PATH


@lru_cache(maxsize=None)
def _load(path_str: str) -> EnvBackendConfig:
    data: dict = {}
    try:
        loaded = yaml.safe_load(Path(path_str).read_text())
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, ValueError):
        data = {}  # missing/unreadable config.yaml -> defaults (openstack); the arena config load already
                   # fails loudly at startup if the file is truly required and absent.
    eb = dict(data.get("env_backend") or {})
    for k in _FLAT_BACKEND_FIELDS:            # explicit env_backend wins over a stale flat field
        if k in data:
            eb.setdefault(k, data[k])
    return EnvBackendConfig(**eb)


def load_env_backend(path: Optional[Path] = None) -> EnvBackendConfig:
    """Load the env-backend settings from config.yaml's `env_backend:` section (flat fields migrated).
    Cached per resolved path. A missing/unreadable file yields defaults."""
    return _load(str(_resolve_config_path(path)))


def env_backend(cfg=None) -> EnvBackendConfig:
    """The env-backend settings for this run. Prefers an `EnvBackendConfig` attached to `cfg` (tests /
    explicit override); otherwise loads from config.yaml. ExperimentManagerConfig no longer carries these."""
    injected = getattr(cfg, "env_backend", None)
    if isinstance(injected, EnvBackendConfig):
        return injected
    return load_env_backend()
