"""Environment-backend configuration, read from config.yaml's `env_backend:` section and owned by the environment layer."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

import yaml
from pydantic import BaseModel

# config.yaml lives at the repo root. This file is arena/environment/config.py, so parents[2] is the root.
_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"

# Deprecated flat top-level forms, migrated into the env_backend section for back-compat.
_FLAT_BACKEND_FIELDS = ("cloud_backend", "os_cloud", "mhbench_config", "gcp_relay_ip", "gcp_flavor_cpu_cost")


class EnvBackendConfig(BaseModel):
    """Environment-backend (MHBench) settings: the deployment target."""
    cloud_backend: str = "openstack"          # "openstack" (default) or "gcp"
    os_cloud: str = "openstack"               # clouds.yaml cloud name for the OpenStack CLI/SDK
    mhbench_config: Optional[str] = None       # MHBench cli --config, relative to mhbench_dir
    gcp_relay_ip: str = "10.0.1.10"           # mgmt/bastion internal IP (telemetry relay + defender-box fallback)
    gcp_flavor_cpu_cost: Dict[str, int] = {}  # MHBench flavor -> GCP CPUS_ALL_REGIONS cost. Feeds max_active_cpus


def _resolve_config_path(path: Optional[Path] = None) -> Path:
    """Mirror ExperimentManagerConfig.load's resolution so the env-backend section reads from the same file."""
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
        data = {}  # missing/unreadable config.yaml falls back to defaults (openstack)
    eb = dict(data.get("env_backend") or {})
    for k in _FLAT_BACKEND_FIELDS:            # explicit env_backend wins over a stale flat field
        if k in data:
            eb.setdefault(k, data[k])
    return EnvBackendConfig(**eb)


def load_env_backend(path: Optional[Path] = None) -> EnvBackendConfig:
    """Load the env-backend settings from config.yaml's `env_backend:` section. A missing file yields defaults."""
    return _load(str(_resolve_config_path(path)))


def env_backend(cfg=None) -> EnvBackendConfig:
    """The env-backend settings for this run. Prefers an `EnvBackendConfig` attached to `cfg`, else config.yaml."""
    injected = getattr(cfg, "env_backend", None)
    if isinstance(injected, EnvBackendConfig):
        return injected
    return load_env_backend()
