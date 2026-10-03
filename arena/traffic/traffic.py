"""TrafficConfig — dynamic pydantic type validated against the registered
background-traffic plugins. Mirrors ``AttackerConfig`` / ``DefenderConfig``.

Also exposes ``run_traffic()`` — the injector symmetric with ``run_defender()``: it builds the plugin's
runner config, injects the environment-produced ``TrafficEnvSpec`` + ``SetupAccess`` on top, writes the
config file, and spawns the runner. (Unlike run_defender, it does NOT call setup()/prepare(): traffic's
heavy install is a separate pre-rotation arena step — see TrafficPlugin.setup — because its install noise
must be rotated away before the attack window; run_traffic is the post-rotation "start the generators".)
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from ..experiment_log import log, output_root
from .plugins.base import TrafficPlugin
from . import plugins  # noqa: F401 — triggers auto-discovery


async def run_traffic(
    traffic,
    environment,
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    bastion_ip: Optional[str] = None,
    traffic_env_spec=None,
    traffic_access=None,
) -> asyncio.subprocess.Process:
    """Build the traffic runner config (injecting the env-produced spec + scoped access) and spawn the
    runner. Symmetric with defender.run_defender."""
    config_path = output_root(experiment_name, cfg) / experiment_name / "traffic" / "traffic_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    built = traffic.build_config(experiment_name, environment)
    type(traffic).validate_built_config(built)  # fail fast if the config drifts from the runner contract
    # Agent-facing TrafficEnvSpec (victim inventory) + harness-only SetupAccess (scoped key + bastion
    # routing per victim), both produced by the environment plugin. The runner reads these instead of
    # computing its own SSH key / parsing the topology.
    if traffic_env_spec is not None:
        built["traffic_env_spec"] = traffic_env_spec.model_dump()
    built["traffic_setup_access"] = [a.model_dump() for a in (traffic_access or [])]
    built["management_ip"] = cfg.arena_host_ip   # the harness's own host (never a target)
    built["bastion_ip"] = bastion_ip
    built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "traffic")
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Preparing traffic ({traffic.type}), config: {config_path}")
    process = await traffic.run(config_path, experiment_name, cfg)
    log(experiment_name, f"Traffic runner started (pid={process.pid})")
    return process


class TrafficConfig:
    """Dynamic type — validated against whichever traffic plugins are registered."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any):
        def validate(value: Any) -> BaseModel:
            if isinstance(value, BaseModel):
                return value
            if isinstance(value, dict):
                type_key = value.get("type")
                traffic_cls = TrafficPlugin._registry.get(type_key)
                if traffic_cls is None:
                    raise ValueError(
                        f"Unknown traffic type: {type_key!r}. "
                        f"Available: {list(TrafficPlugin._registry)}"
                    )
                return traffic_cls.model_validate(value)
            raise ValueError(f"Expected dict or traffic config, got {type(value)}")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.model_dump(),
                info_arg=False,
            ),
        )
