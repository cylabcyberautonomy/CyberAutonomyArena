import asyncio
from typing import Any, Optional

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from .plugins.base import TrafficPlugin
from ..experiment_log import log, output_root
from . import plugins  # noqa: F401 — triggers auto-discovery


class TrafficConfig:
    """Dynamic type that pydantic validates against the registered plugins."""

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


async def run_traffic(
    traffic: TrafficConfig,
    experiment,
    cfg: ExperimentManagerConfig,
    prepared,
) -> Optional[asyncio.subprocess.Process]:
    experiment_name = experiment.experiment_name
    config_path = output_root(experiment_name, cfg) / experiment_name / "traffic" / "traffic_config.json"
    log(experiment_name, f"Starting traffic ({traffic.type}), config: {config_path}")
    process = await traffic.run_start(experiment, prepared, config_path, cfg)
    if process is not None:
        log(experiment_name, f"Traffic process started (pid={process.pid})")
    else:
        log(experiment_name, "Traffic running on the hosts (no harness-side process)")
    return process
