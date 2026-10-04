import asyncio
from typing import Any

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from .plugins.base import DefenderPlugin
from ..experiment_log import log, output_root
from . import plugins  # noqa: F401 — triggers auto-discovery


class DefenderConfig:
    """Dynamic type — validated against whichever plugins are registered."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any):
        def validate(value: Any) -> BaseModel:
            if isinstance(value, BaseModel):
                return value
            if isinstance(value, dict):
                type_key = value.get("type")
                defender_cls = DefenderPlugin._registry.get(type_key)
                if defender_cls is None:
                    raise ValueError(
                        f"Unknown defender type: {type_key!r}. "
                        f"Available: {list(DefenderPlugin._registry)}"
                    )
                return defender_cls.model_validate(value)
            raise ValueError(f"Expected dict or defender config, got {type(value)}")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.model_dump(),
                info_arg=False,
            ),
        )


async def run_defender(
    defender: DefenderConfig,
    experiment,
    cfg: ExperimentManagerConfig,
    prepared,
) -> asyncio.subprocess.Process:
    # RUN phase — just launch, the defender analog of run_attacker (and the same shape: compute the config
    # path, then delegate to the plugin's run_start wrapper). DefenderPlugin.run_setup() already did setup +
    # provision_box + build_config + write + prepare(arm), so the defender is fully armed and its config is
    # on disk; this only spawns the reactive loop. READY/RUNNING are emitted by the arena after
    # wait_until_ready (the readiness marker the runner writes once the loop is armed).
    experiment_name = experiment.experiment_name
    config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
    log(experiment_name, f"Starting defender ({defender.type}) run loop, config: {config_path}")
    process = await defender.run_start(experiment, prepared, config_path, cfg)
    log(experiment_name, f"Defender process started (pid={process.pid})")
    return process
