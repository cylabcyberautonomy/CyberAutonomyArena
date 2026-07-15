import asyncio
import json
from typing import Any, Optional

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from ..environment import DeployedEnvironment
from .plugins.base import AttackerPlugin
from ..experiment_log import log, output_root
from . import plugins  # noqa: F401 — triggers auto-discovery


class AttackerConfig:
    """Dynamic type — validated against whichever plugins are registered."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any):
        def validate(value: Any) -> BaseModel:
            if isinstance(value, BaseModel):
                return value
            if isinstance(value, dict):
                type_key = value.get("type")
                attacker_cls = AttackerPlugin._registry.get(type_key)
                if attacker_cls is None:
                    raise ValueError(
                        f"Unknown attacker type: {type_key!r}. "
                        f"Available: {list(AttackerPlugin._registry)}"
                    )
                return attacker_cls.model_validate(value)
            raise ValueError(f"Expected dict or attacker config, got {type(value)}")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.model_dump(),
                info_arg=False,
            ),
        )


async def run_attacker(
    attacker: AttackerConfig,
    environment: Optional[DeployedEnvironment],
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    c2c_server: Optional[str] = None,
) -> asyncio.subprocess.Process:
    config_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    built = attacker.build_config(experiment_name, environment, c2c_server)
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Starting attacker ({attacker.type}), config: {config_path}")
    process = await attacker.run(config_path, experiment_name, cfg, c2c_server)
    log(experiment_name, f"Attacker process started (pid={process.pid})")
    return process
