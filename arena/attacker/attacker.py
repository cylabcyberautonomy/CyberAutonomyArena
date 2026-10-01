import asyncio
import json
from typing import Any, Optional

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from .plugins.base import AttackerPlugin, PreparedAttacker
from .env_spec import AttackerEnvSpec
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
    experiment,
    cfg: ExperimentManagerConfig,
    prepared: PreparedAttacker,
) -> asyncio.subprocess.Process:
    experiment_name = experiment.experiment_name
    env_spec = experiment._attacker_env_spec  # adversary-safe spec the arena attached (env-produced)
    config_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    # The attacker consumes the attacker-facing env spec + its OWN opaque setup handle (`prepared`).
    # The arena never inspects `prepared`: a C2 attacker reads its own C2 URLs off it inside
    # build_config()/run(); a shell agent ignores it. No C2 plumbing threads through the arena.
    built = attacker.build_config(experiment_name, env_spec, prepared)
    type(attacker).validate_built_config(built)  # fail fast if the config drifts from the runner contract
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Starting attacker ({attacker.type}), config: {config_path}")
    # run_start launches the process AND emits RUNNING (attacker-emitted; the arena waits for it).
    process = await attacker.run_start(experiment, prepared, config_path, cfg)
    log(experiment_name, f"Attacker process started (pid={process.pid})")
    return process
