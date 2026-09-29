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
    env_spec: AttackerEnvSpec,
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    prepared: PreparedAttacker,
    c2c_server: Optional[str] = None,
) -> asyncio.subprocess.Process:
    config_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "attacker_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    # The attacker consumes the attacker-facing env spec the environment produced (passed in by the
    # arena) — it never parses raw environment/topology internals.
    built = attacker.build_config(experiment_name, env_spec, c2c_server)
    # Target-side payloads (ExploitStruts, ssh/nc agent-spawn) make the VICTIM fetch the implant
    # from a C2 URL. Normally that's c2c_server, but under c2_on_kali c2c_server is a 127.0.0.1
    # ssh -L tunnel usable only by the strategy on beluga — victims must use the Kali in-tenant
    # URL (prepared.remote_url). Record it separately so low-level download actions use the
    # victim-reachable address without changing the strategy's own C2 API URL. Other backends:
    # agent_c2c == c2c_server, so their payloads are unchanged.
    agent_c2c = prepared.remote_url if (getattr(cfg, "c2_on_kali", False) and prepared.remote_url) else c2c_server
    if agent_c2c:
        built["agent_c2c_server"] = agent_c2c
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Starting attacker ({attacker.type}), config: {config_path}")
    process = await attacker.start(prepared, config_path, experiment_name, cfg, c2c_server, agent_c2c_url=agent_c2c)
    log(experiment_name, f"Attacker process started (pid={process.pid})")
    return process
