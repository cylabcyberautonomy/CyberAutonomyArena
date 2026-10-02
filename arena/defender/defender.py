import asyncio
import json
from typing import Any, Optional

from pydantic import BaseModel
from pydantic_core import core_schema

from ..config import ExperimentManagerConfig
from ..environment import DeployedEnvironment
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
    environment: Optional[DeployedEnvironment],
    experiment_name: str,
    cfg: ExperimentManagerConfig,
    bastion_ip: Optional[str] = None,
    defender_env_spec=None,
    defender_access=None,
    env_action_socket: Optional[str] = None,
    env_action_token: Optional[str] = None,
) -> asyncio.subprocess.Process:
    config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    await defender.setup(experiment_name, environment, cfg, bastion_ip,
                         defender_env_spec=defender_env_spec, defender_access=defender_access)
    built = defender.build_config(experiment_name, environment)
    type(defender).validate_built_config(built)  # fail fast if the config drifts from the runner contract (pre-injection)
    # Agent-facing DefenderEnvSpec (host inventory, no creds) + harness-only SetupAccess (key + bastion
    # routing per victim), both produced by the environment plugin. A migrated defender reads these
    # instead of computing its own SSH key / parsing the topology.
    if defender_env_spec is not None:
        built["defender_env_spec"] = defender_env_spec.model_dump()
    built["defender_setup_access"] = [a.model_dump() for a in (defender_access or [])]
    # The Defense/Perry defenders (llm_soc/deception/prompt_injection) each name their own code path now;
    # inject the running plugin's dir under the stable runner key "deception_dir". A self-contained defender
    # (canary) or one with its own path (velociraptor) declares no code_dir_field, so it gets nothing here.
    if type(defender).code_dir_field:
        built["deception_dir"] = str(cfg.plugin_dir(type(defender).code_dir_field))
    # "management_ip" is the harness's own fixed host (cfg.arena_host_ip), NOT an Elasticsearch address — every
    # defender reads its OWN per-experiment ES on the defender box (see DefenderPlugin.prepare_box_es).
    # It is kept only so a defender's self-protection knows not to block the harness/manager host. It is
    # NOT `bastion_ip`/`bastion_ip` below, which is this experiment's own ephemeral bastion floating IP —
    # Perry's AnsibleRunner needs THAT one to SSH-ProxyCommand into the experiment's internal 192.168.x.x
    # hosts (ssh -W %h:%p ... root@<bastion>).
    built["management_ip"] = cfg.arena_host_ip
    built["bastion_ip"] = bastion_ip
    built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
    # Dynamic topology-mutation channel: the defender's RemoteEnvOrchestrator POSTs EnvActionRequest
    # events to this UDS with this per-experiment token (see env_action_server.py). Injected ONLY into the
    # defender config — the attacker config never carries it (nor any management address). Absent when the
    # defender declared no VM budget (the window is never armed), so a non-mutating defender gets nothing.
    if env_action_socket is not None and env_action_token is not None:
        built["env_action_socket"] = env_action_socket
        built["env_action_token"] = env_action_token
        built["experiment_name"] = experiment_name  # the orchestrator stamps it into each request payload
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Preparing defender ({defender.type}), config: {config_path}")
    # EXTERNAL arming phase, symmetric with the attacker's setup(): stand up the box ES and run any
    # arming that completes before the scenario (decoy / honey-cred deploy for a strategy that arms in
    # setup). This BLOCKS and raises on failure, so the slow, failure-prone arming finishes — and fails
    # the experiment — before the attacker starts, instead of racing inside the run loop. run() below
    # then only launches the reactive loop.
    prepared = await defender.prepare(config_path, experiment_name, cfg)
    log(experiment_name,
        f"Defender prepared (armed_in_setup={prepared.armed_in_setup}); starting run loop")
    process = await defender.run(config_path, experiment_name, cfg)
    log(experiment_name, f"Defender process started (pid={process.pid})")
    return process
