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
    mgmt_ip: Optional[str] = None,
    defender_env_spec=None,
    defender_access=None,
) -> asyncio.subprocess.Process:
    config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    await defender.setup(experiment_name, environment, cfg, mgmt_ip)
    built = defender.build_config(experiment_name, environment)
    # Agent-facing DefenderEnvSpec (host inventory, no creds) + harness-only SetupAccess (key + bastion
    # routing per victim), both produced by the environment plugin. A migrated defender reads these
    # instead of computing its own SSH key / parsing the topology.
    if defender_env_spec is not None:
        built["defender_env_spec"] = defender_env_spec.model_dump()
    built["defender_setup_access"] = [a.model_dump() for a in (defender_access or [])]
    built["deception_dir"] = str(cfg.deception_dir)
    # "management_ip" here is the harness's own fixed host (Elasticsearch's address -
    # see host_ip in config.yaml). Deliberately NOT the same thing as `mgmt_ip`/
    # `bastion_ip` below, which is this experiment's own ephemeral bastion floating
    # IP - Perry's AnsibleRunner needs THAT one to SSH-ProxyCommand into the
    # experiment's internal 192.168.x.x hosts at all (ssh -W %h:%p ... root@<bastion>).
    # These two got conflated under one "management_ip" name for a while, which
    # silently broke any AnsibleRunner.run_playbook() call (Falco install, decoy
    # deployment, ...) the moment it was actually exercised - passing the harness
    # host where the bastion IP belongs, since the harness host can't proxy into a
    # random experiment's private OpenStack subnet.
    built["management_ip"] = cfg.host_ip
    built["bastion_ip"] = mgmt_ip
    # GCP-only: the address GCP victims' falcosidekick ships Falco alerts to. On GCP the
    # victim egress firewall blocks the on-prem harness ES (management_ip/host_ip), so alerts
    # go to a socat relay on the management host (gcp_relay_ip:9200), which forwards them over
    # a reverse SSH tunnel to the harness ES. The runner uses this ONLY for perry_cfg.external_ip
    # (falcosidekick's target); the defender itself still reads ES directly at management_ip.
    # Absent on OpenStack, where victims reach host_ip directly.
    if getattr(cfg, "cloud_backend", "openstack") == "gcp":
        # getattr default so an already-running manager (config object predating the
        # gcp_relay_ip field) still resolves it without a restart; a restart picks up
        # any override from config.gcp.yaml.
        built["falco_relay_ip"] = getattr(cfg, "gcp_relay_ip", "10.0.1.10")
    built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
    config_path.write_text(json.dumps(built, indent=2))
    log(experiment_name, f"Starting defender ({defender.type}), config: {config_path}")
    process = await defender.run(config_path, experiment_name, cfg)
    log(experiment_name, f"Defender process started (pid={process.pid})")
    return process
