#!/usr/bin/env python3
"""Subprocess entry point for the LLM SOC defense plugin.

Runs one of Perry's LLM-SOC-analyst strategies (defender/strategy/llm/*.py): on a
Falco-flagged suspicious host, an LLM agent (SysFlowAgent) investigates by
iteratively querying that host's SysFlow telemetry in Elasticsearch, then reports
whether it believes the host is compromised and, if so, the attacker's C2 IP.
FalcoLLM restores the host on a confirmed verdict; FalcoLLMC2Block blocks the C2
IP instead of restoring.

Telemetry source: Falco alerts (see TELEMETRY_MAP below for which analyzer
pairs with which strategy). Since this defender needs Falco, it installs it
on every host itself as part of its own setup (see the InstallFalco call
below) rather than depending on the environment's provisioning having
already done it - most MHBench-provisioned environments never start Falco
even when it's baked into the image (only *_instrumented vm_types do), so
relying on that would leave the "falco" index empty.

Receives a config JSON path as argv[1]. The JSON must contain:
  experiment_name, strategy, llm_model, topology_spec,
  deception_dir, management_ip, log_dir
"""
import json
import signal
import sys
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

# deception_dir is prepended to sys.path so its packages are importable
# regardless of where this script is invoked from.
_deception_dir = config.get("deception_dir", "")
if _deception_dir and _deception_dir not in sys.path:
    sys.path.insert(0, _deception_dir)

import openstack
from elasticsearch import Elasticsearch
from config.config import Config
from ansible.AnsibleRunner import AnsibleRunner
from environment.network import Network, Subnet, Host
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
# Both strategies subscribe to SuspiciousHost, which only the Falco-backed
# analyzers emit (SimpleTelemetryAnalysis never does - it only emits
# DecoyHostInteraction, for the Deception plugin's reactive strategies).
# Pairing matches Perry's own scenarios/defenders/falco_llm.py: FalcoLLM ->
# FalcoBasicAnalysis (needs 5+ alerts before flagging), FalcoLLMC2Block ->
# FalcoAgressiveAnalysis (flags on the first alert - it only blocks an IP
# rather than restoring a whole host, so a false positive is cheaper).
from defender.telemetry import FalcoBasicAnalysis, FalcoAgressiveAnalysis
from defender.telemetry.telemetry_service import TelemetryService
from defender.orchestrator.OpenstackOrchestrator import OpenstackOrchestrator
from defender.strategy import FalcoLLM, FalcoLLMC2Block
from ansible.defender.falco.install_falco import InstallFalco

STRATEGY_MAP = {
    "FalcoLLM": FalcoLLM,
    "FalcoLLMC2Block": FalcoLLMC2Block,
}

TELEMETRY_MAP = {
    "FalcoLLM": FalcoBasicAnalysis,
    "FalcoLLMC2Block": FalcoAgressiveAnalysis,
}

experiment_name = config["experiment_name"]
log_dir = Path(config["log_dir"])
log_dir.mkdir(parents=True, exist_ok=True)

PerryLogger.setup_logger(str(log_dir))
action_logger = setup_action_logger(str(log_dir))

perry_config_data = json.loads((Path(config["deception_dir"]) / "config" / "config.json").read_text())
perry_cfg = Config(**perry_config_data)

openstack_conn = openstack.connect()
management_ip = config["management_ip"]
es_url = f"https://{management_ip}:{perry_cfg.elastic_config.port}"
es_conn = Elasticsearch(es_url, api_key=perry_cfg.elastic_config.api_key, verify_certs=False)

# bastion_ip is THIS experiment's own bastion floating IP (from MHBench
# provisioning) - not the same as management_ip above (the harness's own fixed
# address). AnsibleRunner needs the bastion specifically: its inventory's
# ProxyCommand SSHes through it (-W %h:%p ... root@<bastion>) to reach the
# experiment's internal 192.168.x.x hosts at all.
ansible_runner = AnsibleRunner(
    ssh_key_path=perry_cfg.openstack_config.ssh_key_path,
    management_ip=config["bastion_ip"],
    ansible_dir=str(Path(config["deception_dir"]) / "ansible"),
    log_path=str(log_dir),  # AnsibleRunner treats this as a directory and writes ansible_log.log inside it
)

def _build_network(network_data: dict, experiment_name: str) -> Network:
    """Network/Subnet/Host are plain classes here, not pydantic models (no
    .model_validate) - build them by hand from MHBench's topology JSON. `sec_group`
    isn't in that JSON (it's assigned at deploy time); MHBench names it
    "<experiment_name>-<subnet_name>_sg" (see NetworkTopology.sg_name /
    NetworkDeployer._n in MHBench's src/abstractions/network.py and
    src/deployment/network_deployer.py) - reproduce that here so decoy deployment
    (DeployDecoy) attaches new hosts to the subnet's real OpenStack security group."""
    subnets = [
        Subnet(
            name=subnet_data["name"],
            hosts=[Host(name=h["name"], ip=h["ip_address"]) for h in subnet_data["hosts"]],
            sec_group=f"{experiment_name}-{subnet_data['name']}_sg",
        )
        for subnet_data in network_data["subnets"]
    ]
    return Network(name=network_data["name"], subnets=subnets)


topology_spec = config.get("topology_spec")
network = None
if topology_spec:
    topology_data = json.loads(Path(topology_spec).read_text())
    network = _build_network(topology_data["networks"][0], experiment_name)

if network is not None:
    # es_url above already uses this experiment's actual management_ip rather
    # than whatever's baked into config/config.json on disk - keep InstallFalco
    # (which reads config.external_ip internally) consistent with that.
    perry_cfg.external_ip = management_ip
    print(f"[{experiment_name}] Installing Falco on all hosts...", flush=True)
    # install_falco.yml's tasks are creates:-guarded, so this is safe to run
    # even if Falco is already present (e.g. baked into a *_instrumented image).
    # Left uncaught deliberately: if Falco can't be installed, this defender
    # can never trigger, so failing fast here beats a silently-idle defender.
    ansible_runner.run_playbook(InstallFalco(network.get_all_host_ips(), perry_cfg))
    print(f"[{experiment_name}] Falco install complete.", flush=True)

strategy_cls = STRATEGY_MAP.get(config["strategy"])
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {config['strategy']!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = TELEMETRY_MAP[config["strategy"]](es_conn, network)
telemetry_service = TelemetryService(telemetry_analysis)
orchestrator = OpenstackOrchestrator(
    openstack_conn=openstack_conn,
    ansible_runner=ansible_runner,
    external_elasticsearch_server=es_url,
    elasticsearch_api_key=perry_cfg.elastic_config.api_key,
    config=perry_cfg,
    network=network,
    action_logger=action_logger,
)

strategy = strategy_cls(
    arsenal=arsenal,
    network=network,
    orchestrator=orchestrator,
    telemetry_service=telemetry_service,
    llm_model=config.get("llm_model"),
)

defender = Defender(
    arsenal=arsenal,
    strategy=strategy,
    telemetry_service=telemetry_service,
    orchestrator=orchestrator,
    network=network,
)

_running = True


def _shutdown(signum, frame):
    global _running
    _running = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

print(
    f"[{experiment_name}] Defender starting "
    f"(strategy={config['strategy']}, llm_model={config.get('llm_model')})",
    flush=True,
)
defender.start()
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
