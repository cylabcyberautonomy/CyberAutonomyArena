#!/usr/bin/env python3
"""Subprocess entry point for the Deception defense plugin.

Receives a config JSON path as argv[1]. The JSON must contain:
  experiment_name, strategy, arsenal, topology_spec,
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
from defender.telemetry.SimpleTelemetryAnalysis import SimpleTelemetryAnalysis
from defender.telemetry.telemetry_service import TelemetryService
from defender.orchestrator.OpenstackOrchestrator import OpenstackOrchestrator
from defender.strategy import (
    DoNothing,
    StaticStandalone,
    StaticLayered,
    ReactiveLayered,
    ReactiveStandalone,
    NaiveDecoyCredential,
    NaiveDecoyHost,
)

STRATEGY_MAP = {
    "DoNothing": DoNothing,
    "StaticStandalone": StaticStandalone,
    "StaticLayered": StaticLayered,
    "ReactiveLayered": ReactiveLayered,
    "ReactiveStandalone": ReactiveStandalone,
    "NaiveDecoyCredential": NaiveDecoyCredential,
    "NaiveDecoyHost": NaiveDecoyHost,
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

strategy_cls = STRATEGY_MAP.get(config["strategy"])
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {config['strategy']!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = SimpleTelemetryAnalysis(es_conn, network)
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

print(f"[{experiment_name}] Defender starting (strategy={config['strategy']})", flush=True)
defender.start()
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
