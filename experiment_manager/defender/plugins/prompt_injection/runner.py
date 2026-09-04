#!/usr/bin/env python3
"""Subprocess entry point for the Prompt Injection defense plugin.

Runs Perry's AIAttackerDetection strategy
(defender/strategy/dynamic_prompt_injection.py): watches for a burst of
Falco-flagged suspicious activity on a host and responds by deploying decoy
hosts and honey-credentials whose names/file contents are themselves a
prompt-injection payload aimed at an LLM-driven attacker, trying to convince
the attacker's own model that the exercise is complete.

Telemetry source: Falco alerts, via FalcoBasicAnalysis (5+ alerts on a host in
the analysis window before it's flagged SuspiciousHost). Since this defender
needs Falco, it installs it on every host itself as part of its own setup
(see the InstallFalco call below) rather than depending on the environment's
provisioning having already done it - most MHBench-provisioned environments
never start Falco even when it's baked into the image (only *_instrumented
vm_types do), so relying on that would leave the "falco" index empty.

Receives a config JSON path as argv[1]. The JSON must contain:
  experiment_name, topology_spec, deception_dir, management_ip, log_dir
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
from environment.network import Network
from utility.logging.logging import setup_logger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
# AIAttackerDetection subscribes to FalcoEvent/SuspiciousHost, which only the
# Falco-backed analyzers emit (SimpleTelemetryAnalysis never does - it only
# emits DecoyHostInteraction, for the Deception plugin's reactive strategies).
# Matches Perry's own scenarios/experiments/hotnets/ai_attacker_detection.py pairing.
from defender.telemetry import FalcoBasicAnalysis
from defender.telemetry.telemetry_service import TelemetryService
from defender.orchestrator.OpenstackOrchestrator import OpenstackOrchestrator
from defender.strategy import AIAttackerDetection
from ansible.defender.falco.install_falco import InstallFalco

experiment_name = config["experiment_name"]
log_dir = Path(config["log_dir"])
log_dir.mkdir(parents=True, exist_ok=True)

setup_logger(str(log_dir / "perry.log"))
action_logger = setup_action_logger(str(log_dir / "actions.log"))

perry_config_data = json.loads((Path(config["deception_dir"]) / "config" / "config.json").read_text())
perry_cfg = Config(**perry_config_data)

openstack_conn = openstack.connect()
management_ip = config["management_ip"]
es_url = f"https://{management_ip}:{perry_cfg.elastic_config.port}"
es_conn = Elasticsearch(es_url, api_key=perry_cfg.elastic_config.api_key, verify_certs=False)

ansible_runner = AnsibleRunner(
    ssh_key_path=perry_cfg.openstack_config.ssh_key_path,
    management_ip=management_ip,
    ansible_dir=str(Path(config["deception_dir"]) / "ansible"),
    log_path=str(log_dir / "ansible.log"),
)

topology_spec = config.get("topology_spec")
network = None
if topology_spec:
    topology_data = json.loads(Path(topology_spec).read_text())
    network = Network.model_validate(topology_data["networks"][0])

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

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = FalcoBasicAnalysis(es_conn, network)
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

strategy = AIAttackerDetection(
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

print(f"[{experiment_name}] Defender starting (strategy=AIAttackerDetection)", flush=True)
defender.start()
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
