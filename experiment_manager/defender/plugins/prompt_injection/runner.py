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

# The three defender runners are standalone scripts, not package modules, so the
# plugins/ directory (which holds the shared topology builder) has to go on
# sys.path explicitly - the same way deception_dir does above.
_plugins_dir = str(Path(__file__).resolve().parent.parent)
if _plugins_dir not in sys.path:
    sys.path.insert(0, _plugins_dir)

from topology import build_network, host_users, telemetry_host_ips

import openstack
from elasticsearch import Elasticsearch
from config.config import Config
from ansible.AnsibleRunner import AnsibleRunner
from environment.network import Network, Subnet, Host
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
# AIAttackerDetection subscribes to FalcoEvent/SuspiciousHost, which only the
# Falco-backed analyzers emit (SimpleTelemetryAnalysis never does - it only
# emits DecoyHostInteraction, for the Deception plugin's reactive strategies).
# Matches Perry's own scenarios/experiments/hotnets/ai_attacker_detection.py pairing.
from defender.telemetry import FalcoBasicAnalysis
from defender.telemetry.telemetry_service import TelemetryService
from defender.orchestrator.OpenstackOrchestrator import OpenstackOrchestrator
from defender.strategy import (
    AIAttackerDetection,
    StaticLayeredHostName,
    StaticLayeredUserName,
    StaticLayeredFileName,
    StaticLayeredFileContent,
    StaticLayeredAll,
)

STRATEGY_MAP = {
    "AIAttackerDetection": AIAttackerDetection,
    "StaticLayeredHostName": StaticLayeredHostName,
    "StaticLayeredUserName": StaticLayeredUserName,
    "StaticLayeredFileName": StaticLayeredFileName,
    "StaticLayeredFileContent": StaticLayeredFileContent,
    "StaticLayeredAll": StaticLayeredAll,
}

# Only AIAttackerDetection consumes telemetry (it subscribes to FalcoEvent /
# SuspiciousHost and deploys decoys in response). The StaticLayered* variants do
# all their work in initialize() and subscribe to nothing, so installing Falco
# for them is pure cost: several minutes of arming time and a large failure
# surface (apt on freshly booted hosts) in exchange for events nobody reads.
_NEEDS_FALCO = {"AIAttackerDetection"}
from ansible.defender.falco.install_falco import InstallFalco

experiment_name = config["experiment_name"]
strategy_name = config.get("strategy", "AIAttackerDetection")
strategy_cls = STRATEGY_MAP.get(strategy_name)
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {strategy_name!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)
log_dir = Path(config["log_dir"])
log_dir.mkdir(parents=True, exist_ok=True)

PerryLogger.setup_logger(str(log_dir))
action_logger = setup_action_logger(str(log_dir))

perry_config_data = json.loads((Path(config["deception_dir"]) / "config" / "config.json").read_text())
perry_cfg = Config(**perry_config_data)

openstack_conn = openstack.connect()
management_ip = config["management_ip"]
# http, not https, and no api_key: this is the harness's own Elasticsearch
# container (see the deception plugin's setup.py), which runs plain HTTP with
# xpack.security.enabled=false. Connecting with https raised
# "TlsError: WRONG_VERSION_NUMBER" on the very first indices.exists() call in
# TelemetryAnalysis.__init__, killing this runner before it ever armed.
es_url = f"http://{management_ip}:{perry_cfg.elastic_config.port}"
es_conn = Elasticsearch(es_url)

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


topology_spec = config.get("topology_spec")
network = None
if topology_spec:
    topology_data = json.loads(Path(topology_spec).read_text())
    network = build_network(topology_data["networks"][0], experiment_name, topology_data.get("subnet_connections"))

if network is not None and strategy_name in _NEEDS_FALCO:
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

print(f"[{experiment_name}] Defender starting (strategy={strategy_name})", flush=True)
defender.start()

# Signal the harness that this strategy is fully armed (initialize() has
# deployed its decoys and planted its credentials/fake data). main.py blocks on
# this file before starting the attacker - see DefenderPlugin.wait_until_ready.
# Written after start() returns, so it means "armed", not merely "process
# alive"; the harness's own log_dir is used so no extra config key is needed.
(log_dir / "defender_ready").write_text(str(time.time()))
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
