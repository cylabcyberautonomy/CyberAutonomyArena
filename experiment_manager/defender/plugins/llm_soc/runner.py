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
import os
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

from topology import (
    build_network,
    host_users,
    telemetry_host_ips,
)

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
# This run's Elasticsearch indices are scoped to this experiment
# (falco-<name> / sysflow-<name>). The ES on the harness host is shared and
# persistent across every concurrent run, and a falco/sysflow document has no
# experiment field - only a hostname and an IP, both of which repeat across
# topologies. Unscoped, a defender reads other runs' telemetry and acts on it:
# on 2026-09-15 the 2-host s45_soc_sbt_t0 reported 34 suspicious hosts
# (database0-23 among them) and restored its own host0 off the back of that.
perry_cfg.experiment_name = experiment_name

# PERRY SEAM (cross-repo, not harness-side): the concrete orchestrator (OpenstackOrchestrator vs
# GCPOrchestrator) and its cloud handle live in Defense-MHBench-compatible, so selecting between them
# is the one place the runner still reads the backend. Everything else the defender does is now
# backend-agnostic (it reads its own box ES; the env owns sensor shipping). A future cross-repo change
# would have the environment hand the defender an orchestrator/backend handle, removing this read too.
# Defaults to 'openstack' so that path is byte-for-byte unchanged.
cloud_backend = getattr(perry_cfg, "cloud_backend", "openstack")
openstack_conn = openstack.connect() if cloud_backend != "gcp" else None
management_ip = config["management_ip"]
# The defender reads its OWN per-experiment Elasticsearch on the defender box, over the ssh -L tunnel
# the plugin opened in prepare_box_es (es_url = http://127.0.0.1:<port>, plain "falco"/"sysflow"
# indices). There is NO shared harness ES: es_url is always injected (prepare_box_es fails closed if
# the box is missing), and the env relay already ships sensors to the box (victim -> relay -> box:9200),
# so this runner does NO InstallFalco / sysflow-repoint. http, not https, no api_key: box ES runs plain
# HTTP with security disabled (https raised "TlsError: WRONG_VERSION_NUMBER" on the first query).
es_url = config["es_url"]
es_conn = Elasticsearch(es_url)
falco_index = config.get("falco_index", "falco")
sysflow_index = config.get("sysflow_index", "sysflow")

# bastion_ip is THIS experiment's own bastion floating IP (from MHBench
# provisioning) - not the same as management_ip above (the harness's own fixed
# address). AnsibleRunner needs the bastion specifically: its inventory's
# ProxyCommand SSHes through it (-W %h:%p ... root@<bastion>) to reach the
# experiment's internal 192.168.x.x hosts at all.
# SCOPED defender key from the harness-injected SetupAccess (defender_setup_access): the per-system
# key that works forward-only through the bastion and on the box+victims. Fail closed — never fall
# back to perry_cfg's management (god) key on disk, which would defeat the per-system key scoping.
# AnsibleRunner uses this key for BOTH its bastion `-W` jump and the victim hop, so the scoped key
# covers the whole chain (the forward-only jump creds make the bastion `-W` safe).
def _scoped_ssh_key(cfg_dict):
    for a in cfg_dict.get("defender_setup_access", []):
        if a.get("ssh_key"):
            return os.path.expanduser(a["ssh_key"])
    raise RuntimeError("no scoped ssh_key in defender_setup_access; refusing to use the management key")

ansible_runner = AnsibleRunner(
    ssh_key_path=_scoped_ssh_key(config),
    management_ip=config["bastion_ip"],
    ansible_dir=str(Path(config["deception_dir"]) / "ansible"),
    log_path=str(log_dir),  # AnsibleRunner treats this as a directory and writes ansible_log.log inside it
)


topology_spec = config.get("topology_spec")
network = None
telemetry_hosts: list[str] = []
if topology_spec:
    topology_data = json.loads(Path(topology_spec).read_text())
    network = build_network(topology_data["networks"][0], experiment_name, topology_data.get("subnet_connections"))
    # Hosts that actually run sysflow - the "*_instrumented" vm_types MHBench's
    # online registry attaches start_sysflow/start_defender_services to. The
    # Kali attacker has no telemetry stack, so it is excluded.
    telemetry_hosts = telemetry_host_ips(topology_data["networks"][0])

# The environment owns sensor shipping: victim falcosidekick + sf-processor ship to the mgmt-host relay,
# which forwards to the defender box (victim -> relay -> box:9200). So the defender does NOT install
# Falco or repoint sysflow — telemetry is already flowing to the box ES this runner reads over the tunnel.
if network is not None:
    print(f"[{experiment_name}] Box mode: telemetry ships to the defender box via the env relay; "
          f"skipping InstallFalco / sysflow-repoint.", flush=True)

strategy_cls = STRATEGY_MAP.get(config["strategy"])
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {config['strategy']!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)

# Self-protection: a defender must never block its OWN telemetry/management infrastructure (see
# self_protect.py). Defender-local invariant — no attacker knowledge needed; replaces the old
# MHB_C2_ON_KALI gate that coupled the defender to an attacker config flag.
from self_protect import SelfProtectingOrchestrator  # noqa: E402 — runner adds deception_dir dirs to path above
_PROTECTED_IPS = {ip for ip in (management_ip, config.get("bastion_ip")) if ip}

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = TELEMETRY_MAP[config["strategy"]](
    es_conn, network, falco_index, sysflow_index
)
telemetry_service = TelemetryService(telemetry_analysis)
if cloud_backend == "gcp":
    # GCPOrchestrator exists only on the Defense repo's gcp-backend branch; import it lazily
    # inside this branch so the OpenStack path never depends on it. It wires BlockIP via the
    # backend-agnostic ansible actuator (iptables over the bastion), needing no openstack_conn.
    from defender.orchestrator.GCPOrchestrator import GCPOrchestrator
    orchestrator = GCPOrchestrator(
        ansible_runner=ansible_runner,
        external_elasticsearch_server=es_url,
        elasticsearch_api_key=perry_cfg.elastic_config.api_key,
        config=perry_cfg,
        network=network,
        action_logger=action_logger,
    )
else:
    orchestrator = OpenstackOrchestrator(
        openstack_conn=openstack_conn,
        ansible_runner=ansible_runner,
        external_elasticsearch_server=es_url,
        elasticsearch_api_key=perry_cfg.elastic_config.api_key,
        config=perry_cfg,
        network=network,
        action_logger=action_logger,
    )

# Self-protection wrapper: any block aimed at the defender's own ES/mgmt IP is dropped, whatever the
# strategy or the attacker's C2 placement. Applied once here so both the strategy and the Defender
# (below) share the guarded orchestrator.
orchestrator = SelfProtectingOrchestrator(orchestrator, _PROTECTED_IPS)
print(f"[{experiment_name}] Self-protecting orchestrator active; protected IPs: {sorted(_PROTECTED_IPS)}", flush=True)

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
