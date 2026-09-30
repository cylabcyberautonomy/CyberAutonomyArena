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
    defendable_host_ips,
    host_users,
    telemetry_host_ips,
)

import openstack
from elasticsearch import Elasticsearch
from config.config import Config
from ansible.AnsibleRunner import AnsibleRunner
from ansible.defender import ReconfigureSysFlow
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
# This run's Elasticsearch indices are scoped to this experiment
# (falco-<name> / sysflow-<name>). The ES on the harness host is shared and
# persistent across every concurrent run, and a falco/sysflow document has no
# experiment field - only a hostname and an IP, both of which repeat across
# topologies. Unscoped, a defender reads other runs' telemetry and acts on it:
# on 2026-09-15 the 2-host s45_soc_sbt_t0 reported 34 suspicious hosts
# (database0-23 among them) and restored its own host0 off the back of that.
perry_cfg.experiment_name = experiment_name

# cloud_backend comes from the deception repo's config/config.json (perry_cfg), exactly as
# prompt_injection/runner.py reads it. On GCP there is no OpenStack cloud to connect to, and
# the orchestrator below is swapped for GCPOrchestrator. Defaults to 'openstack' so the
# OpenStack path is byte-for-byte unchanged.
cloud_backend = getattr(perry_cfg, "cloud_backend", "openstack")
openstack_conn = openstack.connect() if cloud_backend != "gcp" else None
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

if network is not None:
    # es_url above already uses this experiment's actual management_ip rather
    # than whatever's baked into config/config.json on disk - keep InstallFalco
    # (which reads config.external_ip internally) consistent with that.
    #
    # external_ip is what falcosidekick ON THE VICTIMS ships Falco alerts to (InstallFalco
    # writes it into each host's /etc/falcosidekick/config.yaml hostport). On OpenStack that
    # is management_ip (the harness ES) directly. On GCP the victim egress firewall blocks the
    # on-prem harness ES, so ship to the management-host socat relay (falco_relay_ip:9200),
    # which forwards over a reverse SSH tunnel to the harness ES. The defender's OWN reads still
    # use es_url=management_ip above (it runs on the harness, which reaches ES directly).
    # config["falco_relay_ip"] is threaded by defender.py on GCP, but that runs in the
    # long-lived manager process; a manager that predates that edit won't have written it.
    # Since the runner is a fresh subprocess every run, default it here too so the fix takes
    # effect without a manager restart. MHB_FALCO_RELAY_IP overrides; 10.0.1.10 is the GCP
    # management host's internal IP on the victim-reachable management CIDR (where the socat
    # relay listens). OpenStack is untouched (victims reach management_ip directly).
    falco_relay_ip = config.get("falco_relay_ip") or os.environ.get("MHB_FALCO_RELAY_IP", "10.0.1.10")
    perry_cfg.external_ip = (
        falco_relay_ip if (cloud_backend == "gcp" and falco_relay_ip) else management_ip
    )
    print(f"[{experiment_name}] Installing Falco on all hosts...", flush=True)
    # install_falco.yml's tasks are creates:-guarded, so this is safe to run
    # even if Falco is already present (e.g. baked into a *_instrumented image).
    # Left uncaught deliberately: if Falco can't be installed, this defender
    # can never trigger, so failing fast here beats a silently-idle defender.
    # Not get_all_host_ips(): that includes the attacker's own box, which the
    # defender does not own and could never instrument. See
    # topology.defendable_host_ips.
    ansible_runner.run_playbook(
        InstallFalco(defendable_host_ips(topology_data["networks"][0]), perry_cfg)
    )
    print(f"[{experiment_name}] Falco install complete.", flush=True)

    # Both halves of this defender read Elasticsearch, and each half needs its
    # own telemetry stream pointed here:
    #
    #   detection - Falco, handled by InstallFalco above (its falcosidekick
    #   config task now notifies a restart handler, without which a baked host's
    #   already-running sidekick kept shipping to MHBench's own ES);
    #
    #   investigation - SysFlow. On a SuspiciousHost, FalcoLLM hands the host's
    #   IP to SysFlowAgent, which does five Elasticsearch queries against the
    #   "sysflow" index to decide whether that host is compromised. Real
    #   *_instrumented hosts boot with sysflow already running against the
    #   Elasticsearch baked into their image (MHBench's aux_files/
    #   pipeline.local.json -> http://10.81.1.25:9200), so that index held
    #   nothing for any host in this experiment and the agent would have been
    #   reasoning over an empty result set no matter how good the detection got.
    #   The deception plugin's runner already does exactly this before arming;
    #   this one never did.
    if telemetry_hosts:
        print(
            f"[{experiment_name}] Pointing sysflow on {len(telemetry_hosts)} host(s) "
            f"at {es_url}: {', '.join(telemetry_hosts)}",
            flush=True,
        )
        ansible_runner.run_playbook(ReconfigureSysFlow(telemetry_hosts, perry_cfg))
        print(f"[{experiment_name}] SysFlow reconfigure complete.", flush=True)

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
_PROTECTED_IPS = {ip for ip in (management_ip, config.get("bastion_ip"), config.get("falco_relay_ip")) if ip}

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = TELEMETRY_MAP[config["strategy"]](
    es_conn, network, perry_cfg.falco_index, perry_cfg.sysflow_index
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
orchestrator = _SelfProtectingOrchestrator(orchestrator, _PROTECTED_IPS)
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
