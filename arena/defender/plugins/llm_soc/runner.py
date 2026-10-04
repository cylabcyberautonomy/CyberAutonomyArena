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
  experiment_name, strategy, llm_model, defender_env_spec (host inventory),
  management_ip, log_dir
"""
import json
import os
import signal
import sys
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

# The plugin's repo is already importable: the arena spawns this runner with cwd + PYTHONPATH set to it
# (see the plugin's run() / _run_deception_script), so there is no repo-path key in the config.

from elasticsearch import Elasticsearch
from config.config import Config
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

perry_config_data = json.loads((Path("config") / "config.json").read_text())  # cwd is the repo (arena sets it)
perry_cfg = Config(**perry_config_data)
# This run's Elasticsearch indices are scoped to this experiment
# (falco-<name> / sysflow-<name>). The ES on the harness host is shared and
# persistent across every concurrent run, and a falco/sysflow document has no
# experiment field - only a hostname and an IP, both of which repeat across
# topologies. Unscoped, a defender reads other runs' telemetry and acts on it:
# on 2026-09-15 the 2-host s45_soc_sbt_t0 reported 34 suspicious hosts
# (database0-23 among them) and restored its own host0 off the back of that.
perry_cfg.experiment_name = experiment_name

# No cloud handle: the defender holds NO cloud credential (it never touches the cloud API — the
# environment does, on its behalf, via the env action channel). The backend (OpenStack/GCP) is entirely
# the environment's concern now; the defender is backend-agnostic.
management_ip = config["management_ip"]
# The defender reads its OWN per-experiment Elasticsearch on the defender box, over the ssh -L tunnel
# the plugin opened in prepare_box_es (es_url = http://127.0.0.1:<port>, plain "falco"/"sysflow"
# indices). There is NO shared harness ES: es_url is always injected (prepare_box_es fails closed if
# the box is missing), and the env relay already ships sensors to the box (victim -> relay -> box:9200),
# so this runner does NO InstallFalco / sysflow-repoint. http, not https, no api_key: box ES runs plain
# HTTP with security disabled (https raised "TlsError: WRONG_VERSION_NUMBER" on the first query).
es_url = config["es_url"]
# request_timeout=30 (not the 10s default): this run's box ES is installed + started FRESH in
# prepare(), and its first indices.create() can take >10s while the single-node cluster finishes
# forming (the HTTP port answers a GET before the cluster is ready for index ops). The 10s default
# timed out a cold box ES during live validation; 30s clears the cold-start window.
es_conn = Elasticsearch(es_url, request_timeout=30)
falco_index = config.get("falco_index", "falco")
sysflow_index = config.get("sysflow_index", "sysflow")

# No harness-side AnsibleRunner / scoped victim key here any more: the defender does NOT reach victims
# from the arena. The box agent (deployed in prepare_box_agent) holds the scoped key and runs ansible
# from inside the environment; the controller only talks to the box agent + the env UDS channel.


# Build Perry's Network from the ENVIRONMENT-provided DefenderEnvSpec (agent-facing host inventory:
# {name, ip, role}, victims only — the attacker foothold and the defender box are excluded by the env,
# see deployer._iter_victims). No MHBench topology-JSON parsing: this defender is environment-agnostic.
# Everything every host in the spec is one the defender owns, so RestoreServer's defendable-host guard is
# exactly "is this IP in my estate". sec_group / management_sg are unused here (BlockIP needs only host
# IPs; RestoreServer rebuilds via the orchestrator's cloud handle) — decoy placement, which needs the
# Neutron names, is a decoy-defender concern (deception/prompt_injection), not this one.
spec_hosts = (config.get("defender_env_spec") or {}).get("hosts") or []
victims = [Host(name=h["name"], ip=h["ip"]) for h in spec_hosts if h.get("ip")]
network = Network(
    name=experiment_name,
    subnets=[Subnet(name=f"{experiment_name}-victims", hosts=victims, sec_group="", attacker=False)],
)

# The environment owns sensor shipping: victim falcosidekick + sf-processor ship to the mgmt-host relay,
# which forwards to the defender box (victim -> relay -> box:9200). So the defender does NOT install
# Falco or repoint sysflow — telemetry is already flowing to the box ES this runner reads over the tunnel.
print(f"[{experiment_name}] Box mode: telemetry ships to the defender box via the env relay; "
      f"skipping InstallFalco / sysflow-repoint. Estate: {len(victims)} host(s).", flush=True)

strategy_cls = STRATEGY_MAP.get(config["strategy"])
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {config['strategy']!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)

arsenal = CountArsenal(config.get("arsenal", {}))
telemetry_analysis = TELEMETRY_MAP[config["strategy"]](
    es_conn, network, falco_index, sysflow_index
)
telemetry_service = TelemetryService(telemetry_analysis)
# BOX-ONLY EXECUTION — the single, enforced execution path. The defender holds NO cloud credential and
# does NOT reach victims from the arena: it forwards infra actions to the arena environment (UDS) and host
# actions to the box agent, which runs them from INSIDE the environment. There is deliberately no legacy
# arena-execution orchestrator (OpenstackOrchestrator/GCPOrchestrator) any more — box execution is the only way.
from defender.orchestrator.RemoteEnvOrchestrator import RemoteEnvOrchestrator
orchestrator = RemoteEnvOrchestrator.from_config(
    config, experiment_name=experiment_name, network=network, action_logger=action_logger)

# No harness self-protection wrapper: a defender's actions have real consequences. If a strategy blocks
# an IP it shouldn't (e.g. its own bastion/mgmt), that is the defender's bug to avoid, not the harness's
# to silently paper over. Keeping the harness out of the defender's decisions is the invariant here.

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
# This runner is only ever launched in "run" mode (argv[2]=="run"): llm_soc's prepare() is an
# in-plugin box-ES stand-up (DefenderPlugin.prepare on the plugin), NOT the deception "prepare"-mode
# runner — llm_soc strategies have no external arming to run here. So there is deliberately no
# prepare-mode branch below (unlike the deception/prompt_injection runners).
#
# prepared=True: the arena ran the defender's prepare() phase (box ES stand-up; and for a
# strategy that arms in setup, its external decoy/cred deploy) before launching this loop.
# FalcoLLM/C2Block are ARMS_IN_SETUP=False, so start() still runs their in-process arming
# (subscribe to Falco telemetry) here; prepared=True only suppresses a re-run of external
# arming for the static strategies (not these), so it is safe + explicit for the contract.
defender.start(prepared=True)

# Signal the harness that this strategy is armed (for llm_soc, subscribed to telemetry).
# main.py blocks on this file before starting the attacker - see DefenderPlugin.wait_until_ready.
# Written after start() returns, so it means "armed", not merely "process alive"; the harness's
# own log_dir is used so no extra config key is needed.
(log_dir / "defender_ready").write_text(str(time.time()))
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
