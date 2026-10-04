#!/usr/bin/env python3
"""Subprocess entry point for the Prompt Injection defense plugin.

Deploys decoy hosts and honey-credentials whose names/file contents are
themselves a prompt-injection payload aimed at an LLM-driven attacker, trying to
convince the attacker's own model that the exercise is complete.

Default strategy is StaticLayeredAll (defender/strategy/All.py): all four
injection channels - decoy hostname, honey username, planted file name, planted
file content - fired at once, everything deployed in initialize() before the
attacker starts, subscribing to no telemetry.

Its decoys are built from the same DeployDecoy call ReactiveLayered uses -
apacheVulnerability=False and, importantly, no honeySSHService, so it never
touches the deploy_honey_service.yml path that made AIAttackerDetection fatal.
Deployment is reliable as it stands: across 21 archived StaticLayeredAll runs
every decoy reached ACTIVE, every decoy got its fake data on the first pass, and
every honey credential was planted, with no defender traceback in any of them.

One known difference from ReactiveLayered, left alone deliberately: credential
PLACEMENT. ReactiveLayered uses Strategy._honeycred_deploy_hosts (entry segment
only); this strategy splits credentials evenly across all subnets, which in the
archived runs put 27 of 42 (64%) on hosts off the attacker's entry path. That
affects how often the payload is READ, not whether it deploys.

AIAttackerDetection (defender/strategy/dynamic_prompt_injection.py) remains
selectable: it is the *reactive* variant, waiting for a burst of Falco-flagged
activity before deploying. Only that strategy consumes telemetry, so only that
strategy triggers the Falco install below (see _NEEDS_FALCO); the static
variants get NoTelemetry and never touch Elasticsearch.

Receives a config JSON path as argv[1]. The JSON must contain:
  experiment_name, management_ip, log_dir,
  and the arena-injected defender_env_spec (the env run spec Perry's Network is built from)
"""
import json
import os
import signal
import threading
import sys
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

# The plugin's repo is already importable: the arena spawns this runner with cwd + PYTHONPATH set to it
# (see the plugin's run() / _run_deception_script), so there is no repo-path key in the config.

# This runner is a standalone script, not a package module, so its OWN directory (which holds this
# plugin's copy of the perry_network builder) goes on sys.path explicitly (the plugin repo itself is
# already importable via the arena-set PYTHONPATH).
_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

from perry_network import build_network_from_spec

from elasticsearch import Elasticsearch
from config.config import Config
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
# AIAttackerDetection subscribes to FalcoEvent/SuspiciousHost, which only the
# Falco-backed analyzers emit (SimpleTelemetryAnalysis never does - it only
# emits DecoyHostInteraction, for the Deception plugin's reactive strategies).
# Matches Perry's own scenarios/experiments/hotnets/ai_attacker_detection.py pairing.
from defender.telemetry import FalcoBasicAnalysis
from defender.telemetry.NoTelemetry import NoTelemetry
from defender.telemetry.telemetry_service import TelemetryService
# It only exists on the Defense repo's `gcp-backend` branch; the OpenStack batch runs
# `fix/parallel-decoy-deploy`, which lacks it, so a top-level import here crashed every
# OpenStack defender on startup (ModuleNotFoundError) — see runbook §7. The usage is
# already guarded by cloud_backend, so the import belongs there too.
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

experiment_name = config["experiment_name"]
strategy_name = config.get("strategy", "StaticLayeredAll")
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

# PERRY SEAM (cross-repo, not harness-side): same as llm_soc/runner.py — the only backend read left
# is choosing the concrete orchestrator + its cloud handle, both of which live in
# Defense-MHBench-compatible. Everything else here is backend-agnostic.
# No cloud handle: the defender holds NO cloud credential (the environment touches the cloud on its
# behalf). Backend choice is entirely the environment's concern now.
management_ip = config["management_ip"]
# The defender reads its OWN per-experiment Elasticsearch on the defender box, over the ssh -L tunnel the
# plugin opened in prepare_box_es (es_url = http://127.0.0.1:<port>, plain "falco"/"sysflow" indices).
# No shared harness ES. The env relay already ships sensors to the box (victim -> relay -> box:9200), so
# this runner does NO InstallFalco. Plain HTTP, security disabled (https raised WRONG_VERSION_NUMBER).
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


# Build Perry's Network from the ENVIRONMENT-produced run spec (defender_env_spec), not a backend
# topology: the env resolved the Neutron network/sg names + per-host users. Backend-agnostic defender
# (see this plugin's perry_network.py). telemetry_hosts is unused here (this runner never repoints sensors).
network, _telemetry_hosts = build_network_from_spec(config.get("defender_env_spec"))

if network is not None and strategy_name in _NEEDS_FALCO:
    # Box mode: the environment owns sensor shipping (falcosidekick -> relay -> box:9200), so the
    # defender does NOT install Falco. Telemetry is already flowing to the box ES this runner reads.
    print(f"[{experiment_name}] Box mode: telemetry ships to the defender box via the env relay; "
          f"skipping InstallFalco.", flush=True)

arsenal = CountArsenal(config.get("arsenal", {}))
# A static strategy subscribes to nothing, so polling Falco for it is not merely
# wasted work - it is a liability. FalcoBasicAnalysis parses every document it
# pulls with FalcoAlert(**doc), unguarded, inside the runner's `while _running`
# loop, and FalcoAlert requires a `tags` field that Falco's own internal
# notifications (source: "internal", e.g. "Falco internal: timeouts
# notification") do not carry. One such document raises ValidationError and takes
# the whole defender process down: that is what killed s45_pi_eqm_t0 16 minutes
# into a 19-minute run, for alerts no subscriber would have read anyway.
if strategy_name in _NEEDS_FALCO:
    telemetry_analysis = FalcoBasicAnalysis(
        es_conn, network, falco_index, sysflow_index
    )
else:
    telemetry_analysis = NoTelemetry(
        es_conn, network, falco_index, sysflow_index
    )
print(
    f"[{experiment_name}] Telemetry analysis: {type(telemetry_analysis).__name__}",
    flush=True,
)
telemetry_service = TelemetryService(telemetry_analysis)
# BOX-ONLY EXECUTION — the single, enforced path. No cloud credential, no arena victim access: the
# payload-named decoy VM-create goes to the environment (UDS), host actions to the box agent, which runs
# them from INSIDE the environment. No legacy arena-execution orchestrator.
from defender.orchestrator.RemoteEnvOrchestrator import RemoteEnvOrchestrator
orchestrator = RemoteEnvOrchestrator.from_config(
    config, experiment_name=experiment_name, network=network, action_logger=action_logger)

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
    # Force immediate exit. Just clearing the flag isn't enough: the loop can be
    # blocked inside defender.run() (a long poll/telemetry call), so _running is
    # only checked once run() returns — leaving the process alive after SIGTERM.
    # That hung the harness's (un-timed) defender_process.wait() and wedged the
    # whole run at Running until the defender was SIGKILL'd. SIGTERM here only ever
    # means "the harness is tearing you down", so exit right away.
    global _running
    _running = False
    os._exit(0)


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

# The _shutdown handler above only runs when the main thread is executing Python
# bytecode — but the run loop blocks inside a C call in defender.run(), so on
# SIGTERM the handler is DEFERRED and never fires (proven live: the defender
# ignored SIGTERM and had to be SIGKILLed, hanging the harness's teardown wait).
# set_wakeup_fd writes the signal number to a pipe from the C-level signal
# trampoline the instant a signal is delivered (no Python handler / GIL needed);
# this daemon watchdog — which runs because the blocked main thread's I/O releases
# the GIL — then hard-exits. Validated to reap a blocked process ~1ms after SIGTERM.
_wd_r, _wd_w = os.pipe()
os.set_blocking(_wd_w, False)
signal.set_wakeup_fd(_wd_w)

def _sigkill_watchdog():
    try:
        os.read(_wd_r, 1)  # blocks until the first signal (SIGTERM/SIGINT) arrives
    except Exception:
        pass
    os._exit(0)

threading.Thread(target=_sigkill_watchdog, daemon=True, name="sigkill-watchdog").start()

# mode is argv[2]: "prepare" (external arming only, then exit) or "run" (the reactive loop). The arena
# runs a "prepare" pass first (DefenderPlugin.prepare -> _run_prepare_and_wait) so any external arming
# COMPLETES before the attacker starts, then a "run" pass (DefenderPlugin.run). See base.PreparedDefender.
mode = sys.argv[2] if len(sys.argv) > 2 else "run"

if mode == "prepare":
    # EXTERNAL arming ONLY. The static StaticLayered* channels (Perry Strategy.ARMS_IN_SETUP) deploy their
    # decoys + plant payloads and exit; AIAttackerDetection is reactive, so for it this is a no-op (it arms
    # in its loop). Write the PreparedDefender baton the arena reads back, then exit so the arming is
    # COMPLETE (a failure is a non-zero exit the arena raises on) before the attacker is released.
    print(f"[{experiment_name}] Defender preparing (strategy={strategy_name})", flush=True)
    defender.prepare()
    (log_dir / "defender_prepared.json").write_text(
        json.dumps({}))  # empty baton; the arena reads it back as PreparedDefender
    print(f"[{experiment_name}] Defender prepared "
          f"(armed_in_setup={defender.strategy.ARMS_IN_SETUP})", flush=True)
    sys.exit(0)

print(f"[{experiment_name}] Defender starting (strategy={strategy_name})", flush=True)
# prepared=True: the arena already ran prepare() (external arming for ARMS_IN_SETUP strategies), so
# start() does NOT re-deploy those; AIAttackerDetection (reactive) still does its full arming here.
defender.start(prepared=True)

# Signal the harness that this strategy is armed. main.py blocks on this file before starting the
# attacker - see DefenderPlugin.wait_until_ready. Written after start() returns, so it means "armed",
# not merely "process alive"; the harness's own log_dir is used so no extra config key is needed.
(log_dir / "defender_ready").write_text(str(time.time()))
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
