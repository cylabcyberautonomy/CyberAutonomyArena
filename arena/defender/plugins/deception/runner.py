#!/usr/bin/env python3
"""Subprocess entry point for the Deception defense plugin.

Receives a config JSON path as argv[1]. The JSON must contain:
  experiment_name, strategy, arsenal, deception_dir, management_ip, log_dir,
  and the arena-injected defender_env_spec (the env run spec Perry's Network is built from)
"""
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

# deception_dir is prepended to sys.path so its packages are importable
# regardless of where this script is invoked from.
_deception_dir = config.get("deception_dir", "")
if _deception_dir and _deception_dir not in sys.path:
    sys.path.insert(0, _deception_dir)

# The three defender runners are standalone scripts, not package modules, so the
# plugins/ directory (which holds the shared perry_network builder) has to go on
# sys.path explicitly - the same way deception_dir does above.
_plugins_dir = str(Path(__file__).resolve().parent.parent)
if _plugins_dir not in sys.path:
    sys.path.insert(0, _plugins_dir)

from perry_network import build_network_from_spec

from elasticsearch import Elasticsearch
from config.config import Config
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
from defender.telemetry.SimpleTelemetryAnalysis import SimpleTelemetryAnalysis
from defender.telemetry.ReactiveCredentials import ReactiveCredentials
from defender.telemetry.telemetry_service import TelemetryService
from defender.strategy import (
    DoNothing,
    StaticStandalone,
    StaticLayered,
    ReactiveLayered,
    ReactiveStandalone,
    NaiveDecoyCredential,
    NaiveDecoyHost,
)
try:  # HoneyShell exists only on newer Defense branches; optional so this runner loads without it.
    from defender.strategy import HoneyShell
except ImportError:
    HoneyShell = None

STRATEGY_MAP = {
    "DoNothing": DoNothing,
    "StaticStandalone": StaticStandalone,
    "StaticLayered": StaticLayered,
    "ReactiveLayered": ReactiveLayered,
    "ReactiveStandalone": ReactiveStandalone,
    "NaiveDecoyCredential": NaiveDecoyCredential,
    "NaiveDecoyHost": NaiveDecoyHost,
}
if HoneyShell is not None:
    STRATEGY_MAP["HoneyShell"] = HoneyShell

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

# The defender reads its OWN per-experiment Elasticsearch on the defender box, over the ssh -L tunnel the
# plugin opened in prepare_box_es (es_url = http://127.0.0.1:<port>, plain "falco"/"sysflow" indices).
# No shared harness ES. The env relay already ships sensors to the box (victim -> relay -> box:9200), so
# this runner does NO sysflow-repoint. Plain HTTP, security disabled (https raised WRONG_VERSION_NUMBER).
# No cloud handle: the defender holds NO cloud credential (the environment touches the cloud on its
# behalf). Backend choice is entirely the environment's concern now.
management_ip = config["management_ip"]
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
# topology: the env has already resolved the Neutron network/sg names + per-host users + which hosts run
# sysflow. No topology parse here — the defender is backend-agnostic (see plugins/perry_network.py).
network, telemetry_hosts = build_network_from_spec(config.get("defender_env_spec"))

strategy_cls = STRATEGY_MAP.get(config["strategy"])
if strategy_cls is None:
    print(
        f"[{experiment_name}] Unknown strategy: {config['strategy']!r}. "
        f"Available: {list(STRATEGY_MAP)}",
        flush=True,
    )
    sys.exit(1)

arsenal = CountArsenal(config.get("arsenal", {}))

# The analysis has to emit the event types the chosen strategy actually
# subscribes to, or the strategy's handlers are dead code. ReactiveLayered and
# ReactiveStandalone subscribe to DecoyCredentialUsed / DecoyHostInteraction /
# SSHEvent, and ReactiveCredentials is the only analysis that emits
# DecoyCredentialUsed - it spots a decoy username in an ssh command line, which
# is exactly the honey-credential trail AddHoneyCredentials plants. Pairing them
# with SimpleTelemetryAnalysis (which emits DecoyHostInteraction only, from two
# narrow netcat/curl network rules) left the honey-credential half of the
# arsenal undetectable no matter what the attacker did with it. The Falco
# analyses are deliberately NOT candidates here: they emit SuspiciousHost /
# FalcoEvent, which only the llm_soc-style strategies (FalcoLLM,
# falco_llm_c2_block, dynamic_prompt_injection) subscribe to.
_ANALYSIS_MAP = {
    "ReactiveLayered": ReactiveCredentials,
    "ReactiveStandalone": ReactiveCredentials,
}
analysis_cls = _ANALYSIS_MAP.get(config["strategy"], SimpleTelemetryAnalysis)
print(f"[{experiment_name}] Telemetry analysis: {analysis_cls.__name__}", flush=True)
telemetry_analysis = analysis_cls(
    es_conn, network, falco_index, sysflow_index
)
telemetry_service = TelemetryService(telemetry_analysis)
# BOX-ONLY EXECUTION — the single, enforced path. No cloud credential, no arena victim access: decoy
# VM-create goes to the environment (UDS), the decoy's sensor setup + honey-cred/fake-data host actions go
# to the box agent, which runs them from INSIDE the environment. No legacy arena-execution orchestrator.
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
    # Force immediate exit. Clearing the flag isn't enough: the reactive defender's
    # run loop blocks inside a C call in defender.run() (telemetry/ES poll), so
    # _running is only re-checked once run() returns — leaving the process alive after
    # SIGTERM and wedging the whole experiment at Running until it is SIGKILLed (seen
    # live on the o46 reactive-layered runs, which sat Running for 90+ min after the
    # attacker finished). SIGTERM only ever means "the harness is tearing you down".
    global _running
    _running = False
    os._exit(0)


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

# [REACTIVE-REAP FIX] Ported from prompt_injection/runner.py (commit 5e06fd4): the
# _shutdown handler above only runs when the main thread executes Python bytecode, but
# the run loop blocks inside a C call in defender.run(), so on SIGTERM the Python handler
# is DEFERRED and never fires — which is exactly why the deception (reactive) runs never
# terminated and held VMs at the cap (the prompt_injection runner had this watchdog; the
# deception runner never got it). set_wakeup_fd writes the signal number to a pipe from
# the C-level signal trampoline the instant a signal arrives (no Python handler/GIL
# needed); this daemon watchdog — runnable because the blocked main thread's I/O releases
# the GIL — then hard-exits ~1ms after SIGTERM.
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

# Box mode: the environment owns sensor shipping (sf-processor -> relay -> box:9200), so the defender
# does NOT repoint sysflow. Telemetry is already flowing to the box ES this runner reads over the tunnel.
if telemetry_hosts:
    print(f"[{experiment_name}] Box mode: telemetry ships to the defender box via the env relay; "
          f"skipping sysflow-repoint.", flush=True)

# mode is argv[2]: "prepare" (external arming only, then exit) or "run" (the reactive loop). The arena
# runs a "prepare" pass first (DefenderPlugin.prepare -> _run_prepare_and_wait) so the slow decoy deploy
# COMPLETES before the attacker starts, then a "run" pass (DefenderPlugin.run). See base.PreparedDefender.
mode = sys.argv[2] if len(sys.argv) > 2 else "run"

if mode == "prepare":
    # EXTERNAL arming ONLY. For a static/naive strategy (Perry Strategy.ARMS_IN_SETUP) this deploys the
    # decoys + plants honey-creds/fake data and exits; for a reactive strategy it is a no-op (it arms in
    # its loop). Write the PreparedDefender baton the arena reads back, then exit so the arming is COMPLETE
    # (and any failure is a non-zero exit the arena raises on) before the attacker is released.
    print(f"[{experiment_name}] Defender preparing (strategy={config['strategy']})", flush=True)
    defender.prepare()
    (log_dir / "defender_prepared.json").write_text(
        json.dumps({"armed_in_setup": bool(defender.strategy.ARMS_IN_SETUP)}))
    print(f"[{experiment_name}] Defender prepared "
          f"(armed_in_setup={defender.strategy.ARMS_IN_SETUP})", flush=True)
    sys.exit(0)

print(f"[{experiment_name}] Defender starting (strategy={config['strategy']})", flush=True)
# prepared=True: the arena already ran prepare() (external arming for ARMS_IN_SETUP strategies), so
# start() does NOT re-deploy those; a reactive/in-process strategy still does its full arming here.
defender.start(prepared=True)

# Signal the harness that this strategy is armed. For a reactive strategy its decoy/cred deploy +
# subscriptions happened here in start(); for a static strategy they happened in the prepare pass and
# start() only began monitoring. Either way the marker means "armed" and gates the attacker (see
# DefenderPlugin.wait_until_ready). Written after start() returns, in the harness's own log_dir.
(log_dir / "defender_ready").write_text(str(time.time()))
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
