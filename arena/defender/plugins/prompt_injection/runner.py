#!/usr/bin/env python3
"""Subprocess entry point for the Prompt Injection defense plugin."""
import json
import os
import signal
import threading
import sys
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

_here = str(Path(__file__).resolve().parent)
if _here not in sys.path:
    sys.path.insert(0, _here)

from perry_network import build_network_from_spec

from elasticsearch import Elasticsearch
from config.config import Config
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
from defender.telemetry import FalcoBasicAnalysis
from defender.telemetry.NoTelemetry import NoTelemetry
from defender.telemetry.telemetry_service import TelemetryService
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

perry_config_data = json.loads((Path("config") / "config.json").read_text())
perry_cfg = Config(**perry_config_data)
perry_cfg.experiment_name = experiment_name

management_ip = config["management_ip"]
es_url = config["es_url"]
es_conn = Elasticsearch(es_url, request_timeout=30)
falco_index = config.get("falco_index", "falco")
sysflow_index = config.get("sysflow_index", "sysflow")

network, _telemetry_hosts = build_network_from_spec(config.get("defender_env_spec"))

if network is not None and strategy_name in _NEEDS_FALCO:
    print(f"[{experiment_name}] Box mode: telemetry ships to the defender box via the env relay; "
          f"skipping InstallFalco.", flush=True)

arsenal = CountArsenal(config.get("arsenal", {}))
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
    global _running
    _running = False
    os._exit(0)


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

_wd_r, _wd_w = os.pipe()
os.set_blocking(_wd_w, False)
signal.set_wakeup_fd(_wd_w)

def _sigkill_watchdog():
    try:
        os.read(_wd_r, 1)
    except Exception:
        pass
    os._exit(0)

threading.Thread(target=_sigkill_watchdog, daemon=True, name="sigkill-watchdog").start()

print(f"[{experiment_name}] Defender arming (strategy={strategy_name})", flush=True)
defender.start(prepared=False)

(log_dir / "defender_ready").write_text("armed\n")
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
