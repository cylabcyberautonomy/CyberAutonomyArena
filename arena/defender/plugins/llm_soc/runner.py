#!/usr/bin/env python3
"""Subprocess entry point for the LLM SOC defense plugin."""
import json
import os
import signal
import sys
import time
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

from elasticsearch import Elasticsearch
from config.config import Config
from environment.network import Network, Subnet, Host
from utility.logging.logging import PerryLogger, setup_action_logger
from defender.Defender import Defender
from defender.arsenal.CountArsenal import CountArsenal
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

perry_config_data = json.loads((Path("config") / "config.json").read_text())
perry_cfg = Config(**perry_config_data)
perry_cfg.experiment_name = experiment_name

management_ip = config["management_ip"]
es_url = config["es_url"]
es_conn = Elasticsearch(es_url, request_timeout=30)
falco_index = config.get("falco_index", "falco")
sysflow_index = config.get("sysflow_index", "sysflow")

spec_hosts = (config.get("defender_env_spec") or {}).get("hosts") or []
victims = [Host(name=h["name"], ip=h["ip"]) for h in spec_hosts if h.get("ip")]
network = Network(
    name=experiment_name,
    subnets=[Subnet(name=f"{experiment_name}-victims", hosts=victims, sec_group="", attacker=False)],
)

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
from defender.orchestrator.RemoteEnvOrchestrator import RemoteEnvOrchestrator
orchestrator = RemoteEnvOrchestrator.from_config(
    config, experiment_name=experiment_name, network=network, action_logger=action_logger)

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
defender.start(prepared=False)

(log_dir / "defender_ready").write_text("armed\n")
print(f"[{experiment_name}] Defender running", flush=True)

while _running:
    defender.run()
    time.sleep(10)

print(f"[{experiment_name}] Defender stopped", flush=True)
