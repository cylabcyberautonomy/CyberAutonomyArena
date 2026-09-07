#!/usr/bin/env python3
"""One-time setup for the Deception defense plugin, run by DeceptionDefenderPlugin.setup()
before the long-running runner.py subprocess starts. Currently: ensure the shared
Elasticsearch instance is up. Receives a config JSON path as argv[1] containing
`deception_dir`.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text())

_deception_dir = config.get("deception_dir", "")
if _deception_dir and _deception_dir not in sys.path:
    sys.path.insert(0, _deception_dir)

from config.config import Config

perry_config_data = json.loads((Path(config["deception_dir"]) / "config" / "config.json").read_text())
perry_cfg = Config(**perry_config_data)

# Elasticsearch is shared, persistent infrastructure (see host_ip in
# experiment_harness/config.yaml / management_ip in defender/defender.py - this is
# the harness host itself, not an ephemeral experiment VM): every experiment's Falco
# agents ship alerts to the SAME address (ansible/defender/falco/install_falco.yml),
# so it can't be spun up fresh per experiment without breaking that. What this setup
# step does is ensure it's actually running here - idempotent and safe under
# concurrent experiments (checked, not unconditionally (re)created). Runs
# security-disabled/plain HTTP: this is a closed, single-tenant research
# environment (no data crosses a real network boundary beyond the experiment's own
# hosts), so the TLS/auth setup real Elasticsearch deployments need is pure
# overhead here. If that ever changes, switch this AND install_falco.py's
# es_host/es_user/es_password back to https + basic auth.
_ES_CONTAINER_NAME = "mhbench-elasticsearch"
_ES_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:9.5.0"  # pin matches elasticsearch-py's version (see requirements.txt) - the client rejects a server whose major version it doesn't recognize


def _es_ready(port: int) -> bool:
    # A real HTTP GET, not just a TCP connect - the container's port is published
    # (and accepts connections) well before the JVM inside is actually serving
    # requests, so a bare socket check reports "ready" ~15s too early and the
    # runner's first real query races a server that isn't listening yet.
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _ensure_elasticsearch(port: int) -> None:
    if _es_ready(port):
        return  # already up - a previous experiment, or a concurrent one, already started it

    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", _ES_CONTAINER_NAME],
        capture_output=True, text=True,
    )
    if inspect.returncode == 0:
        if inspect.stdout.strip() != "true":
            subprocess.run(["docker", "start", _ES_CONTAINER_NAME], check=True)
    else:
        subprocess.run(
            [
                "docker", "run", "-d", "--name", _ES_CONTAINER_NAME,
                "-p", f"{port}:9200",
                "-e", "discovery.type=single-node",
                "-e", "xpack.security.enabled=false",
                "-e", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
                _ES_IMAGE,
            ],
            check=True,
        )

    for _ in range(90):
        if _es_ready(port):
            return
        time.sleep(2)
    raise RuntimeError(f"Elasticsearch did not become reachable on port {port} in time")


_ensure_elasticsearch(perry_cfg.elastic_config.port)
print("Elasticsearch ready.", flush=True)
