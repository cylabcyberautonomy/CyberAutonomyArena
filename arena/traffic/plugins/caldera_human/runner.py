#!/usr/bin/env python3
"""Caldera-human traffic runner — stdlib only (ansible invoked via the sibling ansible.py helper).

Spawned by CalderaHumanTraffic.run() AFTER the pre-attack log rotation. It:
  1. STARTS the pyhuman generators on every victim (ansible `start` play),
  2. touches <log_dir>/traffic_ready — the arena gates the attacker on this (TrafficPlugin.wait_until_ready),
  3. idles until SIGTERM (the arena stops it when the attacker finishes), then
  4. STOPS the generators and pulls their labeled activity log into <log_dir>/activity_logs before the
     VMs are destroyed.

argv[1] = config JSON with: experiment_name, ansible_playbook_bin, log_dir, and the arena-injected
traffic_setup_access (per-victim scoped key + bastion routing) / traffic_env_spec. It reaches victims only
through that injected access — it never reads a management key or parses a topology.
"""
from __future__ import annotations

import importlib.util
import json
import signal
import sys
import time
from pathlib import Path

# Load the sibling ansible helper standalone (it is pure stdlib) so the runner needn't import the whole
# arena package — same self-contained spirit as the canary runner.
_ANSIBLE_PY = Path(__file__).resolve().parent / "ansible.py"
_spec = importlib.util.spec_from_file_location("_bg_ansible", _ANSIBLE_PY)
bg_ansible = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bg_ansible)

CONFIG = json.loads(Path(sys.argv[1]).read_text())
EXP = CONFIG["experiment_name"]
ACCESS = CONFIG.get("traffic_setup_access", [])
ANSIBLE_BIN = CONFIG["ansible_playbook_bin"]
LOG_DIR = Path(CONFIG["log_dir"])
LOG_DIR.mkdir(parents=True, exist_ok=True)
MARKER = LOG_DIR / "traffic_ready"
ANSIBLE_LOG = LOG_DIR / "bgtraffic_ansible.log"


def _log(msg: str) -> None:
    print(f"[{EXP}] traffic-runner: {msg}", flush=True)


def _play(action: str, extravars: dict | None = None) -> None:
    bg_ansible.run_play(action=action, access=ACCESS, ansible_playbook_bin=ANSIBLE_BIN,
                        extravars=extravars or {}, log_path=ANSIBLE_LOG)


def main() -> None:
    if not ACCESS:
        _log("no victim access in config (empty traffic_setup_access) — cannot start generators")
        sys.exit(1)

    _log(f"starting generators on {len(ACCESS)} victim(s)")
    _play("start")  # raises -> non-zero exit -> arena's wait_until_ready sees the dead process and fails the run
    MARKER.write_text("running\n")
    _log("generators up (readiness marker written); holding until SIGTERM")

    running = {"v": True}

    def _stop(signum, frame):
        running["v"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while running["v"]:
        time.sleep(2)

    # Best-effort teardown: stop the generators, then pull the labeled activity log before the VMs die.
    _log("stopping generators")
    try:
        _play("stop")
    except Exception as e:  # noqa: BLE001
        _log(f"stop play failed (best-effort): {e}")
    _log("collecting activity logs")
    try:
        collect_dir = LOG_DIR / "activity_logs"
        collect_dir.mkdir(parents=True, exist_ok=True)
        _play("collect", {"bgtraffic_collect_dest": str(collect_dir)})
    except Exception as e:  # noqa: BLE001
        _log(f"collect play failed (best-effort): {e}")
    _log("stopped")


if __name__ == "__main__":
    main()
