#!/usr/bin/env python3
"""Canary defender runner — stdlib only (SSH via subprocess, ES via urllib).

argv[1] = config JSON with:
  experiment_name, topology_spec, checks[], canary_host, telemetry_port,
  telemetry_timeout_s, fail_closed, ssh_key, management_ip, bastion_ip, log_dir

Writes <log_dir>/connectivity_report.json, then arms (writes <log_dir>/defender_ready)
unless fail_closed and a required check failed. Then idles until SIGTERM (the harness
tears it down when the attacker finishes).
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------- config
CONFIG = json.loads(Path(sys.argv[1]).read_text())
EXP = CONFIG["experiment_name"]
CHECKS = CONFIG.get("checks") or ["ssh", "resolve", "telemetry", "canary_event"]
SSH_KEY = os.path.expanduser(CONFIG["ssh_key"])
BASTION = CONFIG.get("bastion_ip")
ES_HOST = CONFIG.get("management_ip")
ES_PORT = int(CONFIG.get("telemetry_port", 9200))
TELEMETRY_TIMEOUT = float(CONFIG.get("telemetry_timeout_s", 60.0))
FAIL_CLOSED = bool(CONFIG.get("fail_closed", False))
LOG_DIR = Path(CONFIG["log_dir"])
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _log(msg: str) -> None:
    print(f"[{EXP}] canary: {msg}", flush=True)


# --------------------------------------------------------------------------- topology
def _victims(topology_spec: str | None) -> list[tuple[str, str]]:
    """[(model_name, internal_ip)] for every non-attacker host."""
    if not topology_spec or not Path(topology_spec).exists():
        return []
    topo = json.loads(Path(topology_spec).read_text())
    out = []
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            for h in sub.get("hosts", []):
                if h.get("vm_type") == "kali_running":
                    continue
                ip = h.get("ip_address")
                if ip:
                    out.append((h["name"], str(ip)))
    return out


def _sanitize(name: str) -> str:
    # Mirror Perry's defender/telemetry/index_names.sanitize so we look at the exact
    # falco-<exp>/sysflow-<exp> indices a real defender reads.
    return re.sub(r"[^a-z0-9_.-]+", "-", (name or "").strip().lower()).strip("-._")


# --------------------------------------------------------------------------- ssh
def _proxy(bastion: str) -> str:
    return (
        f"ssh -W %h:%p -i {SSH_KEY} -o BatchMode=yes -o PasswordAuthentication=no "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{bastion}"
    )


def _ssh_victim(ip: str, remote_cmd: str, timeout: int = 45) -> tuple[bool, str]:
    """Run remote_cmd on a victim through the bastion. Returns (ok, output-or-error)."""
    if not BASTION:
        return False, "no bastion_ip"
    cmd = [
        "ssh", "-i", SSH_KEY,
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={min(timeout, 20)}",
        "-o", f"ProxyCommand={_proxy(BASTION)}",
        f"root@{ip}", remote_cmd,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    if r.returncode != 0:
        return False, (r.stderr.strip() or f"exit {r.returncode}")
    return True, r.stdout.strip()


# --------------------------------------------------------------------------- es
def _es_get(path: str, timeout: int = 15):
    url = f"http://{ES_HOST}:{ES_PORT}{path}"
    req = urllib.request.Request(url, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw.strip() else {}


def _es_count(index: str) -> int | None:
    try:
        return int(_es_get(f"/{index}/_count").get("count", 0))
    except Exception:
        return None


# --------------------------------------------------------------------------- checks
def check_ssh(victims):
    results = {}
    ok_any = False
    for name, ip in victims:
        ok, out = _ssh_victim(ip, "hostname")
        results[name] = {"ip": ip, "ok": ok, "detail": out}
        ok_any = ok_any or ok
    return {
        "ok": ok_any and all(v["ok"] for v in results.values()) if victims else False,
        "reachable": sum(1 for v in results.values() if v["ok"]),
        "total": len(victims),
        "hosts": results,
    }


def check_resolve(victims, ssh_results):
    """Compare topology model-name to the victim's real OS hostname."""
    rows = {}
    matches = 0
    for name, ip in victims:
        got = (ssh_results.get("hosts", {}).get(name) or {})
        os_host = got.get("detail") if got.get("ok") else None
        match = bool(os_host) and (os_host == name)
        matches += 1 if match else 0
        rows[name] = {"ip": ip, "os_hostname": os_host, "matches_model_name": match}
    return {
        "ok": bool(victims) and matches == len(victims),
        "matching": matches,
        "total": len(victims),
        "note": "mismatches are the FalcoLLM hostname-resolution trap (model name != OS hostname)",
        "hosts": rows,
    }


def check_telemetry():
    falco = f"falco-{_sanitize(EXP)}"
    sysflow = f"sysflow-{_sanitize(EXP)}"
    try:
        cat = _es_get("/_cat/indices?format=json")
        names = {row.get("index") for row in cat} if isinstance(cat, list) else set()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reachable": False, "error": str(e),
                "es": f"{ES_HOST}:{ES_PORT}", "falco_index": falco, "sysflow_index": sysflow}
    return {
        "ok": falco in names or sysflow in names,
        "reachable": True,
        "es": f"{ES_HOST}:{ES_PORT}",
        "falco_index": falco, "falco_present": falco in names, "falco_docs": _es_count(falco),
        "sysflow_index": sysflow, "sysflow_present": sysflow in names, "sysflow_docs": _es_count(sysflow),
    }


def check_canary_event(victims, want_host):
    """Read /etc/shadow on one victim, then confirm the falco index grows (data actually
    flows victim -> sensor -> store)."""
    if not victims:
        return {"ok": False, "detail": "no victims"}
    target = None
    for name, ip in victims:
        if want_host and (name == want_host or want_host in name):
            target = (name, ip)
            break
    target = target or victims[0]
    name, ip = target
    falco = f"falco-{_sanitize(EXP)}"

    before = _es_count(falco)
    ok_read, out = _ssh_victim(ip, "for i in 1 2 3; do cat /etc/shadow >/dev/null 2>&1; done; echo triggered")
    if not ok_read:
        return {"ok": False, "host": name, "detail": f"could not trigger read: {out}"}

    deadline = time.time() + TELEMETRY_TIMEOUT
    after = before
    while time.time() < deadline:
        time.sleep(3)
        after = _es_count(falco)
        if before is not None and after is not None and after > before:
            break
    grew = before is not None and after is not None and after > before
    return {
        "ok": bool(grew),
        "host": name,
        "falco_index": falco,
        "docs_before": before,
        "docs_after": after,
        "detail": ("event observed" if grew else
                   "no new falco docs after the canary read within the timeout "
                   "(sensor not capturing / not shipping to this ES / index empty)"),
    }


# --------------------------------------------------------------------------- main
def main() -> None:
    victims = _victims(CONFIG.get("topology_spec"))
    report = {"experiment": EXP, "checks_requested": CHECKS, "victims": len(victims), "results": {}}
    _log(f"{len(victims)} victim(s); running checks: {CHECKS}")

    ssh_res = None
    if "ssh" in CHECKS:
        ssh_res = check_ssh(victims)
        report["results"]["ssh"] = ssh_res
        _log(f"ssh: {ssh_res['reachable']}/{ssh_res['total']} reachable")

    if "resolve" in CHECKS:
        res = check_resolve(victims, ssh_res or check_ssh(victims))
        report["results"]["resolve"] = res
        _log(f"resolve: {res['matching']}/{res['total']} model-name == OS-hostname")

    if "telemetry" in CHECKS:
        tel = check_telemetry()
        report["results"]["telemetry"] = tel
        _log(f"telemetry: reachable={tel.get('reachable')} "
             f"falco={tel.get('falco_present')} sysflow={tel.get('sysflow_present')}")

    if "canary_event" in CHECKS:
        ev = check_canary_event(victims, CONFIG.get("canary_host"))
        report["results"]["canary_event"] = ev
        _log(f"canary_event: ok={ev['ok']} ({ev.get('detail')})")

    all_ok = all(r.get("ok") for r in report["results"].values()) if report["results"] else False
    report["all_ok"] = all_ok

    report_path = LOG_DIR / "connectivity_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    _log(f"report -> {report_path} (all_ok={all_ok})")

    marker = LOG_DIR / "defender_ready"
    if FAIL_CLOSED and not all_ok:
        _log("fail_closed and a check failed — NOT arming (defender will fail the run)")
        sys.exit(1)
    marker.write_text("armed\n")
    _log("armed")

    # Idle until the harness sends SIGTERM at teardown.
    running = {"v": True}

    def _stop(signum, frame):
        running["v"] = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while running["v"]:
        time.sleep(2)
    _log("stopped")


if __name__ == "__main__":
    main()
