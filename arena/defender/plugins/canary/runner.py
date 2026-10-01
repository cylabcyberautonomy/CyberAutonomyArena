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
import shlex
import sys
import time
import urllib.request
from pathlib import Path

# --------------------------------------------------------------------------- config
CONFIG = json.loads(Path(sys.argv[1]).read_text())
EXP = CONFIG["experiment_name"]
CHECKS = CONFIG.get("checks") or ["ssh", "resolve", "telemetry", "canary_event"]
ES_HOST = CONFIG.get("management_ip")
ES_PORT = int(CONFIG.get("telemetry_port", 9200))
TELEMETRY_TIMEOUT = float(CONFIG.get("telemetry_timeout_s", 60.0))
FAIL_CLOSED = bool(CONFIG.get("fail_closed", False))
LOG_DIR = Path(CONFIG["log_dir"])
LOG_DIR.mkdir(parents=True, exist_ok=True)

# The environment-produced host access: one entry per victim, {name, host, user, port, ssh_key,
# ssh_common_args (the bastion ProxyCommand etc.)}. The canary does not parse the topology or
# resolve an MHBench key itself.
ACCESS = CONFIG.get("defender_setup_access", [])


def _log(msg: str) -> None:
    print(f"[{EXP}] canary: {msg}", flush=True)


def _sanitize(name: str) -> str:
    # Mirror Perry's defender/telemetry/index_names.sanitize so we look at the exact
    # falco-<exp>/sysflow-<exp> indices a real defender reads.
    return re.sub(r"[^a-z0-9_.-]+", "-", (name or "").strip().lower()).strip("-._")


# --------------------------------------------------------------------------- ssh
def _ssh(access: dict, remote_cmd: str, timeout: int = 45) -> tuple[bool, str]:
    """Run remote_cmd on a victim using its SetupAccess entry (key + routing). Returns (ok, out/err)."""
    _k = access.get("ssh_key")
    if not _k:
        # Fail closed: never fall back to the management (god) key on disk — that would defeat the
        # per-system key scoping. The harness must inject a scoped ssh_key in defender_setup_access.
        raise RuntimeError("SetupAccess entry has no ssh_key; refusing to use the management key")
    key = os.path.expanduser(_k)
    cmd = [
        "ssh", "-i", key,
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={min(timeout, 20)}",
        "-p", str(access.get("port", 22)),
    ]
    cmd += shlex.split(access.get("ssh_common_args") or "")  # bastion ProxyCommand, etc.
    cmd += [f"{access.get('user', 'root')}@{access['host']}", remote_cmd]
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
def check_ssh(access_list):
    results = {}
    ok_any = False
    for a in access_list:
        ok, out = _ssh(a, "hostname")
        results[a["name"]] = {"ip": a["host"], "ok": ok, "detail": out}
        ok_any = ok_any or ok
    return {
        "ok": ok_any and all(v["ok"] for v in results.values()) if access_list else False,
        "reachable": sum(1 for v in results.values() if v["ok"]),
        "total": len(access_list),
        "hosts": results,
    }


def check_resolve(access_list, ssh_results):
    """Compare each host's DefenderEnvSpec model-name to its real OS hostname."""
    rows = {}
    matches = 0
    for a in access_list:
        name = a["name"]
        got = (ssh_results.get("hosts", {}).get(name) or {})
        os_host = got.get("detail") if got.get("ok") else None
        match = bool(os_host) and (os_host == name)
        matches += 1 if match else 0
        rows[name] = {"ip": a["host"], "os_hostname": os_host, "matches_model_name": match}
    return {
        "ok": bool(access_list) and matches == len(access_list),
        "matching": matches,
        "total": len(access_list),
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


def check_canary_event(access_list, want_host):
    """Read /etc/shadow on one victim, then confirm the falco index grows (data actually
    flows victim -> sensor -> store)."""
    if not access_list:
        return {"ok": False, "detail": "no victims"}
    target = None
    for a in access_list:
        if want_host and (a["name"] == want_host or want_host in a["name"]):
            target = a
            break
    target = target or access_list[0]
    name = target["name"]
    falco = f"falco-{_sanitize(EXP)}"

    before = _es_count(falco)
    ok_read, out = _ssh(target, "for i in 1 2 3; do cat /etc/shadow >/dev/null 2>&1; done; echo triggered")
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
    victims = ACCESS
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
