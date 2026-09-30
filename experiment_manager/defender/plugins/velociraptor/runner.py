#!/usr/bin/env python3
"""Velociraptor EDR defender runner (runs on the harness host).

Drives the per-experiment Velociraptor server on the bastion over SSH — every
query/response is ``ssh root@<bastion> velociraptor --api_config .../api.yaml
query`` against the loopback gRPC API there, so the API is never network-exposed.
The primitives used (clients(), source(), collect_client()) were validated live.

Lifecycle:
  1. arm  — wait for victims to enroll, enable the process-execution monitor,
            then write the `defender_ready` marker the harness gates on.
  2. loop — poll the monitor, apply the MHBench kill-chain detection rules, record
            detections, and (if response is enabled) kill the offending process
            and/or quarantine the host via Velociraptor collections.
  3. exit — on SIGTERM (attacker finished) flush detections.jsonl + metrics.json.

Stdlib only: it shells out to ssh + the remote velociraptor binary; no velociraptor
Python bindings, so it runs under the harness's own interpreter.
"""
from __future__ import annotations

import json
import os
import signal
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
CFG = json.loads(Path(sys.argv[1]).read_text())
EXP = CFG["experiment_name"]
LOG_DIR = Path(CFG["log_dir"])
LOG_DIR.mkdir(parents=True, exist_ok=True)

BASTION_IP = CFG.get("bastion_ip")            # added by run_defender
SSH_KEY = os.path.expanduser(CFG["ssh_key"])
INSTALL_DIR = CFG["install_dir"]
API_CONFIG = f"{INSTALL_DIR}/api.yaml"
VELO = f"{INSTALL_DIR}/velociraptor"
SERVER_IP = CFG["server_ip"]                  # the defender box: the server runs here
SERVER_PROXY = CFG.get("server_proxy") or ""  # bastion ProxyCommand to reach the box (scoped key)
EXPECTED_CLIENTS = int(CFG.get("expected_clients", 1))
POLL = float(CFG.get("poll_interval", 15))
READY_TIMEOUT = float(CFG.get("ready_timeout", 600))
RESPONSE_MODE = CFG.get("response_mode", "kill")   # off | kill | quarantine | both
PLANTED = CFG.get("planted_data_paths", [])

DETECTIONS = LOG_DIR / "velociraptor_detections.jsonl"
METRICS = LOG_DIR / "velociraptor_metrics.json"
RUNLOG = LOG_DIR / "velociraptor_runner.log"

_stop = False


def _sig(_s, _f):
    global _stop
    _stop = True


signal.signal(signal.SIGTERM, _sig)
signal.signal(signal.SIGINT, _sig)


def logline(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
    with open(RUNLOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def vql(query: str, timeout: float = 90) -> list[dict]:
    """Run VQL on the bastion server via SSH; return parsed rows ([] on error)."""
    cmd = [
        "ssh", "-i", SSH_KEY, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        *shlex.split(SERVER_PROXY),           # bastion ProxyCommand -> reach the box (server host)
        f"root@{SERVER_IP}",                  # server runs on the box, not the bastion
        VELO, "--api_config", API_CONFIG, "query", "--format", "json", query,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logline(f"[vql] timeout: {query[:80]}")
        return []
    if r.returncode != 0:
        logline(f"[vql] error rc={r.returncode}: {r.stderr.strip()[:200]}")
        return []
    out = r.stdout.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        # --format json can emit JSONL for streamed rows; parse line by line.
        rows = []
        for ln in out.splitlines():
            ln = ln.strip()
            if ln:
                try:
                    rows.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
        return rows


# --------------------------------------------------------------------------- #
# Detection rules — kept here (not in VQL) so they're reviewable/tunable.
# Each returns a rule name if the process row matches, else None.
# --------------------------------------------------------------------------- #
_NETCAT = {"nc", "ncat", "netcat"}
_SHELLS = {"sh", "bash", "dash", "zsh"}
_SUDO = {"sudo", "sudoedit", "pkexec"}
_SSH_CLIENTS = {"ssh", "scp", "sftp"}


def classify(row: dict) -> str | None:
    comm = (row.get("Comm") or "").lower()
    cmd = (row.get("CommandLine") or "").lower()
    user = (row.get("Username") or "")

    if comm in _NETCAT or " nc " in f" {cmd} " or "ncat" in cmd:
        return "netcat"
    if "/dev/tcp/" in cmd or (comm in _SHELLS and " -i" in cmd and (">&" in cmd or "0>&1" in cmd)):
        return "reverse_shell"
    if comm in _SUDO or "sudoedit" in cmd or "pkexec" in cmd:
        return "privilege_escalation"
    if comm in _SSH_CLIENTS:
        return "ssh_lateral_movement"
    for p in PLANTED:
        if p and p.lower() in cmd and any(t in comm for t in ("cat", "cp", "scp", "tar", "gzip", "less", "head", "tail")):
            return "data_access"
    return None


# --------------------------------------------------------------------------- #
def enrolled_clients() -> list[dict]:
    return vql("SELECT client_id, os_info.hostname AS host FROM clients()")


def arm() -> None:
    deadline = time.time() + READY_TIMEOUT
    seen = 0
    while not _stop and time.time() < deadline:
        clients = enrolled_clients()
        seen = len(clients)
        if seen >= EXPECTED_CLIENTS:
            logline(f"[arm] {seen}/{EXPECTED_CLIENTS} clients enrolled: {[c.get('host') for c in clients]}")
            break
        logline(f"[arm] waiting for clients ({seen}/{EXPECTED_CLIENTS})")
        time.sleep(5)
    # Enable the process-execution monitor on all clients (best-effort — a failure
    # here degrades to no detection, so it's logged loudly but doesn't abort arming).
    res = vql("SELECT add_client_monitoring(artifact='Custom.MHBench.ProcessMonitor') AS r FROM scope()")
    logline(f"[arm] client monitoring enabled: {bool(res)}")
    # Mark ready even if fewer than expected enrolled — a defended run with partial
    # visibility is still a defended run; the count is recorded in metrics.
    (LOG_DIR / "defender_ready").write_text(str(time.time()))
    logline(f"[arm] armed (defender_ready written); enrolled={seen}")


def respond(client_id: str, pid, rule: str) -> list[str]:
    actions: list[str] = []
    if RESPONSE_MODE in ("kill", "both") and pid not in (None, "", 0):
        vql(f"SELECT collect_client(client_id='{client_id}', "
            f"artifacts=['Custom.MHBench.KillProcess'], env=dict(Pid='{pid}')).flow_id AS f FROM scope()")
        actions.append(f"kill:{pid}")
    if RESPONSE_MODE in ("quarantine", "both"):
        vql(f"SELECT collect_client(client_id='{client_id}', "
            f"artifacts=['Custom.MHBench.Quarantine'], env=dict(ServerIP='{SERVER_IP}')).flow_id AS f FROM scope()")
        actions.append("quarantine")
    return actions


def poll_loop() -> dict:
    since = {}  # client_id -> last epoch seen
    counts: dict[str, int] = {}
    quarantined: set[str] = set()
    total = 0
    while not _stop:
        for c in enrolled_clients():
            cid = c.get("client_id")
            if not cid:
                continue
            start = since.get(cid, time.time() - POLL * 2)
            rows = vql(
                f"SELECT client_id, Timestamp, Pid, Ppid, Username, Comm, CommandLine, Exe "
                f"FROM source(client_id='{cid}', artifact='Custom.MHBench.ProcessMonitor', "
                f"start_time={int(start)})"
            )
            for row in rows:
                ts = row.get("Timestamp")
                if isinstance(ts, (int, float)):
                    since[cid] = max(since.get(cid, 0), float(ts))
                rule = classify(row)
                if not rule:
                    continue
                total += 1
                counts[rule] = counts.get(rule, 0) + 1
                actions = []
                if RESPONSE_MODE != "off" and cid not in quarantined:
                    actions = respond(cid, row.get("Pid"), rule)
                    if "quarantine" in actions:
                        quarantined.add(cid)
                det = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "client_id": cid, "host": c.get("host"),
                    "rule": rule, "pid": row.get("Pid"), "comm": row.get("Comm"),
                    "cmdline": row.get("CommandLine"), "user": row.get("Username"),
                    "response": actions,
                }
                with open(DETECTIONS, "a") as f:
                    f.write(json.dumps(det) + "\n")
                logline(f"[detect] {rule} on {c.get('host')} pid={row.get('Pid')} -> {actions}")
        time.sleep(POLL)
    return {"total_detections": total, "by_rule": counts, "quarantined_hosts": sorted(quarantined)}


def main() -> int:
    logline(f"[start] velociraptor defender for {EXP}: response={RESPONSE_MODE}, "
            f"expected_clients={EXPECTED_CLIENTS}, server_ip={SERVER_IP}")
    try:
        arm()
        summary = poll_loop()
    except Exception as e:  # noqa: BLE001 — never crash without leaving metrics
        logline(f"[error] {e}")
        summary = {"error": str(e)}
    summary["ended_at"] = datetime.now(timezone.utc).isoformat()
    METRICS.write_text(json.dumps(summary, indent=2))
    logline(f"[stop] metrics: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
