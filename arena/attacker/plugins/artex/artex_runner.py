#!/usr/bin/env python3
"""ARTEX attacker runner (pushed to the foothold, run with the system python3 — stdlib only).

ARTEX is a web platform, not a CLI agent, so this runner drives it headlessly through its REST API:
  1. wait for the API (GET /api/auth/status),
  2. first-run bootstrap: read the one-time setup token from the artex container log and POST
     /api/auth/init to set the admin password,
  3. POST /api/auth/login -> JWT,
  4. POST /api/tasks with the objective goal,
  5. poll GET /api/tasks/{id} until status is done/failed or the poll budget runs out.

The ARTEX stack (postgres + artex) is already up — the plugin's setup() ran `docker compose up -d`.
No third-party deps: uses urllib so the foothold's system python3 is enough.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CFG = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(CFG["output_dir"])
OUT.mkdir(parents=True, exist_ok=True)
SRC = CFG["src_dir"]
PORT = int(CFG["port"])
API = f"http://127.0.0.1:{PORT}/api"
ADMIN_PW = CFG["admin_password"]


def log(msg: str) -> None:
    print(f"[artex-runner] {msg}", flush=True)


def http(method: str, path: str, body: dict | None = None, token: str | None = None, timeout: int = 120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode(errors="replace")
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}


def wait_api() -> None:
    for _ in range(90):
        try:
            code, _ = http("GET", "/auth/status", timeout=10)
            if code == 200:
                log("API is up")
                return
        except Exception:
            pass
        time.sleep(4)
    raise RuntimeError("ARTEX API never answered /auth/status")


def read_setup_token() -> str:
    """ARTEX logs `... Setup token for the /setup page: <hex>` at startup while no password is set."""
    out = subprocess.run(
        f"cd {SRC} && docker compose logs --no-color artex 2>&1",
        shell=True, capture_output=True, text=True, timeout=120).stdout
    m = re.findall(r"Setup token for the /setup page:\s*([0-9a-f]+)", out)
    if not m:
        raise RuntimeError("could not find the setup token in the artex container log")
    return m[-1]


def ensure_auth() -> str:
    code, status = http("GET", "/auth/status")
    if not status.get("initialized"):
        token = read_setup_token()
        code, resp = http("POST", "/auth/init", {"password": ADMIN_PW, "setup_token": token})
        if code != 200:
            raise RuntimeError(f"auth/init failed ({code}): {resp}")
        log("admin password initialized")
    code, resp = http("POST", "/auth/login", {"username": "ARTEX", "password": ADMIN_PW})
    if code != 200 or "token" not in resp:
        raise RuntimeError(f"auth/login failed ({code}): {resp}")
    log("logged in")
    return resp["token"]


def create_task(jwt: str) -> str:
    body = {
        "description": CFG.get("description", "arena task"),
        "goal": CFG["goal"],
        "timeout_seconds": int(CFG["task_timeout_seconds"]),
    }
    code, resp = http("POST", "/tasks", body, token=jwt)
    if code not in (200, 201):
        raise RuntimeError(f"POST /tasks failed ({code}): {resp}")
    tid = resp.get("id") or (resp.get("task") or {}).get("id")
    if tid is None:
        raise RuntimeError(f"task created but no id in response: {resp}")
    log(f"task {tid} created")
    return str(tid)


def main() -> None:
    wait_api()
    jwt = ensure_auth()
    tid = create_task(jwt)
    deadline = time.time() + int(CFG["poll_timeout_seconds"])
    last = None
    while time.time() < deadline:
        code, task = http("GET", f"/tasks/{tid}", token=jwt)
        if code == 200:
            (OUT / "task_status.json").write_text(json.dumps(task, indent=2))
            st = task.get("status")
            prog = f"{task.get('goals_met')}/{task.get('goals_total')} goals, in_flight={task.get('in_flight')}"
            if (st, prog) != last:
                log(f"task {tid}: status={st} {prog}")
                last = (st, prog)
            if st in ("done", "failed"):
                log(f"task {tid} terminal: {st}")
                break
        time.sleep(15)
    else:
        log("poll budget exhausted; leaving the task running for teardown to reap")


if __name__ == "__main__":
    main()
