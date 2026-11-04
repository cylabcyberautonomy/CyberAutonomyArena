#!/usr/bin/env python3
"""CyberStrikeAI attacker runner (pushed to the foothold, run with the system python3 — stdlib only).

CyberStrikeAI is a server platform, not a CLI agent, so this runner drives it through its REST API:
  1. wait for the web server (HTTPS, self-signed),
  2. POST /api/auth/login (built-in admin + the first-boot generated password) -> Bearer token,
  3. POST /api/multi-agent/runs {message, orchestration} (with an Idempotency-Key) -> runId,
  4. poll GET /api/multi-agent/runs/{runId} until the run status is terminal.

The server is already up — the plugin's setup() built + launched it and scraped the admin password.
Uses urllib + an unverified TLS context (no third-party deps; the foothold's system python3 is enough).
"""
from __future__ import annotations

import json
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

CFG = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(CFG["output_dir"])
OUT.mkdir(parents=True, exist_ok=True)
PORT = int(CFG["port"])
ROOT = f"https://127.0.0.1:{PORT}/api"

_TERMINAL = {"completed", "succeeded", "success", "finished", "done", "failed", "error", "cancelled", "canceled"}

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def log(msg: str) -> None:
    print(f"[cyberstrike-runner] {msg}", flush=True)


def call(method: str, path: str, body: dict | None = None, token: str | None = None,
         headers: dict | None = None, timeout: int = 120):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(ROOT + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            raw = r.read().decode(errors="replace")
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw}


def wait_web() -> None:
    for _ in range(90):
        try:
            code, _ = call("POST", "/auth/login", {}, timeout=10)
            if code and code != 502:
                log("web is up")
                return
        except Exception:
            pass
        time.sleep(4)
    raise RuntimeError("CyberStrikeAI web never answered")


def login() -> str:
    code, resp = call("POST", "/auth/login",
                      {"username": CFG["admin_username"], "password": CFG["admin_password"]})
    if code != 200 or "token" not in resp:
        raise RuntimeError(f"auth/login failed ({code}): {resp}")
    log("logged in")
    return resp["token"]


def submit(token: str) -> str:
    code, resp = call("POST", "/multi-agent/runs",
                      {"message": CFG["message"], "orchestration": CFG.get("orchestration", "deep")},
                      token=token, headers={"Idempotency-Key": str(uuid.uuid4())})
    if code not in (200, 201, 202):
        raise RuntimeError(f"submit run failed ({code}): {resp}")
    rid = resp.get("runId") or resp.get("id") or (resp.get("run") or {}).get("runId")
    if not rid:
        raise RuntimeError(f"run submitted but no runId: {resp}")
    log(f"run {rid} submitted (status={resp.get('status')})")
    return str(rid)


def main() -> None:
    wait_web()
    token = login()
    rid = submit(token)
    deadline = time.time() + int(CFG["poll_timeout_seconds"])
    last = None
    while time.time() < deadline:
        code, run = call("GET", f"/multi-agent/runs/{rid}", token=token)
        if code == 200:
            (OUT / "run_status.json").write_text(json.dumps(run, indent=2))
            st = (run.get("status") or "").lower()
            if st != last:
                log(f"run {rid}: status={st}")
                last = st
            if st in _TERMINAL:
                log(f"run {rid} terminal: {st}")
                break
        else:
            log(f"poll HTTP {code}: {run}")
        time.sleep(15)
    else:
        log("poll budget exhausted; leaving the run for teardown to reap")


if __name__ == "__main__":
    main()
