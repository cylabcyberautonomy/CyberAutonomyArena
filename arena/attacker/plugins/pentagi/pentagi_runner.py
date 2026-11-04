#!/usr/bin/env python3
"""PentAGI attacker runner (pushed to the foothold, run with the system python3 — stdlib only).

PentAGI is a platform, not a CLI agent, so this runner drives it through its GraphQL API:
  1. wait for the web server,
  2. POST /api/v1/auth/login (seeded admin) -> session cookie,
  3. GraphQL createFlow(modelProvider, input) -> flow id,
  4. poll GraphQL flow(flowId).status until finished/failed or the poll budget runs out.

The stack (pentagi + pgvector + scraper) is already up — the plugin's setup() ran docker compose.
Uses urllib + a cookie jar + an unverified TLS context (PentAGI serves HTTPS with a self-signed cert),
so no third-party deps and the foothold's system python3 is enough.
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CFG = json.loads(Path(sys.argv[1]).read_text())
OUT = Path(CFG["output_dir"])
OUT.mkdir(parents=True, exist_ok=True)
PORT = int(CFG["port"])
ROOT = f"https://127.0.0.1:{PORT}/api/v1"

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_CTX),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
)


def log(msg: str) -> None:
    print(f"[pentagi-runner] {msg}", flush=True)


def post(path: str, body: dict, timeout: int = 120):
    req = urllib.request.Request(ROOT + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _OPENER.open(req, timeout=timeout) as r:
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
            # /auth/login with no body -> a 4xx, but it proves the API is serving.
            code, _ = post("/auth/login", {}, timeout=10)
            if code and code != 502:
                log("web is up")
                return
        except Exception:
            pass
        time.sleep(4)
    raise RuntimeError("PentAGI web never answered")


def login() -> None:
    code, resp = post("/auth/login", {"mail": CFG["admin_email"], "password": CFG["admin_password"]})
    if code != 200:
        raise RuntimeError(f"auth/login failed ({code}): {resp}")
    log(f"logged in as {CFG['admin_email']}")


def gql(query: str, variables: dict):
    code, resp = post("/graphql", {"query": query, "variables": variables})
    if code != 200:
        raise RuntimeError(f"graphql HTTP {code}: {resp}")
    if resp.get("errors"):
        raise RuntimeError(f"graphql errors: {resp['errors']}")
    return resp.get("data", {})


def create_flow() -> str:
    data = gql(
        "mutation($p:String!,$i:String!){createFlow(modelProvider:$p,input:$i){id status title}}",
        {"p": CFG["model_provider"], "i": CFG["input"]},
    )
    flow = data.get("createFlow") or {}
    fid = flow.get("id")
    if not fid:
        raise RuntimeError(f"createFlow returned no id: {data}")
    log(f"flow {fid} created (status={flow.get('status')})")
    return str(fid)


def main() -> None:
    wait_web()
    login()
    fid = create_flow()
    deadline = time.time() + int(CFG["poll_timeout_seconds"])
    last = None
    while time.time() < deadline:
        try:
            data = gql("query($id:ID!){flow(flowId:$id){id status title}}", {"id": fid})
            flow = data.get("flow") or {}
            st = flow.get("status")
            (OUT / "flow_status.json").write_text(json.dumps(flow, indent=2))
            if st != last:
                log(f"flow {fid}: status={st}")
                last = st
            if st in ("finished", "failed"):
                log(f"flow {fid} terminal: {st}")
                break
        except Exception as e:  # noqa: BLE001 — transient API/poll errors shouldn't kill the run
            log(f"poll error: {e}")
        time.sleep(15)
    else:
        log("poll budget exhausted; leaving the flow for teardown to reap")


if __name__ == "__main__":
    main()
