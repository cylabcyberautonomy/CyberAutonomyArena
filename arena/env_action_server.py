"""The defender→environment action channel: a UDS-only HTTP endpoint a RUNNING defender's
RemoteEnvOrchestrator (Defense repo) POSTs EnvActionRequest events to.

SECURITY (why a Unix domain socket, not a TCP port) — see the env_requests.py header and docs/
security-model.md. The adversary agent executes on an in-env VM (the foothold); this channel must be
reachable by the defender runner (a subprocess co-located on the harness host) yet UNREACHABLE by any
in-env VM. A UDS has no network port at all, so it is categorically unreachable from the victim/attacker
subnets regardless of how the public API is bound (uvicorn defaults to loopback, but a manager launched
with --host 0.0.0.0 would expose a TCP route — a UDS removes that failure mode entirely). Defense in
depth, three independent layers, any one of which blocks the adversary:

  1. transport     — UDS on the harness host; no VM can reach it.
  2. authentication — a per-experiment bearer token, injected ONLY into the defender config (never the
                      attacker's, which carries no management address at all).
  3. authorization  — a bounded primitive vocabulary (add/rebuild/remove host) within the defender's
                      pre-reserved VM budget, only while the serving window is open.

The handler (handle_env_action) is kept pure and transport-free so it is unit-testable without sockets;
serve_env_actions wraps it in a tiny UDS-bound FastAPI/uvicorn server started from the arena lifespan.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


def resolve_socket_path(cfg) -> str:
    """The manager's env-action socket path. Explicit cfg.env_action_socket wins; otherwise derive a
    short, per-manager path under the runtime dir from a hash of output_dir, so the two managers one user
    runs on one host (:8000 / :8003, distinct output_dir) never collide on a single socket. Kept short
    (UDS paths cap at ~108 bytes — cf. the SSH ControlPath limit)."""
    explicit = getattr(cfg, "env_action_socket", None)
    if explicit:
        return str(explicit)
    tag = hashlib.sha1(str(cfg.output_dir).encode()).hexdigest()[:8]
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return str(Path(runtime) / f"arena-env-{tag}.sock")


def _trace_entry(request, result) -> dict:
    """A small, dependency-light trace record for EnvironmentLifecycle.record_request — exactly what the
    recorded experiment should show about one serviced env-mutation event."""
    return {
        "kind": request.kind.value,
        "name": request.name,
        "target": request.target,
        "ok": result.ok,
        "ip": result.ip,
        "error": result.error,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


async def handle_env_action(payload: dict, *, registry, cfg, lock=None) -> dict:
    """Authorize, budget-check, dispatch, and record ONE env-mutation event. Returns a plain dict with
    the EnvActionResult fields plus an internal "status" (HTTP status the transport should use, popped
    before the body is returned over the wire). Pure: no socket/transport here, so it is unit-testable.

    The serving-window state is read off the LIVE Experiment object (registry.get) that the run loop
    stamps: _env_action_token, _env_serving, _env_budget_remaining, _env_lifecycle."""
    from .environment import EnvActionKind, EnvActionRequest, EnvActionResult, EnvRequestUnsupported

    name = payload.get("experiment_name")
    token = payload.get("token")
    action = payload.get("action") or {}

    # --- existence ---------------------------------------------------------
    try:
        exp = registry.get(name)
    except (KeyError, TypeError):
        return {"ok": False, "error": "unknown experiment", "status": 404}

    # --- authentication (constant-time compare) ----------------------------
    import hmac
    expected = getattr(exp, "_env_action_token", None)
    if not expected or not isinstance(token, str) or not hmac.compare_digest(token, expected):
        return {"ok": False, "error": "unauthorized", "status": 403}

    # --- serving window ----------------------------------------------------
    if not getattr(exp, "_env_serving", False):
        return {"ok": False, "error": "environment is not serving (window closed)", "status": 409}

    # --- validate the event ------------------------------------------------
    try:
        req = EnvActionRequest.model_validate(action)
    except Exception as e:  # noqa: BLE001 — turn any validation error into a 400, never crash the server
        return {"ok": False, "error": f"bad env action: {e}", "status": 400}

    lc = getattr(exp, "_env_lifecycle", None)

    # --- budget ceiling (ADD_HOST only) ------------------------------------
    if req.kind == EnvActionKind.ADD_HOST and getattr(exp, "_env_budget_remaining", 0) <= 0:
        result = EnvActionResult(kind=req.kind, ok=False, error="defender VM budget exhausted")
        if lc is not None:
            lc.record_request(_trace_entry(req, result))
        return {**result.model_dump(mode="json"), "status": 200}

    # --- dispatch (serialise cloud mutations under the same lock provisioning uses) -----------------
    async def _dispatch():
        return await exp.environment.handle_env_request(exp, exp.deployed_environment, req, cfg)

    try:
        if lock is not None:
            async with lock.acquire(0):
                result = await _dispatch()
        else:
            result = await _dispatch()
    except EnvRequestUnsupported as e:
        result = EnvActionResult(kind=req.kind, ok=False, error=str(e))
    except Exception as e:  # noqa: BLE001 — a backend failure must degrade gracefully, not wedge the run
        result = EnvActionResult(kind=req.kind, ok=False, error=f"environment error: {e}")

    # --- budget accounting (only on success) -------------------------------
    if result.ok and req.kind == EnvActionKind.ADD_HOST:
        exp._env_budget_remaining = getattr(exp, "_env_budget_remaining", 0) - 1
    elif result.ok and req.kind == EnvActionKind.REMOVE_HOST:
        exp._env_budget_remaining = getattr(exp, "_env_budget_remaining", 0) + 1

    if lc is not None:
        lc.record_request(_trace_entry(req, result))
    return {**result.model_dump(mode="json"), "status": 200}


def build_env_action_app(registry, cfg, lock):
    """A tiny FastAPI app with the single action route, for serving over a UDS."""
    from fastapi import FastAPI, Body
    from fastapi.responses import JSONResponse

    app = FastAPI(title="arena-env-actions")

    @app.post("/environment/action")
    async def _action(payload: dict = Body(...)):  # noqa: ANN202, B008
        res = await handle_env_action(payload, registry=registry, cfg=cfg, lock=lock)
        status = res.pop("status", 200)
        return JSONResponse(res, status_code=status)

    return app


async def serve_env_actions(socket_path: str, registry, cfg, lock) -> None:
    """Run the UDS server until cancelled (started as a lifespan task). Removes a stale socket file first
    so a crashed prior manager doesn't block bind."""
    import uvicorn

    try:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    except OSError:
        pass
    Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
    config = uvicorn.Config(build_env_action_app(registry, cfg, lock), uds=socket_path, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
