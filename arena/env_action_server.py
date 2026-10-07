"""The defender-to-environment action channel for EnvActionRequest events (UDS, plus a token'd TCP variant)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import shlex
import socket
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


def new_env_action_token() -> str:
    """A fresh per-experiment token for the TCP control-plane channel. Unused by the UDS path."""
    return secrets.token_urlsafe(32)


def pick_free_tcp_port() -> int:
    """An ephemeral free TCP port on the harness (bind :0, read it, release)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_reverse_tunnel_cmd(box_access, box_port: int, tcp_port: int) -> list[str]:
    """Return the `ssh -R` command that exposes the harness env-action server at 127.0.0.1:<box_port> on the box."""
    base = box_access.ssh_base()
    opts = ["-N",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
            "-R", f"127.0.0.1:{box_port}:127.0.0.1:{tcp_port}"]
    return [base[0], *opts, *base[1:]]


async def open_reverse_tunnel(box_access, box_port: int, tcp_port: int,
                              log_path: "Optional[Path]" = None, confirm_s: float = 12.0):
    """Open the ssh -R tunnel, check that it came up within confirm_s, and return the live process."""
    cmd = build_reverse_tunnel_cmd(box_access, box_port, tcp_port)
    out = open(log_path, "a") if log_path else subprocess.DEVNULL
    proc = await asyncio.create_subprocess_exec(*cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                                start_new_session=True)
    # ExitOnForwardFailure makes an early non-zero exit the failure signal. A healthy -N tunnel stays up.
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=confirm_s)
        raise RuntimeError(f"env-action reverse tunnel to the box failed to come up (ssh exited rc={rc}); "
                           f"check the box sshd AllowTcpForwarding — see {log_path}")
    except asyncio.TimeoutError:
        return proc

async def close_reverse_tunnel(proc) -> None:
    """Best-effort teardown of the ssh -R tunnel process (on DEACTIVATE/teardown)."""
    if proc is None or proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=10)
    except (asyncio.TimeoutError, ProcessLookupError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def resolve_socket_path(cfg) -> str:
    """The manager's env-action socket path. Explicit cfg.env_action_socket wins, else a per-manager path."""
    explicit = getattr(cfg, "env_action_socket", None)
    if explicit:
        return str(explicit)
    tag = hashlib.sha1(str(cfg.output_dir).encode()).hexdigest()[:8]
    runtime = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return str(Path(runtime) / f"arena-env-{tag}.sock")


def _trace_entry(request, result) -> dict:
    """A small trace record for EnvironmentLifecycle.record_request about one serviced env-mutation event."""
    return {
        "kind": request.kind.value,
        "name": request.name,
        "target": request.target,
        "ok": result.ok,
        "ip": result.ip,
        "error": result.error,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


async def handle_env_action(payload: dict, *, registry, cfg, lock=None,
                            token: Optional[str] = None, trusted_transport: bool = True) -> dict:
    """Authorize, dispatch, and record one env-mutation event. Returns a dict with the EnvActionResult
    fields plus an internal "status" (the HTTP status, popped before the body goes over the wire).

    `trusted_transport` is True for the UDS server (no token). For the TCP server it is False, and `token`
    must match this experiment's _env_action_token (constant-time compare) or the handler rejects it 403."""
    from .environment import EnvActionKind, EnvActionRequest, EnvActionResult, EnvRequestUnsupported

    name = payload.get("experiment_name")
    action = payload.get("action") or {}

    # --- existence ---------------------------------------------------------
    try:
        exp = registry.get(name)
    except (KeyError, TypeError):
        return {"ok": False, "error": "unknown experiment", "status": 404}

    # --- token (untrusted/TCP transport only) ------------------------------
    if not trusted_transport:
        expected = getattr(exp, "_env_action_token", None)
        if not expected or not token or not hmac.compare_digest(str(token), str(expected)):
            return {"ok": False, "error": "forbidden (bad or missing env-action token)", "status": 403}

    # --- serving window ----------------------------------------------------
    if not getattr(exp, "_env_serving", False):
        return {"ok": False, "error": "environment is not serving (window closed)", "status": 409}

    # --- check the event ---------------------------------------------------
    try:
        req = EnvActionRequest.model_validate(action)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"bad env action: {e}", "status": 400}

    lc = getattr(exp, "_env_lifecycle", None)

    # --- dispatch ----------------------------------------------------------
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
    except Exception as e:  # noqa: BLE001
        result = EnvActionResult(kind=req.kind, ok=False, error=f"environment error: {e}")

    if lc is not None:
        lc.record_request(_trace_entry(req, result))
    return {**result.model_dump(mode="json"), "status": 200}


def build_env_action_app(registry, cfg, lock, *, require_token: bool = False):
    """A tiny FastAPI app with the single action route. `require_token=True` marks the transport untrusted."""
    from fastapi import FastAPI, Body, Header
    from fastapi.responses import JSONResponse

    app = FastAPI(title="arena-env-actions")

    @app.post("/environment/action")
    async def _action(payload: dict = Body(...),  # noqa: ANN202, B008
                      x_arena_token: Optional[str] = Header(default=None)):  # noqa: B008
        res = await handle_env_action(payload, registry=registry, cfg=cfg, lock=lock,
                                      token=x_arena_token, trusted_transport=not require_token)
        status = res.pop("status", 200)
        return JSONResponse(res, status_code=status)

    return app


async def serve_env_actions(socket_path: str, registry, cfg, lock) -> None:
    """Run the UDS server until cancelled, removing a stale socket file first. Token-free."""
    import uvicorn

    try:
        if os.path.exists(socket_path):
            os.unlink(socket_path)
    except OSError:
        pass
    Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
    config = uvicorn.Config(build_env_action_app(registry, cfg, lock, require_token=False),
                            uds=socket_path, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def serve_env_actions_tcp(host: str, port: int, registry, cfg, lock) -> None:
    """Serve the same env-action app over TCP, token-required, for a box-resident defender.

    `host` MUST be harness loopback (127.0.0.1), never 0.0.0.0 or a victim/attacker-reachable interface.
    Every request must carry the per-experiment token. NEEDS A SECURITY REVIEW before production use."""
    import uvicorn

    app = build_env_action_app(registry, cfg, lock, require_token=True)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
