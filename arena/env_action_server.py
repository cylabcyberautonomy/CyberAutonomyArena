"""The defender→environment action channel: a UDS-only HTTP endpoint a RUNNING defender's
RemoteEnvOrchestrator (Defense repo) POSTs EnvActionRequest events to.

SECURITY (why a Unix domain socket, not a TCP port) — see the env_requests.py header and docs/
security-model.md. The adversary agent executes on an in-env VM (the foothold); this channel must be
reachable by the defender controller (a subprocess co-located on the harness host) yet UNREACHABLE by
any in-env VM. A UDS has no network port at all, so it is categorically unreachable from the
victim/attacker subnets regardless of how the public API is bound (uvicorn defaults to loopback, but a
manager launched with --host 0.0.0.0 would expose a TCP route — a UDS removes that failure mode
entirely). The transport IS the boundary, so there is deliberately NO authentication token here: a
token would be pure redundancy against a path nothing hostile can take. (Contrast the box-agent channel,
a TCP service INSIDE the environment, which keeps its token because it is reachable from in-env.) This
reasoning holds only while the channel stays a UDS; a move to TCP would require restoring a token.

SLICE 4 (the box model — see docs/agent-symmetry.md). A defender whose RUNNER executes in-env (on the
box, runs_on_box=True) cannot reach this UDS. serve_env_actions_tcp() serves the SAME app over a TCP port
bound to the box-facing interface, with the per-experiment token RESTORED (X-Arena-Token header, verified
in handle_env_action when trusted_transport=False against exp._env_action_token). The UDS path stays
token-free (trusted_transport=True) and unchanged. This deliberately moves the security boundary the
UDS gave for free, so: the TCP server MUST bind only to the isolated, attacker-invisible box subnet
(never 0.0.0.0), the token is required on every request and compared in constant time, and the whole
path NEEDS A SECURITY REVIEW before it is trusted in production.

The serving window + bounded primitive vocabulary remain — not as security layers but as correctness:
topology mutation is valid only while the attack runs (ACTIVATE..DEACTIVATE) and only for the primitives
within the defender's pre-reserved VM budget; each serviced event is recorded as experiment data.

The handler (handle_env_action) is kept pure and transport-free so it is unit-testable without sockets;
serve_env_actions wraps it in a tiny UDS-bound FastAPI/uvicorn server started from the arena lifespan.
"""
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
    """A fresh per-experiment token for the TCP control-plane channel (serve_env_actions_tcp). The arena
    generates one when it arms a runs_on_box defender, stamps it on exp._env_action_token, and threads it
    to the box runner so its RemoteEnvOrchestrator can authenticate. Unused by the UDS path."""
    return secrets.token_urlsafe(32)


def pick_free_tcp_port() -> int:
    """An ephemeral free TCP port on the harness (bind :0, read it, release). Used per-experiment for the
    loopback env-action TCP server, so concurrent experiments on one harness never collide."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_reverse_tunnel_cmd(box_access, box_port: int, tcp_port: int) -> list[str]:
    """PURE (unit-testable): the harness-initiated `ssh -R` command that exposes the harness's
    127.0.0.1:<tcp_port> env-action server as 127.0.0.1:<box_port> ON THE BOX — so a box-resident defender
    reaches the channel at box-loopback while the box→harness direction is never needed (mirrors Incalmo's
    harness→foothold ssh -L). Hardening (security review conditions):
      * EXPLICIT 127.0.0.1 bind on the box side of -R  -> loopback-only regardless of the box sshd's
        GatewayPorts; no victim/attacker/other-box-subnet host can reach the forwarded port.
      * EXACTLY ONE forward, no -D/-L/dynamic/SOCKS     -> the box can reach ONLY this one harness-loopback
        service through the tunnel, nothing else on harness loopback (e.g. not the Incalmo planner).
      * ExitOnForwardFailure=yes                        -> ssh exits non-zero if the forward can't bind,
        never a live ssh with no tunnel (the arm then fails loudly).
      * ServerAliveInterval/CountMax + -N (no shell)    -> a dead tunnel is detected; no remote command.
    `box_access` is the defender box's DefenderSetupAccess (scoped key + bastion routing); ssh_base()
    already carries -i <scoped key> and the bastion ProxyCommand."""
    base = box_access.ssh_base()  # ["ssh", -i key, ...opts..., proxycommand, user@host]
    opts = ["-N",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
            "-R", f"127.0.0.1:{box_port}:127.0.0.1:{tcp_port}"]
    return [base[0], *opts, *base[1:]]


async def open_reverse_tunnel(box_access, box_port: int, tcp_port: int,
                              log_path: "Optional[Path]" = None, confirm_s: float = 12.0):
    """Open the ssh -R tunnel (build_reverse_tunnel_cmd) and CONFIRM it came up, returning the live process
    (kept for the serving window). With ExitOnForwardFailure=yes + -N, ssh exits promptly iff the forward
    failed; so we wait up to confirm_s and raise if it exits (the arm fails, like a readiness gate). If it
    dies mid-run later, the defender's env-actions simply fail (acceptable degradation)."""
    cmd = build_reverse_tunnel_cmd(box_access, box_port, tcp_port)
    out = open(log_path, "a") if log_path else subprocess.DEVNULL
    proc = await asyncio.create_subprocess_exec(*cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                                                start_new_session=True)
    # ExitOnForwardFailure makes an early non-zero exit the failure signal; a healthy -N tunnel stays up.
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=confirm_s)
        raise RuntimeError(f"env-action reverse tunnel to the box failed to come up (ssh exited rc={rc}); "
                           f"check the box sshd AllowTcpForwarding — see {log_path}")
    except asyncio.TimeoutError:
        return proc  # still running after the grace window => the forward is established

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


async def handle_env_action(payload: dict, *, registry, cfg, lock=None,
                            token: Optional[str] = None, trusted_transport: bool = True) -> dict:
    """Authorize, budget-check, dispatch, and record ONE env-mutation event. Returns a plain dict with
    the EnvActionResult fields plus an internal "status" (HTTP status the transport should use, popped
    before the body is returned over the wire). Pure: no socket/transport here, so it is unit-testable.

    The serving-window state is read off the LIVE Experiment object (registry.get) that the run loop
    stamps: _env_serving, _env_budget_remaining, _env_lifecycle.

    TRANSPORT + TOKEN. `trusted_transport` is True for the UDS server (unreachable from in-env — the
    transport IS the boundary, so no token: historical behavior, unchanged). It is False for the TCP
    server (serve_env_actions_tcp, used by a box-resident defender): then `token` MUST match this
    experiment's _env_action_token (constant-time compare) or the call is rejected 403, before anything
    else runs. See the module docstring's SLICE 4 note + security-model.md."""
    from .environment import EnvActionKind, EnvActionRequest, EnvActionResult, EnvRequestUnsupported

    name = payload.get("experiment_name")
    action = payload.get("action") or {}

    # --- existence ---------------------------------------------------------
    try:
        exp = registry.get(name)
    except (KeyError, TypeError):
        return {"ok": False, "error": "unknown experiment", "status": 404}

    # --- token (untrusted/TCP transport only) ------------------------------
    # The UDS path is trusted (transport is the boundary); the TCP path must present this experiment's
    # token. Checked right after existence, before the serving window / validation / any dispatch.
    if not trusted_transport:
        expected = getattr(exp, "_env_action_token", None)
        if not expected or not token or not hmac.compare_digest(str(token), str(expected)):
            return {"ok": False, "error": "forbidden (bad or missing env-action token)", "status": 403}

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


def build_env_action_app(registry, cfg, lock, *, require_token: bool = False):
    """A tiny FastAPI app with the single action route. `require_token=False` (the UDS server) trusts the
    transport; `require_token=True` (the TCP server) marks the transport untrusted so handle_env_action
    verifies the X-Arena-Token header against the experiment's token."""
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
    """Run the UDS server until cancelled (started as a lifespan task). Removes a stale socket file first
    so a crashed prior manager doesn't block bind. Token-free (the transport is the boundary)."""
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
    """Serve the SAME env-action app over TCP, TOKEN-REQUIRED, for a defender whose runner executes in-env
    (on the box, runs_on_box=True) and so cannot reach the harness UDS.

    SECURITY (see the module docstring's SLICE 4 note): `host` MUST be the mgmt host's address on the
    isolated, attacker-invisible defender/box subnet — NEVER 0.0.0.0 or a victim/attacker-reachable
    interface. Every request must carry the per-experiment token (X-Arena-Token == exp._env_action_token),
    verified in constant time by handle_env_action. This restores the token the UDS design could omit
    because, once the channel is a reachable TCP port, the transport is no longer the boundary. NEEDS A
    SECURITY REVIEW before production use."""
    import uvicorn

    app = build_env_action_app(registry, cfg, lock, require_token=True)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()
