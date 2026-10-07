"""Run the Incalmo C2 server on the attacker's foothold, reached via a local ssh -L tunnel."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from ...env_spec import AttackerSetupAccess
from ....config import ExperimentManagerConfig
from ....experiment_log import attacker_log as log, init_attacker_logger as init_logger, output_root

logger = logging.getLogger(__name__)

_C2C_IMAGE = "incalmo/c2c:latest"
_C2_PORT = 8888
_STATE_DIR = Path("/tmp/mhbench-foothold-c2")
_built = False

STARTUP_TIMEOUT = 60
AGENT_BEACON_TIMEOUT = 600
POLL_INTERVAL = 2


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _ctl_path(experiment_name: str) -> str:
    """Per-experiment ControlPath socket for the shared bastion+foothold master connection."""
    name = experiment_name
    if len(name) > 40:
        import hashlib
        name = hashlib.sha1(name.encode()).hexdigest()[:24]
    return str(_STATE_DIR / f"cm-{name}")


def _ssh_to_foothold(access: AttackerSetupAccess, ctl: str | None = None) -> list[str]:
    """Build the ssh argv that reaches the foothold with the scoped key and env-owned routing. `ctl` multiplexes over one master."""
    args = ["ssh"]
    if access.ssh_key:
        args += ["-i", os.path.expanduser(access.ssh_key)]
    args += [
        "-p", str(access.port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
    ]
    if ctl:
        args += ["-o", "ControlMaster=auto", "-o", f"ControlPath={ctl}", "-o", "ControlPersist=120"]
    if access.ssh_common_args:
        args += shlex.split(access.ssh_common_args)
    args += [f"{access.user}@{access.host}"]
    return args


def _close_master(access: AttackerSetupAccess, ctl: str) -> None:
    """Tear down the shared master connection (best-effort) and remove its socket."""
    try:
        subprocess.run(_ssh_to_foothold(access, ctl) + ["-O", "exit"],
                       timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        os.unlink(ctl)
    except OSError:
        pass


def _ensure_image_built_sync(cfg, incalmo_dir) -> None:
    """Build incalmo/c2c on the harness host (once per process) so it can be shipped to foothold."""
    global _built
    if _built:
        return
    logger.info("[foothold-c2] building C2 image %s on the harness host", _C2C_IMAGE)
    subprocess.run(
        ["docker", "build", "-t", _C2C_IMAGE, "-f", "docker/c2server/Dockerfile", "."],
        cwd=str(incalmo_dir), check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=1800,
    )
    _built = True


def _free_local_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def setup_c2(experiment_name: str, cfg, access: AttackerSetupAccess, bastion_ip: str | None = None, incalmo_dir=None) -> tuple[str, str, str]:
    """Run the C2 on the foothold and open a tunnel to it. Return (sentinel, remote_url, local_url)."""
    if access is None or not access.host:
        raise RuntimeError(f"[foothold-c2] need a foothold AttackerSetupAccess with a host (got {access!r})")
    foothold_ip = access.host
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    ctl = _ctl_path(experiment_name)
    ssh = _ssh_to_foothold(access, ctl)
    ssh_plain = _ssh_to_foothold(access)
    _close_master(access, ctl)

    _ensure_image_built_sync(cfg, incalmo_dir)

    last_err = ""
    for attempt in range(45):
        proc = subprocess.run(ssh_plain + ["true"], capture_output=True, text=True)
        if proc.returncode == 0:
            if attempt:
                logger.info("[foothold-c2] foothold %s reachable via %s after %d failed attempt(s)",
                            foothold_ip, bastion_ip, attempt)
            break
        last_err = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
        if attempt == 0 or attempt % 6 == 5:
            logger.warning("[foothold-c2] poll foothold %s via %s attempt %d/45 rc=%d: %s",
                           foothold_ip, bastion_ip, attempt + 1, proc.returncode,
                           last_err[:250] or "(no stderr)")
        time.sleep(10)
    else:
        raise RuntimeError(
            f"[foothold-c2] SSH to foothold {foothold_ip} (via bastion {bastion_ip}) never came up; "
            f"last ssh error: {last_err[:300] or '(none captured)'}")

    for m in range(6):
        mo = subprocess.run(ssh + ["true"], capture_output=True, text=True)
        if mo.returncode == 0:
            break
        logger.warning("[foothold-c2] master-open to foothold %s via %s try %d/6 rc=%d: %s",
                       foothold_ip, bastion_ip, m + 1, mo.returncode,
                       (mo.stderr or "").strip().replace("\n", " ")[:200] or "(no stderr)")
        _close_master(access, ctl)
        time.sleep(5)

    logger.info("[foothold-c2] ensuring docker on foothold %s", foothold_ip)
    subprocess.run(ssh + [
        "export DEBIAN_FRONTEND=noninteractive; command -v docker >/dev/null || "
        "(apt-get -qq update && apt-get -y -qq install docker.io && systemctl enable --now docker)"],
        check=True, timeout=600)

    logger.info("[foothold-c2] shipping %s to foothold", _C2C_IMAGE)
    save = subprocess.Popen(["docker", "save", _C2C_IMAGE], stdout=subprocess.PIPE)
    gz = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=subprocess.PIPE)
    subprocess.run(ssh + ["gunzip | docker load"], stdin=gz.stdout, check=True, timeout=900)
    save.wait(); gz.wait()

    incalmo_dir = Path(incalmo_dir)
    tar = subprocess.Popen(
        ["tar", "czf", "-", "--exclude=.git", "--exclude=.venv", "--exclude=.venv-c2c",
         "--exclude=incalmo/frontend", "--exclude=output", "--exclude=__pycache__",
         "--exclude=incalmo/c2server/payloads/dynamic_payload_*.sh",
         "-C", str(incalmo_dir.parent), incalmo_dir.name], stdout=subprocess.PIPE)
    subprocess.run(ssh + [
        "rm -rf /incalmo && mkdir -p /incalmo && tar xzf - -C /incalmo --strip-components=1"],
        stdin=tar.stdout, check=True, timeout=900)
    tar.wait()

    subprocess.run(ssh + [
        f"docker rm -f c2 >/dev/null 2>&1; docker run -d --name c2 -p 0.0.0.0:{_C2_PORT}:{_C2_PORT} "
        f"-v /incalmo:/incalmo -e UV_PROJECT_ENVIRONMENT=/incalmo/.venv-c2c {_C2C_IMAGE}"],
        check=True, timeout=180)

    _close_master(access, ctl)

    local_port = _free_local_port()
    ssh_tunnel = [
        "ssh", "-N", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=6", "-o", "TCPKeepAlive=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
        "-p", str(access.port),
    ]
    if access.ssh_key:
        ssh_tunnel += ["-i", os.path.expanduser(access.ssh_key)]
    if access.ssh_common_args:
        ssh_tunnel += shlex.split(access.ssh_common_args)
    ssh_tunnel += [
        "-L", f"127.0.0.1:{local_port}:{foothold_ip}:{_C2_PORT}",
        f"{access.user}@{access.host}",
    ]
    supervisor = "while true; do " + " ".join(shlex.quote(a) for a in ssh_tunnel) + "; sleep 2; done"
    tunnel = subprocess.Popen(["bash", "-c", supervisor],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    _statefile(experiment_name).write_text(json.dumps({
        "tunnel_pid": tunnel.pid, "foothold_ip": foothold_ip, "mgmt_ip": bastion_ip, "local_port": local_port,
        "access": access.model_dump(),
    }))
    logger.info("[foothold-c2] resilient tunnel supervisor pid=%s 127.0.0.1:%s -> %s:%s (via %s)",
                tunnel.pid, local_port, foothold_ip, _C2_PORT, bastion_ip)

    url = f"http://127.0.0.1:{local_port}/agents"
    for _ in range(48):
        try:
            urllib.request.urlopen(url, timeout=5).read()
            logger.info("[foothold-c2] C2 serving via tunnel at %s", url)
            break
        except Exception:
            time.sleep(5)
    else:
        raise RuntimeError(f"[foothold-c2] C2 never served on {url} (container/tunnel not ready)")

    return (f"foothold-c2:{experiment_name}",
            f"http://{foothold_ip}:{_C2_PORT}",
            f"http://127.0.0.1:{local_port}")


def _kill_pid(pid: int) -> None:
    """Kill the tunnel by its process group (SIGTERM then SIGKILL), falling back to a single-pid kill."""
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
        time.sleep(0.2)


def teardown_c2(experiment_name: str, cfg=None) -> None:
    """Kill the harness-host tunnel and remove the C2 container on foothold. Never raises."""
    sf = _statefile(experiment_name)
    state = {}
    try:
        state = json.loads(sf.read_text())
    except Exception:
        pass
    pid = state.get("tunnel_pid")
    if isinstance(pid, int):
        _kill_pid(pid)
    acc = state.get("access")
    if acc:
        try:
            access = AttackerSetupAccess.model_validate(acc)
            ssh = _ssh_to_foothold(access)
            subprocess.run(ssh + ["docker rm -f c2 >/dev/null 2>&1 || true"],
                           timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("[foothold-c2] teardown docker rm on foothold %s: %s", state.get("foothold_ip"), e)
    try:
        os.unlink(_ctl_path(experiment_name))
    except OSError:
        pass
    try:
        sf.unlink()
    except Exception:
        pass


def sweep_stale_tunnels() -> None:
    """Reap orphaned tunnels from a crashed prior manager: kill any recorded tunnel pid whose
    /proc cmdline still looks like our ssh -L, then drop the statefile."""
    if not _STATE_DIR.exists():
        return
    for sf in _STATE_DIR.glob("*.json"):
        try:
            state = json.loads(sf.read_text())
            pid = state.get("tunnel_pid")
            if isinstance(pid, int):
                try:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
                except Exception:
                    cmdline = ""
                if "-L 127.0.0.1:" in cmdline and f":{_C2_PORT}" in cmdline:
                    _kill_pid(pid)
            sf.unlink()
        except Exception:
            logger.exception("[foothold-c2] sweep of %s failed", sf)


async def start_c2c_server(
    experiment_name: str, cfg: ExperimentManagerConfig, bastion_ip: str | None = None, foothold_access=None,
    incalmo_dir=None,
) -> tuple[str, str, str]:
    """Start the Incalmo C2 on the foothold. Return (sentinel, remote_url, local_url)."""
    init_logger(experiment_name, output_root(experiment_name, cfg))
    if foothold_access is None:
        raise RuntimeError(
            "the Incalmo C2 runs on the attacker foothold, but no foothold AttackerSetupAccess "
            "(scoped key + routing) was passed to start_c2c_server()")
    loop = asyncio.get_event_loop()
    sentinel, remote_url, local_url = await loop.run_in_executor(
        None, setup_c2, experiment_name, cfg, foothold_access, bastion_ip, incalmo_dir)
    log(experiment_name, f"C2 on foothold: agents -> {remote_url}, harness (tunnel) -> {local_url}")
    return sentinel, remote_url, local_url


async def stop_c2c_server(experiment_name: str) -> None:
    """Tear down the foothold C2: kill the tunnel and remove the container. Never raises."""
    if not experiment_name:
        return
    await asyncio.get_event_loop().run_in_executor(None, teardown_c2, experiment_name, None)


async def wait_for_c2c_ready(c2c_url: str, experiment_name: str) -> None:
    """Poll until the C2 server is responding to HTTP requests."""
    log(experiment_name, "Waiting for C2 server to be ready...")
    await _wait_until_ready(c2c_url)
    log(experiment_name, f"C2 server ready at {c2c_url}")


async def wait_for_agent(local_c2c_url: str, experiment_name: str) -> None:
    """Poll until at least one sandcat agent beacons to the C2 server."""
    log(experiment_name, "Waiting for sandcat agent to beacon...")
    parsed = urlparse(local_c2c_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port
    deadline = asyncio.get_event_loop().time() + AGENT_BEACON_TIMEOUT
    polls = 0
    while asyncio.get_event_loop().time() < deadline:
        polls += 1
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=8)
            writer.write(b"GET /agents HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            await writer.drain()
            chunks = []
            while True:
                c = await asyncio.wait_for(reader.read(65536), timeout=8)
                if not c:
                    break
                chunks.append(c)
            response = b"".join(chunks)
            writer.close()
            await writer.wait_closed()
            _, _, body = response.partition(b"\r\n\r\n")
            agents = json.loads(body) if body.strip() else []
            if agents:
                log(experiment_name, f"Agent beaconed — {len(agents)} agent(s) registered (after {polls} polls).")
                return
            if polls % 6 == 0:
                log(experiment_name, f"...still waiting for agent beacon at {host}:{port} (poll {polls}, 0 agents)")
        except Exception as e:
            if polls % 6 == 0:
                log(experiment_name, f"...agent poll {polls} to {host}:{port} failed: {type(e).__name__}: {e}")
        await asyncio.sleep(POLL_INTERVAL)
    raise TimeoutError(f"No sandcat agent beaconed within {AGENT_BEACON_TIMEOUT}s")


async def _wait_until_ready(c2c_url: str) -> None:
    parsed = urlparse(c2c_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port
    deadline = asyncio.get_event_loop().time() + STARTUP_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            writer.write(b"GET /agents HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(12), timeout=2)
            writer.close()
            await writer.wait_closed()
            if response.startswith(b"HTTP/"):
                return
        except Exception:
            pass
        await asyncio.sleep(POLL_INTERVAL)
    raise TimeoutError(f"C2 server at {c2c_url} did not become ready within {STARTUP_TIMEOUT}s")
