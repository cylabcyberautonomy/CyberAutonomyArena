from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

from ....config import ExperimentManagerConfig
from ....experiment_log import attacker_log as log, init_attacker_logger as init_logger, output_root

logger = logging.getLogger(__name__)

STARTUP_TIMEOUT = 60
AGENT_BEACON_TIMEOUT = 300
POLL_INTERVAL = 2

_C2C_IMAGE = "incalmo/c2c:latest"
_built_images: set[str] = set()
# Serialises all Docker container start/stop operations so that concurrent
# iptables rule additions/removals cannot race and leave port mappings broken.
_docker_lock = asyncio.Lock()


def _container_name(experiment_name: str) -> str:
    return f"incalmo-c2c-{experiment_name}"


async def _ensure_image_built(experiment_name: str, cfg: ExperimentManagerConfig) -> None:
    if _C2C_IMAGE in _built_images:
        return
    log(experiment_name, f"Building C2 image '{_C2C_IMAGE}'...")
    proc = await asyncio.create_subprocess_exec(
        "docker", "build",
        "-t", _C2C_IMAGE,
        "-f", "docker/c2server/Dockerfile",
        ".",
        cwd=str(cfg.incalmo_dir),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to build C2 image: {stderr.decode().strip()}")
    _built_images.add(_C2C_IMAGE)
    log(experiment_name, f"Built '{_C2C_IMAGE}' successfully.")


async def start_c2c_server(experiment_name: str, cfg: ExperimentManagerConfig) -> tuple[str, str, str]:
    """
    Launch the Incalmo C2 Docker container and return immediately.
    Returns (container_id, kali_url, local_url) — container may not be ready yet.
    kali_url uses cfg.host_ip and is reachable from VMs.
    local_url uses 127.0.0.1 and is reachable from this host.
    Call wait_for_c2c_ready(local_url) after saving container_id to the registry.
    """
    init_logger(experiment_name, output_root(experiment_name, cfg))
    await _ensure_image_built(experiment_name, cfg)
    name = _container_name(experiment_name)

    # Hold the lock for the rm→run→port-query sequence so that concurrent experiment
    # launches cannot race on Docker iptables rule insertion / port mapping. (Each C2's
    # state_store.db is now container-local — /tmp — so there is no shared DB to clobber.)
    async with _docker_lock:
        cleanup = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await cleanup.wait()

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "--name", name,
            "-p", "0.0.0.0::8888",
            "-v", f"{cfg.incalmo_dir}:/incalmo",
            # Build the container's uv env in a container-specific dir, NOT the
            # repo's shared .venv. The mount is shared with the host, whose attacker
            # process runs under <incalmo_dir>/.venv/bin/python; if the container (root,
            # different interpreter path) wrote .venv it would break the host venv.
            # Separate paths let both persist, cached, in the mount.
            "-e", "UV_PROJECT_ENVIRONMENT=/incalmo/.venv-c2c",
            _C2C_IMAGE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to start C2 container: {stderr.decode().strip()}")

        container_id = stdout.decode().strip()
        port = await _get_mapped_port(name)

    kali_url = f"http://{cfg.host_ip}:{port}"
    local_url = f"http://127.0.0.1:{port}"
    log(experiment_name, f"C2 container started at {kali_url}")
    return container_id, kali_url, local_url


async def stop_c2c_server(container_id: str) -> None:
    """Force-kill and remove the C2 container. `rm -f` (SIGKILL) skips `docker stop`'s 10s SIGTERM grace —
    these are throwaway containers, and on shutdown they're stopped one-by-one, so that grace × N was
    minutes of dead time before the host teardown could even start."""
    async with _docker_lock:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()


async def wait_for_c2c_ready(c2c_url: str, experiment_name: str) -> None:
    """Poll until the C2 server is responding to HTTP requests."""
    log(experiment_name, "Waiting for C2 server to be ready...")
    await _wait_until_ready(c2c_url)
    log(experiment_name, f"C2 server ready at {c2c_url}")


async def wait_for_agent(local_c2c_url: str, experiment_name: str) -> None:
    """Poll until at least one sandcat agent has beaconed to the C2 server."""
    log(experiment_name, "Waiting for sandcat agent to beacon...")
    parsed = urlparse(local_c2c_url)
    host, port = "127.0.0.1", parsed.port
    deadline = asyncio.get_event_loop().time() + AGENT_BEACON_TIMEOUT
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2)
            writer.write(b"GET /agents HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=2)
            writer.close()
            await writer.wait_closed()
            _, _, body = response.partition(b"\r\n\r\n")
            agents = json.loads(body) if body.strip() else []
            if agents:
                log(experiment_name, f"Agent beaconed — {len(agents)} agent(s) registered.")
                return
        except Exception:
            pass
        await asyncio.sleep(POLL_INTERVAL)
    raise TimeoutError(f"No sandcat agent beaconed within {AGENT_BEACON_TIMEOUT}s")


async def _get_mapped_port(container_name: str) -> int:
    proc = await asyncio.create_subprocess_exec(
        "docker", "port", container_name, "8888",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return int(stdout.decode().strip().split(":")[-1])


async def _wait_until_ready(c2c_url: str) -> None:
    parsed = urlparse(c2c_url)
    host, port = "127.0.0.1", parsed.port
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
