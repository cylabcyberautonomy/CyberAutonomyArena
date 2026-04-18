import asyncio
import logging

import aiohttp

from .config import ExperimentManagerConfig

logger = logging.getLogger(__name__)

STARTUP_TIMEOUT = 60  # seconds to wait for C2 server to be ready
POLL_INTERVAL = 2


def _container_name(experiment_name: str) -> str:
    return f"incalmo-c2c-{experiment_name}"


async def build_c2c_image(cfg: ExperimentManagerConfig) -> None:
    """Build the C2 server Docker image from the experiment_harness Dockerfile."""
    logger.info("Building C2 server image '%s'...", cfg.c2c_image_tag)
    proc = await asyncio.create_subprocess_exec(
        "docker", "build",
        "-t", cfg.c2c_image_tag,
        str(cfg.c2c_dockerfile_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to build C2 image: {stderr.decode().strip()}")
    logger.info("C2 server image built successfully.")


async def start_c2c_server(experiment_name: str, cfg: ExperimentManagerConfig) -> tuple[str, str]:
    """
    Start the C2 server as a Docker container with a dynamic host port.
    Returns (container_id, c2c_url).
    """
    name = _container_name(experiment_name)

    proc = await asyncio.create_subprocess_exec(
        "docker", "run", "-d",
        "--name", name,
        "-p", "127.0.0.1::8888",
        cfg.c2c_image_tag,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to start C2 container: {stderr.decode().strip()}")

    container_id = stdout.decode().strip()
    port = await _get_mapped_port(name)
    url = f"http://127.0.0.1:{port}"

    await _wait_until_ready(url)
    logger.info("C2 server ready for '%s' at %s", experiment_name, url)
    return container_id, url


async def stop_c2c_server(container_id: str) -> None:
    """Stop and remove the C2 server container."""
    for action in ("stop", "rm"):
        proc = await asyncio.create_subprocess_exec(
            "docker", action, container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()


async def _get_mapped_port(container_name: str) -> int:
    proc = await asyncio.create_subprocess_exec(
        "docker", "port", container_name, "8888",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    # output format: "127.0.0.1:XXXXX"
    return int(stdout.decode().strip().split(":")[-1])


async def _wait_until_ready(url: str) -> None:
    deadline = asyncio.get_event_loop().time() + STARTUP_TIMEOUT
    async with aiohttp.ClientSession() as session:
        while asyncio.get_event_loop().time() < deadline:
            try:
                async with session.get(f"{url}/agents", timeout=aiohttp.ClientTimeout(total=2)):
                    return
            except Exception:
                await asyncio.sleep(POLL_INTERVAL)
    raise TimeoutError(f"C2 server at {url} did not become ready within {STARTUP_TIMEOUT}s")
