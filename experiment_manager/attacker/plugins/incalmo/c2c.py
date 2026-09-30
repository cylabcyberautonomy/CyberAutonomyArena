from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse

from ....config import ExperimentManagerConfig
from ....experiment_log import attacker_log as log, init_attacker_logger as init_logger, output_root

logger = logging.getLogger(__name__)

STARTUP_TIMEOUT = 60
AGENT_BEACON_TIMEOUT = 600  # the first beacon can lag (image ship + container first boot); wide margin
POLL_INTERVAL = 2


async def start_c2c_server(
    experiment_name: str, cfg: ExperimentManagerConfig, mgmt_ip: str | None = None, foothold_access=None,
) -> tuple[str, str, str]:
    """Bring up the Incalmo C2 on the attacker's foothold and return once it is serving.

    The C2 always runs on the foothold the environment provides (reached via the harness-only
    SetupAccess); the attacker holds no backend/topology knowledge. See foothold_c2.

    Returns (sentinel, remote_url, local_url):
      sentinel   — stored as the C2 container id; routes teardown back to foothold_c2.
      remote_url — the foothold's in-env address the sandcat agents / setup play beacon to.
      local_url  — the 127.0.0.1 ssh -L tunnel the attacker LLM (on the harness host) uses.
    """
    init_logger(experiment_name, output_root(experiment_name, cfg))
    if foothold_access is None:
        raise RuntimeError(
            "the Incalmo C2 runs on the attacker foothold, but no foothold SetupAccess "
            "(scoped key + routing) was passed to start_c2c_server()")
    from . import foothold_c2
    loop = asyncio.get_event_loop()
    sentinel, remote_url, local_url = await loop.run_in_executor(
        None, foothold_c2.setup_c2, experiment_name, cfg, foothold_access, mgmt_ip)
    log(experiment_name, f"C2 on foothold: agents -> {remote_url}, harness (tunnel) -> {local_url}")
    return sentinel, remote_url, local_url


async def stop_c2c_server(container_id: str) -> None:
    """Tear down the foothold C2 (kill the tunnel + remove the remote container). Never raises."""
    if not container_id:
        return
    from . import foothold_c2
    exp = container_id.split(":", 1)[1] if ":" in container_id else container_id
    await asyncio.get_event_loop().run_in_executor(None, foothold_c2.teardown_c2, exp, None)


async def wait_for_c2c_ready(c2c_url: str, experiment_name: str) -> None:
    """Poll until the C2 server is responding to HTTP requests."""
    log(experiment_name, "Waiting for C2 server to be ready...")
    await _wait_until_ready(c2c_url)
    log(experiment_name, f"C2 server ready at {c2c_url}")


async def wait_for_agent(local_c2c_url: str, experiment_name: str) -> None:
    """Poll until at least one sandcat agent has beaconed to the C2 server."""
    log(experiment_name, "Waiting for sandcat agent to beacon...")
    parsed = urlparse(local_c2c_url)
    host, port = parsed.hostname or "127.0.0.1", parsed.port  # the C2 is reached over the local ssh -L tunnel
    deadline = asyncio.get_event_loop().time() + AGENT_BEACON_TIMEOUT
    polls = 0
    while asyncio.get_event_loop().time() < deadline:
        polls += 1
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=8)
            writer.write(b"GET /agents HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            await writer.drain()
            # read to EOF (HTTP/1.0 closes after body) so we never parse a truncated response
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
    host, port = parsed.hostname or "127.0.0.1", parsed.port  # the C2 is reached over the local ssh -L tunnel
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
