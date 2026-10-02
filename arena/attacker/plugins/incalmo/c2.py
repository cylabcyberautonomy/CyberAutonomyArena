"""Run the Incalmo C2 server on the attacker's foothold.

The C2 runs on the foothold the environment hands the attacker (the box it already operates from),
reached only through the env-provided SetupAccess — its scoped attacker key and opaque bastion/relay
routing. The attacker needs no knowledge of the backend, the harness host, or the topology:
  - setup ships the incalmo/c2c image + the Incalmo tree to the foothold and runs the container
    there, bound to :8888 on the foothold's own in-env address;
  - victims / sandcat agents beacon to that in-env address (the environment opens victim -> foothold
    ingress at deploy time, so no port is declared here);
  - the attacker LLM (on the harness host, which has no in-env address) reaches the C2 through an
    `ssh -L` tunnel opened over the same SetupAccess routing (local 127.0.0.1:<port> -> foothold:8888).

Running the C2 on the foothold — rather than on a host the attacker shares with harness/telemetry
services — keeps all attacker infrastructure on one in-env IP, so a defender can block the whole C2
without collateral. No management key is ever read off disk.

Two layers: the sync setup/teardown (ssh + docker, the bulk of this module) does the heavy lifting;
the async interface at the bottom (start_c2c_server / stop_c2c_server / wait_*) is what the plugin
calls — it runs the sync work in an executor and polls the C2 over the local tunnel.
"""
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

from ...env_spec import SetupAccess
from ....config import ExperimentManagerConfig
from ....experiment_log import attacker_log as log, init_attacker_logger as init_logger, output_root

logger = logging.getLogger(__name__)

_C2C_IMAGE = "incalmo/c2c:latest"
_C2_PORT = 8888
_STATE_DIR = Path("/tmp/mhbench-foothold-c2")
_built = False

# async-interface tunables (readiness / first-beacon polling over the local ssh -L tunnel)
STARTUP_TIMEOUT = 60
AGENT_BEACON_TIMEOUT = 600  # the first beacon can lag (image ship + container first boot); wide margin
POLL_INTERVAL = 2


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _ctl_path(experiment_name: str) -> str:
    """Per-experiment ControlPath socket for the shared bastion+foothold master connection.
    MUST be per-experiment: every topology's foothold is 192.168.202.100/root, so an ssh %%C-style
    path (keyed on remote host+user) would COLLIDE across concurrent experiments and try to share
    one master to different bastions. Hash long names to stay under the AF_UNIX ~108-char limit."""
    name = experiment_name
    if len(name) > 40:
        import hashlib
        name = hashlib.sha1(name.encode()).hexdigest()[:24]
    return str(_STATE_DIR / f"cm-{name}")


def _ssh_to_foothold(access: SetupAccess, ctl: str | None = None) -> list[str]:
    """ssh argv reaching the foothold (foothold) as the env-granted principal, using the SCOPED key +
    env-owned routing carried by the SetupAccess. We never read a management key off disk or build our
    own ProxyCommand: `access.ssh_key` is the foothold-scoped key and `access.ssh_common_args` carries
    the env's bastion/relay routing (a ProxyCommand with a forward-only jump credential, and its own
    /dev/null known_hosts handling on the jump — so recycled-FIP stale bastion keys can't reject us).

    When `ctl` is given, all invocations sharing that ControlPath multiplex over ONE master
    connection: the master carries the end-to-end foothold session tunnelled through the bastion, so
    the bastion hop is made exactly once (on first open) and every later poll/docker/ship/run call
    rides it instead of opening a fresh bastion connection. Under peak-concurrency batches the
    shared FIP/L3 path black-holes *new* connections to a bastion's floating IP for stretches
    (proven: 30 fresh poll connects all dropped while multiplexed ansible traffic got through), so
    collapsing foothold_c2's ~5 fresh connects down to one both removes the post-poll failure points
    and cuts foothold_c2's own contribution to the connection storm."""
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
        args += shlex.split(access.ssh_common_args)  # env-owned bastion/relay routing (ProxyCommand)
    args += [f"{access.user}@{access.host}"]
    return args


def _close_master(access: SetupAccess, ctl: str) -> None:
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


def _ensure_image_built_sync(cfg) -> None:
    """Build incalmo/c2c on the harness host (once per process) so it can be shipped to foothold."""
    global _built
    if _built:
        return
    logger.info("[foothold-c2] building C2 image %s on the harness host", _C2C_IMAGE)
    subprocess.run(
        ["docker", "build", "-t", _C2C_IMAGE, "-f", "docker/c2server/Dockerfile", "."],
        cwd=str(cfg.incalmo_dir), check=True,
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


def setup_c2(experiment_name: str, cfg, access: SetupAccess, bastion_ip: str | None = None) -> tuple[str, str, str]:
    """Run the C2 on the foothold and open a tunnel to it for the attacker LLM. Reaches the foothold
    only via the env-provided SetupAccess (scoped key + bastion routing) — never a management key off
    disk. `bastion_ip` is accepted for log messages only; the routing is opaque in access.ssh_common_args.
    Returns (sentinel, remote_url, local_url):
      sentinel  = "foothold-c2:<exp>"       (legacy handle; teardown is keyed by experiment_name)
      remote_url= http://<foothold>:8888    (in-env address sandcat agents / the setup play beacon to)
      local_url = http://127.0.0.1:<port>   (harness host: readiness polls + attacker LLM, via ssh -L)
    """
    if access is None or not access.host:
        raise RuntimeError(f"[foothold-c2] need a foothold SetupAccess with a host (got {access!r})")
    foothold_ip = access.host
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    ctl = _ctl_path(experiment_name)
    ssh = _ssh_to_foothold(access, ctl)                            # steps 2-5 multiplex over one master
    ssh_plain = _ssh_to_foothold(access)                           # poll: NO ControlMaster (see step 1)
    # A stale/dead ControlPath master from a prior attempt of the SAME experiment (retries reuse the
    # name) poisons every future ControlMaster=auto connect — the "ControlSocket already exists" race
    # that dies as "Connection closed by UNKNOWN port 65535". REAP it (ssh -O exit + unlink), not just
    # unlink the socket file: a half-open master PROCESS would otherwise linger holding the path.
    _close_master(access, ctl)

    _ensure_image_built_sync(cfg)

    # 1. Wait for foothold to be SSH-reachable through the bastion, using a PLAIN (non-multiplexed) ssh.
    #    Decoupled from the ControlMaster deliberately: the old poll ran ControlMaster=auto, so its FIRST
    #    attempt had to WIN the master-open race through the ProxyJump — under peak-concurrency contention
    #    that lost and died as "Connection closed by UNKNOWN port 65535" (captured live), and once a
    #    half-open socket was left behind EVERY later attempt reused the dead master and failed the same
    #    way -> all 45 fast-reject -> "never came up". A plain connect has no master to race and no socket
    #    to poison, so the poll now measures true reachability; the master is opened once, after, in step 1b.
    #    CAPTURE each failure's raw ssh stderr. (The old direct-bastion hop-attribution probe was removed
    #    with the god-key: the foothold-scoped key can only reach foothold, not open a shell on the bastion.)
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

    # 1b. Reachability confirmed — now open the shared ControlMaster EXPLICITLY (a plain `ssh -o ...ctl true`
    #     that foothold is known-reachable for), retrying a few times and clearing any half-open socket between
    #     tries, so steps 2-5 (which run check=True and would otherwise abort on a transient master-open
    #     race) ride a proven master instead of racing to create it on their first call.
    for m in range(6):
        mo = subprocess.run(ssh + ["true"], capture_output=True, text=True)
        if mo.returncode == 0:
            break
        logger.warning("[foothold-c2] master-open to foothold %s via %s try %d/6 rc=%d: %s",
                       foothold_ip, bastion_ip, m + 1, mo.returncode,
                       (mo.stderr or "").strip().replace("\n", " ")[:200] or "(no stderr)")
        _close_master(access, ctl)  # reap the failed/half-open master before retrying
        time.sleep(5)

    # 2. Install docker on foothold if missing (foothold has apt egress + foothold repos; docker not baked).
    logger.info("[foothold-c2] ensuring docker on foothold %s", foothold_ip)
    subprocess.run(ssh + [
        "export DEBIAN_FRONTEND=noninteractive; command -v docker >/dev/null || "
        "(apt-get -qq update && apt-get -y -qq install docker.io && systemctl enable --now docker)"],
        check=True, timeout=600)

    # 3. Ship the image (docker save | gzip | ssh 'gunzip | docker load').
    logger.info("[foothold-c2] shipping %s to foothold", _C2C_IMAGE)
    save = subprocess.Popen(["docker", "save", _C2C_IMAGE], stdout=subprocess.PIPE)
    gz = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=subprocess.PIPE)
    subprocess.run(ssh + ["gunzip | docker load"], stdin=gz.stdout, check=True, timeout=900)
    save.wait(); gz.wait()

    # 4. Ship /incalmo, PLUS the C2's dynamic-payload dir. That dir accumulates a `dynamic_payload_*.sh`
    #    per tasking across ALL prior runs and is NEVER cleaned; the C2 + /incalmo live on the foothold
    #    box where the attacker has a
    #    shell, so shipping it lets the attacker READ every prior run's payloads — other envs' host IPs,
    #    exfil targets, decoy layouts, honey creds (proven: k3_sh_chpe_c2b_t1's shell attacker grep'd
    #    /incalmo and surfaced old StaticLayeredAll decoy/honey payloads → cross-run info leak +
    #    phantom "decoy interactions"). Exclude ONLY the generated `dynamic_payload_*.sh` files — NOT the
    #    whole payloads dir, which also holds the agent-deploy tooling (sandcat.go, downloadAgent.sh,
    #    runDeployAgent.sh, template_payloads/) that the C2's /agent/download endpoint needs; dropping
    #    those breaks agent deployment ("No sandcat agent beaconed within 600s"). So the foothold C2 keeps its
    #    tooling but starts with no stale generated payloads, and only writes its OWN run's at runtime.
    incalmo_dir = Path(cfg.incalmo_dir)
    tar = subprocess.Popen(
        ["tar", "czf", "-", "--exclude=.git", "--exclude=.venv", "--exclude=.venv-c2c",
         "--exclude=incalmo/frontend", "--exclude=output", "--exclude=__pycache__",
         "--exclude=incalmo/c2server/payloads/dynamic_payload_*.sh",
         "-C", str(incalmo_dir.parent), incalmo_dir.name], stdout=subprocess.PIPE)
    subprocess.run(ssh + [
        "rm -rf /incalmo && mkdir -p /incalmo && tar xzf - -C /incalmo --strip-components=1"],
        stdin=tar.stdout, check=True, timeout=900)
    tar.wait()

    # 5. Run the C2 container on foothold, bound to 8888 on all interfaces (in-tenant reachable).
    subprocess.run(ssh + [
        f"docker rm -f c2 >/dev/null 2>&1; docker run -d --name c2 -p 0.0.0.0:{_C2_PORT}:{_C2_PORT} "
        f"-v /incalmo:/incalmo -e UV_PROJECT_ENVIRONMENT=/incalmo/.venv-c2c {_C2C_IMAGE}"],
        check=True, timeout=180)

    # Setup ops done — close the shared master. The tunnel below is deliberately its OWN
    # long-lived connection (independent lifecycle: killed by recorded pid on teardown), not
    # multiplexed over the master, so it must not depend on the master staying alive.
    _close_master(access, ctl)

    # 6. Open the harness-host->foothold tunnel (foothold has no FIP), wrapped in a RESILIENT auto-reconnect
    #    supervisor. The bastion/FIP path saturates under concurrent configure/collect handshake
    #    bursts; a bare `ssh -L` then loses its keepalives and EXITS, the local forward vanishes, and
    #    the attacker's next C2 call gets "Connection refused" -> the run dies AFTER doing all the
    #    expensive attack work (observed: 8 runs killed this way). Two hardenings: (a) ServerAliveCountMax
    #    3 -> 6 (30s interval) so the tunnel rides out ~3min blips WITHOUT dropping; (b) a
    #    `while true; do ssh ...; sleep 2; done` supervisor that re-establishes the forward within ~2s
    #    if ssh ever does exit — the attacker's HTTP client retries bridge the gap. Popen(start_new_session)
    #    makes the bash the process-GROUP leader; teardown/sweep kill the whole group (see _kill_pid) so
    #    both the loop and its child ssh die.
    local_port = _free_local_port()
    # Reuse the env-owned routing (access.ssh_common_args) for the tunnel too — its ProxyCommand handles
    # the bastion hop + the recycled-FIP stale-key trap (/dev/null on the jump); a reconnecting tunnel
    # must not get rejected by a stale key. Same scoped key as every other reach to the foothold.
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
        ssh_tunnel += shlex.split(access.ssh_common_args)  # env-owned bastion/relay routing
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
        "access": access.model_dump(),  # so teardown reaches foothold with the same scoped key + routing, no disk read
    }))
    logger.info("[foothold-c2] resilient tunnel supervisor pid=%s 127.0.0.1:%s -> %s:%s (via %s)",
                tunnel.pid, local_port, foothold_ip, _C2_PORT, bastion_ip)

    # 7. Wait until the C2 serves through the tunnel (first boot runs `uv sync`; give ~4 min).
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
    """Kill the tunnel by its process GROUP — it's a bash auto-reconnect supervisor + child ssh in
    one session (start_new_session), so killpg reaps both; a plain os.kill(pid) would leave the
    child ssh (and its live forward) orphaned. SIGTERM then SIGKILL; falls back to a single-pid kill
    if the group lookup fails. Backward-safe for old single-ssh statefiles (that ssh is its own group)."""
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
    # Reach foothold with the SAME scoped SetupAccess setup persisted (key + routing) — no management-key
    # disk read. Old statefiles predating this field can't rebuild a scoped reach; skip the remote
    # docker rm then (best-effort — the tunnel pid was already killed above, and the VMs get torn down).
    acc = state.get("access")
    if acc:
        try:
            access = SetupAccess.model_validate(acc)
            ssh = _ssh_to_foothold(access)
            subprocess.run(ssh + ["docker rm -f c2 >/dev/null 2>&1 || true"],
                           timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("[foothold-c2] teardown docker rm on foothold %s: %s", state.get("foothold_ip"), e)
    try:
        os.unlink(_ctl_path(experiment_name))  # reap any lingering master socket
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


# ----------------------------------------------------------------------------------------------
# Async interface — what the attacker plugin calls. The sync setup/teardown above does the ssh +
# docker work; these run it in an executor and poll the C2 over the local ssh -L tunnel.
# ----------------------------------------------------------------------------------------------

async def start_c2c_server(
    experiment_name: str, cfg: ExperimentManagerConfig, bastion_ip: str | None = None, foothold_access=None,
) -> tuple[str, str, str]:
    """Bring up the Incalmo C2 on the attacker's foothold and return once it is serving.

    The C2 always runs on the foothold the environment provides (reached via the harness-only
    SetupAccess); the attacker holds no backend/topology knowledge.

    Returns (sentinel, remote_url, local_url):
      sentinel   — legacy handle (teardown is keyed by experiment_name, not this).
      remote_url — the foothold's in-env address the sandcat agents / setup play beacon to.
      local_url  — the 127.0.0.1 ssh -L tunnel the attacker LLM (on the harness host) uses.
    """
    init_logger(experiment_name, output_root(experiment_name, cfg))
    if foothold_access is None:
        raise RuntimeError(
            "the Incalmo C2 runs on the attacker foothold, but no foothold SetupAccess "
            "(scoped key + routing) was passed to start_c2c_server()")
    loop = asyncio.get_event_loop()
    sentinel, remote_url, local_url = await loop.run_in_executor(
        None, setup_c2, experiment_name, cfg, foothold_access, bastion_ip)
    log(experiment_name, f"C2 on foothold: agents -> {remote_url}, harness (tunnel) -> {local_url}")
    return sentinel, remote_url, local_url


async def stop_c2c_server(experiment_name: str) -> None:
    """Tear down the foothold C2 for an experiment (kill the tunnel + remove the remote container),
    keyed by experiment_name via the on-disk statefile. Never raises; a no-op if no C2 was stood up."""
    if not experiment_name:
        return
    await asyncio.get_event_loop().run_in_executor(None, teardown_c2, experiment_name, None)


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
