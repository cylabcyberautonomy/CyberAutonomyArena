"""Run the Incalmo C2 stack on the in-environment Kali VM (OpenStack, opt-in via the Incalmo attacker config c2_on_kali).

On OpenStack the C2 is normally a local Docker container on the harness host (beluga), and the
victims beacon to beluga's host_ip — an IP shared with Elasticsearch/telemetry, so a defender
cannot safely block the whole C2 IP. This module instead runs the C2 on the Kali attacker VM that
is already part of each topology, so the C2 lives at Kali's in-tenant IP (shared with nothing the
defender needs). Victims/agents beacon to `kali_ip:8888`, and a defender's BlockIP(kali_ip) severs
only attacker infra.

Kali has NO floating IP (only the bastion/mgmt host does), so everything reaches it via the bastion
using the foothold's SetupAccess the arena attached — its scoped attacker key + env-owned routing
(a ProxyCommand through the bastion). We never read a management key off disk here:
  - setup ships the incalmo/c2c image + /incalmo to Kali and runs the container there;
  - the attacker LLM on beluga reaches the C2 through an `ssh -L` tunnel opened via the bastion
    (local 127.0.0.1:<port> -> kali_ip:8888).

Mirrors gcp_c2.py (which already runs the C2 off-beluga). Sync module — called via run_in_executor
from c2c.py.
"""
from __future__ import annotations

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

from ...env_spec import SetupAccess

logger = logging.getLogger(__name__)

_C2C_IMAGE = "incalmo/c2c:latest"
_C2_PORT = 8888
_STATE_DIR = Path("/tmp/mhbench-kali-c2")
_built = False


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _ctl_path(experiment_name: str) -> str:
    """Per-experiment ControlPath socket for the shared bastion+Kali master connection.
    MUST be per-experiment: every topology's Kali is 192.168.202.100/root, so an ssh %%C-style
    path (keyed on remote host+user) would COLLIDE across concurrent experiments and try to share
    one master to different bastions. Hash long names to stay under the AF_UNIX ~108-char limit."""
    name = experiment_name
    if len(name) > 40:
        import hashlib
        name = hashlib.sha1(name.encode()).hexdigest()[:24]
    return str(_STATE_DIR / f"cm-{name}")


def _ssh_to_kali(access: SetupAccess, ctl: str | None = None) -> list[str]:
    """ssh argv reaching the foothold (Kali) as the env-granted principal, using the SCOPED key +
    env-owned routing carried by the SetupAccess. We never read a management key off disk or build our
    own ProxyCommand: `access.ssh_key` is the foothold-scoped key and `access.ssh_common_args` carries
    the env's bastion/relay routing (a ProxyCommand with a forward-only jump credential, and its own
    /dev/null known_hosts handling on the jump — so recycled-FIP stale bastion keys can't reject us).

    When `ctl` is given, all invocations sharing that ControlPath multiplex over ONE master
    connection: the master carries the end-to-end Kali session tunnelled through the bastion, so
    the bastion hop is made exactly once (on first open) and every later poll/docker/ship/run call
    rides it instead of opening a fresh bastion connection. Under peak-concurrency batches the
    shared FIP/L3 path black-holes *new* connections to a bastion's floating IP for stretches
    (proven: 30 fresh poll connects all dropped while multiplexed ansible traffic got through), so
    collapsing kali_c2's ~5 fresh connects down to one both removes the post-poll failure points
    and cuts kali_c2's own contribution to the connection storm."""
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
        subprocess.run(_ssh_to_kali(access, ctl) + ["-O", "exit"],
                       timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    try:
        os.unlink(ctl)
    except OSError:
        pass


def _ensure_image_built_sync(cfg) -> None:
    """Build incalmo/c2c on beluga (once per process) so it can be shipped to Kali."""
    global _built
    if _built:
        return
    logger.info("[kali-c2] building C2 image %s on beluga", _C2C_IMAGE)
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


def setup_c2(experiment_name: str, cfg, access: SetupAccess, mgmt_ip: str | None = None) -> tuple[str, str, str]:
    """Run the C2 on the Kali VM and open a beluga->Kali tunnel for the attacker LLM.
    Reaches the foothold via the env-provided SetupAccess (scoped key + bastion routing) — not a
    management key read off disk. `mgmt_ip` is accepted for log messages only; routing is opaque in
    `access.ssh_common_args`.
    Returns (sentinel, remote_url, local_url):
      sentinel  = "kali-c2:<exp>" (stored as c2c_container_id; routes teardown here)
      remote_url= http://<kali_ip>:8888   (sandcat agents / setup play, in-tenant)
      local_url = http://127.0.0.1:<port> (beluga: readiness polls + attacker LLM, via ssh -L)
    """
    if access is None or not access.host:
        raise RuntimeError(f"[kali-c2] need a foothold SetupAccess with a host (got {access!r})")
    kali_ip = access.host
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    ctl = _ctl_path(experiment_name)
    ssh = _ssh_to_kali(access, ctl)                            # steps 2-5 multiplex over one master
    ssh_plain = _ssh_to_kali(access)                           # poll: NO ControlMaster (see step 1)
    # A stale/dead ControlPath master from a prior attempt of the SAME experiment (retries reuse the
    # name) poisons every future ControlMaster=auto connect — the "ControlSocket already exists" race
    # that dies as "Connection closed by UNKNOWN port 65535". REAP it (ssh -O exit + unlink), not just
    # unlink the socket file: a half-open master PROCESS would otherwise linger holding the path.
    _close_master(access, ctl)

    _ensure_image_built_sync(cfg)

    # 1. Wait for Kali to be SSH-reachable through the bastion, using a PLAIN (non-multiplexed) ssh.
    #    Decoupled from the ControlMaster deliberately: the old poll ran ControlMaster=auto, so its FIRST
    #    attempt had to WIN the master-open race through the ProxyJump — under peak-concurrency contention
    #    that lost and died as "Connection closed by UNKNOWN port 65535" (captured live), and once a
    #    half-open socket was left behind EVERY later attempt reused the dead master and failed the same
    #    way -> all 45 fast-reject -> "never came up". A plain connect has no master to race and no socket
    #    to poison, so the poll now measures true reachability; the master is opened once, after, in step 1b.
    #    CAPTURE each failure's raw ssh stderr. (The old direct-bastion hop-attribution probe was removed
    #    with the god-key: the foothold-scoped key can only reach Kali, not open a shell on the bastion.)
    last_err = ""
    for attempt in range(45):
        proc = subprocess.run(ssh_plain + ["true"], capture_output=True, text=True)
        if proc.returncode == 0:
            if attempt:
                logger.info("[kali-c2] Kali %s reachable via %s after %d failed attempt(s)",
                            kali_ip, mgmt_ip, attempt)
            break
        last_err = (proc.stderr or proc.stdout or "").strip().replace("\n", " ")
        if attempt == 0 or attempt % 6 == 5:
            logger.warning("[kali-c2] poll Kali %s via %s attempt %d/45 rc=%d: %s",
                           kali_ip, mgmt_ip, attempt + 1, proc.returncode,
                           last_err[:250] or "(no stderr)")
        time.sleep(10)
    else:
        raise RuntimeError(
            f"[kali-c2] SSH to Kali {kali_ip} (via bastion {mgmt_ip}) never came up; "
            f"last ssh error: {last_err[:300] or '(none captured)'}")

    # 1b. Reachability confirmed — now open the shared ControlMaster EXPLICITLY (a plain `ssh -o ...ctl true`
    #     that Kali is known-reachable for), retrying a few times and clearing any half-open socket between
    #     tries, so steps 2-5 (which run check=True and would otherwise abort on a transient master-open
    #     race) ride a proven master instead of racing to create it on their first call.
    for m in range(6):
        mo = subprocess.run(ssh + ["true"], capture_output=True, text=True)
        if mo.returncode == 0:
            break
        logger.warning("[kali-c2] master-open to Kali %s via %s try %d/6 rc=%d: %s",
                       kali_ip, mgmt_ip, m + 1, mo.returncode,
                       (mo.stderr or "").strip().replace("\n", " ")[:200] or "(no stderr)")
        _close_master(access, ctl)  # reap the failed/half-open master before retrying
        time.sleep(5)

    # 2. Install docker on Kali if missing (Kali has apt egress + kali repos; docker not baked).
    logger.info("[kali-c2] ensuring docker on Kali %s", kali_ip)
    subprocess.run(ssh + [
        "export DEBIAN_FRONTEND=noninteractive; command -v docker >/dev/null || "
        "(apt-get -qq update && apt-get -y -qq install docker.io && systemctl enable --now docker)"],
        check=True, timeout=600)

    # 3. Ship the image (docker save | gzip | ssh 'gunzip | docker load').
    logger.info("[kali-c2] shipping %s to Kali", _C2C_IMAGE)
    save = subprocess.Popen(["docker", "save", _C2C_IMAGE], stdout=subprocess.PIPE)
    gz = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=subprocess.PIPE)
    subprocess.run(ssh + ["gunzip | docker load"], stdin=gz.stdout, check=True, timeout=900)
    save.wait(); gz.wait()

    # 4. Ship /incalmo (same excludes as gcp_c2._provision_container), PLUS the C2's dynamic-payload
    #    dir. That dir accumulates a `dynamic_payload_*.sh` per tasking across ALL prior runs and is
    #    NEVER cleaned; under c2_on_kali the C2 + /incalmo live on the Kali box where the attacker has a
    #    shell, so shipping it lets the attacker READ every prior run's payloads — other envs' host IPs,
    #    exfil targets, decoy layouts, honey creds (proven: k3_sh_chpe_c2b_t1's shell attacker grep'd
    #    /incalmo and surfaced old StaticLayeredAll decoy/honey payloads → cross-run info leak +
    #    phantom "decoy interactions"). Exclude ONLY the generated `dynamic_payload_*.sh` files — NOT the
    #    whole payloads dir, which also holds the agent-deploy tooling (sandcat.go, downloadAgent.sh,
    #    runDeployAgent.sh, template_payloads/) that the C2's /agent/download endpoint needs; dropping
    #    those breaks agent deployment ("No sandcat agent beaconed within 600s"). So the Kali C2 keeps its
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

    # 5. Run the C2 container on Kali, bound to 8888 on all interfaces (in-tenant reachable).
    subprocess.run(ssh + [
        f"docker rm -f c2 >/dev/null 2>&1; docker run -d --name c2 -p 0.0.0.0:{_C2_PORT}:{_C2_PORT} "
        f"-v /incalmo:/incalmo -e UV_PROJECT_ENVIRONMENT=/incalmo/.venv-c2c {_C2C_IMAGE}"],
        check=True, timeout=180)

    # Setup ops done — close the shared master. The tunnel below is deliberately its OWN
    # long-lived connection (independent lifecycle: killed by recorded pid on teardown), not
    # multiplexed over the master, so it must not depend on the master staying alive.
    _close_master(access, ctl)

    # 6. Open the beluga->Kali tunnel (Kali has no FIP), wrapped in a RESILIENT auto-reconnect
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
        "-L", f"127.0.0.1:{local_port}:{kali_ip}:{_C2_PORT}",
        f"{access.user}@{access.host}",
    ]
    supervisor = "while true; do " + " ".join(shlex.quote(a) for a in ssh_tunnel) + "; sleep 2; done"
    tunnel = subprocess.Popen(["bash", "-c", supervisor],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    _statefile(experiment_name).write_text(json.dumps({
        "tunnel_pid": tunnel.pid, "kali_ip": kali_ip, "mgmt_ip": mgmt_ip, "local_port": local_port,
        "access": access.model_dump(),  # so teardown reaches Kali with the same scoped key + routing, no disk read
    }))
    logger.info("[kali-c2] resilient tunnel supervisor pid=%s 127.0.0.1:%s -> %s:%s (via %s)",
                tunnel.pid, local_port, kali_ip, _C2_PORT, mgmt_ip)

    # 7. Wait until the C2 serves through the tunnel (first boot runs `uv sync`; give ~4 min).
    url = f"http://127.0.0.1:{local_port}/agents"
    for _ in range(48):
        try:
            urllib.request.urlopen(url, timeout=5).read()
            logger.info("[kali-c2] C2 serving via tunnel at %s", url)
            break
        except Exception:
            time.sleep(5)
    else:
        raise RuntimeError(f"[kali-c2] C2 never served on {url} (container/tunnel not ready)")

    return (f"kali-c2:{experiment_name}",
            f"http://{kali_ip}:{_C2_PORT}",
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
    """Kill the beluga tunnel and remove the C2 container on Kali. Never raises."""
    sf = _statefile(experiment_name)
    state = {}
    try:
        state = json.loads(sf.read_text())
    except Exception:
        pass
    pid = state.get("tunnel_pid")
    if isinstance(pid, int):
        _kill_pid(pid)
    # Reach Kali with the SAME scoped SetupAccess setup persisted (key + routing) — no management-key
    # disk read. Old statefiles predating this field can't rebuild a scoped reach; skip the remote
    # docker rm then (best-effort — the tunnel pid was already killed above, and the VMs get torn down).
    acc = state.get("access")
    if acc:
        try:
            access = SetupAccess.model_validate(acc)
            ssh = _ssh_to_kali(access)
            subprocess.run(ssh + ["docker rm -f c2 >/dev/null 2>&1 || true"],
                           timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("[kali-c2] teardown docker rm on Kali %s: %s", state.get("kali_ip"), e)
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
            logger.exception("[kali-c2] sweep of %s failed", sf)
