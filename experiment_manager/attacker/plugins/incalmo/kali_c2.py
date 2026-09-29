"""Run the Incalmo C2 stack on the in-environment Kali VM (OpenStack, opt-in via the Incalmo attacker config c2_on_kali).

On OpenStack the C2 is normally a local Docker container on the harness host (beluga), and the
victims beacon to beluga's host_ip — an IP shared with Elasticsearch/telemetry, so a defender
cannot safely block the whole C2 IP. This module instead runs the C2 on the Kali attacker VM that
is already part of each topology, so the C2 lives at Kali's in-tenant IP (shared with nothing the
defender needs). Victims/agents beacon to `kali_ip:8888`, and a defender's BlockIP(kali_ip) severs
only attacker infra.

Kali has NO floating IP (only the bastion/mgmt host does), so everything reaches it via ProxyJump
through the bastion at mgmt_ip, as root, with MHBench's SSH key:
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

logger = logging.getLogger(__name__)

_C2C_IMAGE = "incalmo/c2c:latest"
_C2_PORT = 8888
_STATE_DIR = Path("/tmp/mhbench-kali-c2")
_built = False


def _statefile(experiment_name: str) -> Path:
    return _STATE_DIR / f"{experiment_name}.json"


def _mhb_ssh_key(cfg=None) -> str:
    """MHBench's OpenStack SSH key (used to reach Kali via the bastion)."""
    try:
        if cfg is not None:
            path = Path(cfg.mhbench_dir) / "config" / "config.yaml"
        else:
            path = Path.home() / "MHBench" / "config" / "config.yaml"
        key = yaml_safe_load(path)["openstack"]["ssh_key_path"]
        return str(Path(key).expanduser())
    except Exception:
        return str(Path.home() / ".ssh" / "id_ed25519")


def yaml_safe_load(path: Path) -> dict:
    import yaml
    return yaml.safe_load(path.read_text())


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


def _ssh_to_kali(key: str, mgmt_ip: str, kali_ip: str, ctl: str | None = None) -> list[str]:
    """ssh argv reaching Kali as root, ProxyJumping through the bastion (root@mgmt_ip).

    When `ctl` is given, all invocations sharing that ControlPath multiplex over ONE master
    connection: the master carries the end-to-end Kali session tunnelled through the bastion, so
    the bastion hop is made exactly once (on first open) and every later poll/docker/ship/run call
    rides it instead of opening a fresh bastion connection. Under peak-concurrency batches the
    shared FIP/L3 path black-holes *new* connections to a bastion's floating IP for stretches
    (proven: 30 fresh poll connects all dropped while multiplexed ansible traffic got through), so
    collapsing kali_c2's ~5 fresh connects down to one both removes the post-poll failure points
    and cuts kali_c2's own contribution to the connection storm."""
    args = [
        "ssh", "-i", key,
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
    ]
    if ctl:
        args += ["-o", "ControlMaster=auto", "-o", f"ControlPath={ctl}", "-o", "ControlPersist=120"]
    # Reach Kali via an explicit ProxyCommand rather than `-o ProxyJump=root@{mgmt}`: the command-line
    # UserKnownHostsFile=/dev/null does NOT propagate to a ProxyJump hop, so the JUMP (bastion) host key
    # is checked against ~/.ssh/known_hosts. Bastion FIPs are RECYCLED from a pool, so a reused IP shows
    # up with a new host key -> "REMOTE HOST IDENTIFICATION HAS CHANGED" -> "Host key verification failed"
    # -> the poll reports "never came up" (deterministic per reused-IP; masked for months as the generic
    # error). Ansible never hit this because it always used a ProxyCommand with /dev/null on the jump.
    # Putting /dev/null + StrictHostKeyChecking=no on the INNER (jump) ssh makes the bastion hop ignore
    # known_hosts entirely — no stale key can reject us, and we stop polluting known_hosts on success.
    proxy = (
        f"ssh -W %h:%p -i {key} -o BatchMode=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 root@{mgmt_ip}"
    )
    args += ["-o", f"ProxyCommand={proxy}", f"root@{kali_ip}"]
    return args


def _close_master(key: str, mgmt_ip: str, kali_ip: str, ctl: str) -> None:
    """Tear down the shared master connection (best-effort) and remove its socket."""
    try:
        subprocess.run(_ssh_to_kali(key, mgmt_ip, kali_ip, ctl) + ["-O", "exit"],
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


def setup_c2(experiment_name: str, cfg, mgmt_ip: str, kali_ip: str) -> tuple[str, str, str]:
    """Run the C2 on the Kali VM and open a beluga->Kali tunnel for the attacker LLM.
    Returns (sentinel, remote_url, local_url):
      sentinel  = "kali-c2:<exp>" (stored as c2c_container_id; routes teardown here)
      remote_url= http://<kali_ip>:8888   (sandcat agents / setup play, in-tenant)
      local_url = http://127.0.0.1:<port> (beluga: readiness polls + attacker LLM, via ssh -L)
    """
    if not mgmt_ip or not kali_ip:
        raise RuntimeError(f"[kali-c2] need mgmt_ip and kali_ip (got mgmt_ip={mgmt_ip!r} kali_ip={kali_ip!r})")
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    key = _mhb_ssh_key(cfg)
    ctl = _ctl_path(experiment_name)
    ssh = _ssh_to_kali(key, mgmt_ip, kali_ip, ctl)             # steps 2-5 multiplex over one master
    ssh_plain = _ssh_to_kali(key, mgmt_ip, kali_ip)            # poll: NO ControlMaster (see step 1)
    ssh_bastion = [                                            # bastion-only probe (no ProxyJump) for hop attribution
        "ssh", "-i", key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", f"root@{mgmt_ip}",
    ]
    # A stale/dead ControlPath master from a prior attempt of the SAME experiment (retries reuse the
    # name) poisons every future ControlMaster=auto connect — the "ControlSocket already exists" race
    # that dies as "Connection closed by UNKNOWN port 65535". REAP it (ssh -O exit + unlink), not just
    # unlink the socket file: a half-open master PROCESS would otherwise linger holding the path.
    _close_master(key, mgmt_ip, kali_ip, ctl)

    _ensure_image_built_sync(cfg)

    def _hop(stderr: str) -> str:
        """Attribute a poll failure to a hop: probe the bastion DIRECTLY (no ProxyJump). If the bastion
        answers, the failure is the bastion->Kali leg (or Kali's sshd); if not, it's the bastion/FIP."""
        b = subprocess.run(ssh_bastion + ["true"], capture_output=True, text=True)
        if b.returncode == 0:
            return "bastion REACHABLE -> failure is the bastion->Kali leg / Kali sshd"
        return "bastion UNREACHABLE -> failure is the bastion/FIP hop (" + \
               ((b.stderr or "").strip().replace("\n", " ")[:150] or "no stderr") + ")"

    # 1. Wait for Kali to be SSH-reachable through the bastion, using a PLAIN (non-multiplexed) ssh.
    #    Decoupled from the ControlMaster deliberately: the old poll ran ControlMaster=auto, so its FIRST
    #    attempt had to WIN the master-open race through the ProxyJump — under peak-concurrency contention
    #    that lost and died as "Connection closed by UNKNOWN port 65535" (captured live), and once a
    #    half-open socket was left behind EVERY later attempt reused the dead master and failed the same
    #    way -> all 45 fast-reject -> "never came up". A plain connect has no master to race and no socket
    #    to poison, so the poll now measures true reachability; the master is opened once, after, in step 1b.
    #    CAPTURE + ATTRIBUTE each failure: log the raw ssh stderr AND a direct-bastion probe so we see
    #    which hop actually rejects (bastion/FIP vs bastion->Kali vs Kali sshd) instead of inferring it.
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
            logger.warning("[kali-c2] poll Kali %s via %s attempt %d/45 rc=%d: %s | %s",
                           kali_ip, mgmt_ip, attempt + 1, proc.returncode,
                           last_err[:250] or "(no stderr)", _hop(last_err))
        time.sleep(10)
    else:
        hop = _hop(last_err)
        raise RuntimeError(
            f"[kali-c2] SSH to Kali {kali_ip} (via bastion {mgmt_ip}) never came up; "
            f"last ssh error: {last_err[:300] or '(none captured)'} | {hop}")

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
        _close_master(key, mgmt_ip, kali_ip, ctl)  # reap the failed/half-open master before retrying
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
    _close_master(key, mgmt_ip, kali_ip, ctl)

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
    # ProxyCommand (not ProxyJump) so the bastion hop ignores known_hosts — same recycled-FIP stale-key
    # trap as the poll (see _ssh_to_kali); a reconnecting tunnel must not get rejected by a stale key.
    tunnel_proxy = (
        f"ssh -W %h:%p -i {key} -o BatchMode=yes -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 root@{mgmt_ip}"
    )
    ssh_tunnel = [
        "ssh", "-N", "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=6", "-o", "TCPKeepAlive=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
        "-i", key, "-o", f"ProxyCommand={tunnel_proxy}",
        "-L", f"127.0.0.1:{local_port}:{kali_ip}:{_C2_PORT}",
        f"root@{kali_ip}",
    ]
    supervisor = "while true; do " + " ".join(shlex.quote(a) for a in ssh_tunnel) + "; sleep 2; done"
    tunnel = subprocess.Popen(["bash", "-c", supervisor],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    _statefile(experiment_name).write_text(json.dumps({
        "tunnel_pid": tunnel.pid, "kali_ip": kali_ip, "mgmt_ip": mgmt_ip, "local_port": local_port,
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
    kali_ip, mgmt_ip = state.get("kali_ip"), state.get("mgmt_ip")
    if kali_ip and mgmt_ip:
        try:
            ssh = _ssh_to_kali(_mhb_ssh_key(cfg), mgmt_ip, kali_ip)
            subprocess.run(ssh + ["docker rm -f c2 >/dev/null 2>&1 || true"],
                           timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("[kali-c2] teardown docker rm on Kali %s: %s", kali_ip, e)
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
