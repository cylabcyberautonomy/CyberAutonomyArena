"""Attacker-owned foothold prep — the attacker prepares its own box, over the bastion, using the
credentials in the AttackerEnvSpec. No MHBench cli, no environment.deployer.

The environment provides the box (a reachable Kali VM) and the access (bastion + key) in the
AttackerEnvSpec; the attacker does everything ON the box itself. This mirrors how the Velociraptor
and caldera_human plugins run their own bastion-hop ansible with vendored plays (aux/), reusing
only the ansible-playbook binary — not MHBench's orchestration.

Plays (vendored in aux/):
  start_incalmo.yml     — download + launch the sandcat C2 agent, beaconing to caldera_ip:port
  install_metasploit.yml — msfrpcd + pymetasploit3 (only the msf/LLM attackers need it)
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from ....config import ExperimentManagerConfig
from ....experiment_log import log, output_root
from ...env_spec import AttackerEnvSpec

_AUX = Path(__file__).parent / "aux"
_KALI_ALIAS = "attacker_kali"  # inventory alias the vendored plays' `{{ host }}` resolves to


def _ansible_playbook_bin(cfg: ExperimentManagerConfig) -> Path:
    # Reuse the ansible-playbook binary (a tool), not MHBench's orchestration — same as the
    # velociraptor/caldera_human plugins.
    return cfg.mhbench_dir / ".venv" / "bin" / "ansible-playbook"


def _caldera_ip_port(remote_url: Optional[str]) -> tuple[Optional[str], Optional[int]]:
    """Parse the C2 URL the sandcat agent beacons to (what MHBench passed as caldera_ip/port)."""
    if not remote_url:
        return None, None
    u = urlparse(remote_url)
    return u.hostname, (u.port or 80)


def _write_inventory(env_spec: AttackerEnvSpec, tmp: Path) -> Path:
    if not env_spec.entry_ip or not env_spec.entry_ssh_key:
        raise RuntimeError(
            "attacker foothold prep needs entry_ip + entry_ssh_key in the AttackerEnvSpec "
            f"(got entry_ip={env_spec.entry_ip}, entry_ssh_key={env_spec.entry_ssh_key})"
        )
    entry_key = os.path.expanduser(env_spec.entry_ssh_key)
    common = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
    )
    # If the box is behind a jump, route through it with the JUMP's own credential (scoped/forward-
    # only), not the box key. UserKnownHostsFile=/dev/null on BOTH hops (recycled-FIP host-key trap).
    if env_spec.jump is not None:
        j = env_spec.jump
        jump_key = os.path.expanduser(j.ssh_key) if j.ssh_key else entry_key
        proxy = (
            f"ssh -W %h:%p -i {jump_key} -p {j.port} -o BatchMode=yes -o PasswordAuthentication=no "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {j.user}@{j.host}"
        )
        common += f' -o ProxyCommand="{proxy}"'
    inv = {
        "attacker": {
            "hosts": {
                _KALI_ALIAS: {
                    "ansible_host": str(env_spec.entry_ip),
                    "ansible_port": env_spec.entry_port,
                    "ansible_user": env_spec.entry_user,
                    "ansible_ssh_private_key_file": entry_key,
                    "ansible_ssh_common_args": common,
                }
            }
        }
    }
    p = tmp / "inventory.json"
    p.write_text(json.dumps(inv))
    return p


def _run_play_sync(play: str, env_spec: AttackerEnvSpec, extravars: dict,
                   cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    play_path = _AUX / play
    if not play_path.exists():
        raise RuntimeError(f"vendored attacker play not found: {play_path}")
    log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "foothold.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inv = _write_inventory(env_spec, tmp)
        varfile = tmp / "vars.json"
        # The vendored plays use `{{ host }}`/`{{ user }}`; MHBench ran them as user=root.
        varfile.write_text(json.dumps({"host": _KALI_ALIAS, "user": env_spec.entry_user, **extravars}))
        cmd = [str(_ansible_playbook_bin(cfg)), str(play_path), "-i", str(inv), "-e", f"@{varfile}"]
        env = {
            **os.environ,
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_SSH_ARGS": (
                f"-o ControlMaster=auto -o ControlPath={tmp}/%C -o ControlPersist=60s "
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
            ),
            "ANSIBLE_PIPELINING": "True",
            "ANSIBLE_SSH_RETRIES": "3",
        }
        with open(log_path, "a") as lf:
            _via = f" via {env_spec.jump.host}" if env_spec.jump else ""
            lf.write(f"\n=== attacker foothold play {play} on {env_spec.entry_ip}{_via} ===\n")
            lf.flush()
            r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"attacker foothold play '{play}' failed with exit {r.returncode} (see {log_path})")


async def run_play(play: str, env_spec: AttackerEnvSpec, extravars: dict,
                   cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    import asyncio
    log(experiment_name, f"Attacker prepping its foothold: {play} on {env_spec.entry_ip}")
    await asyncio.get_event_loop().run_in_executor(
        None, _run_play_sync, play, env_spec, extravars, cfg, experiment_name
    )


async def land_sandcat(env_spec: AttackerEnvSpec, remote_url: Optional[str],
                       cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    """Download + start the sandcat C2 agent on the attacker's box (was MHBench's start_incalmo play)."""
    caldera_ip, caldera_port = _caldera_ip_port(remote_url)
    if not caldera_ip or not caldera_port:
        raise RuntimeError(f"cannot derive caldera_ip/port from C2 URL {remote_url!r} for sandcat landing")
    await run_play("start_incalmo.yml", env_spec,
                   {"caldera_ip": caldera_ip, "caldera_port": caldera_port}, cfg, experiment_name)


async def install_metasploit(env_spec: AttackerEnvSpec, cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    """Install msfrpcd + pymetasploit3 on the attacker's box (was MHBench's install_metasploit play)."""
    await run_play("install_metasploit.yml", env_spec, {}, cfg, experiment_name)
