"""Attacker-owned foothold prep — the attacker prepares its own box, over the bastion, using the
credentials in the AttackerEnvSpec. No MHBench cli, no environment.deployer.

The environment provides the box (a reachable foothold VM) and the access (bastion + key) in the
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
from ...env_spec import AttackerSetupAccess

_AUX = Path(__file__).parent / "aux"


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


def _write_inventory(access: list[AttackerSetupAccess], tmp: Path) -> Path:
    """One inventory over every foothold — ansible preps them all at once (multi-host)."""
    if not access:
        raise RuntimeError("attacker foothold prep got no AttackerSetupAccess entries")
    base = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
    )
    hosts = {}
    for fa in access:
        if not fa.host or not fa.ssh_key:
            raise RuntimeError(f"foothold {fa.name!r} needs host + ssh_key (got host={fa.host}, ssh_key={fa.ssh_key})")
        # Routing (bastion/relay ProxyCommand, or empty for direct) is opaque and env-owned.
        common = f"{base} {fa.ssh_common_args}".strip()
        hosts[fa.name] = {
            "ansible_host": str(fa.host),
            "ansible_port": fa.port,
            "ansible_user": fa.user,
            "ansible_ssh_private_key_file": os.path.expanduser(fa.ssh_key),
            "ansible_ssh_common_args": common,
            "user": fa.user,  # the vendored plays' `become_user: {{ user }}` resolves per-host from here
        }
    p = tmp / "inventory.json"
    p.write_text(json.dumps({"attacker": {"hosts": hosts}}))
    return p


_GROUP = "attacker"  # inventory group holding every foothold; the vendored plays' `{{ host }}` targets it


def _run_play_sync(play: str, access: list[AttackerSetupAccess], extravars: dict,
                   cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    play_path = _AUX / play
    if not play_path.exists():
        raise RuntimeError(f"vendored attacker play not found: {play_path}")
    log_path = output_root(experiment_name, cfg) / experiment_name / "attacker" / "foothold.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inv = _write_inventory(access, tmp)
        varfile = tmp / "vars.json"
        # The vendored plays use `{{ host }}` (the target group) and `{{ user }}` (per-host, resolved
        # from each foothold's inventory `user` var — see _write_inventory), so multiple footholds
        # with different accounts still work.
        varfile.write_text(json.dumps({"host": _GROUP, **extravars}))
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
            lf.write(f"\n=== attacker foothold play {play} on {[fa.host for fa in access]} ===\n")
            lf.flush()
            r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"attacker foothold play '{play}' failed with exit {r.returncode} (see {log_path})")


async def run_play(play: str, access: list[AttackerSetupAccess], extravars: dict,
                   cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    import asyncio
    log(experiment_name, f"Attacker prepping its foothold(s): {play} on {[fa.host for fa in access]}")
    await asyncio.get_event_loop().run_in_executor(
        None, _run_play_sync, play, access, extravars, cfg, experiment_name
    )


async def land_sandcat(access: list[AttackerSetupAccess], remote_url: Optional[str],
                       cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    """Download + start the sandcat C2 agent on the attacker's foothold(s) (MHBench's start_incalmo)."""
    caldera_ip, caldera_port = _caldera_ip_port(remote_url)
    if not caldera_ip or not caldera_port:
        raise RuntimeError(f"cannot derive caldera_ip/port from C2 URL {remote_url!r} for sandcat landing")
    await run_play("start_incalmo.yml", access,
                   {"caldera_ip": caldera_ip, "caldera_port": caldera_port}, cfg, experiment_name)


async def install_metasploit(access: list[AttackerSetupAccess], cfg: ExperimentManagerConfig, experiment_name: str) -> None:
    """Install msfrpcd + pymetasploit3 on the attacker's foothold(s) (MHBench's install_metasploit)."""
    await run_play("install_metasploit.yml", access, {}, cfg, experiment_name)
