"""Self-contained bastion-hop ansible runner for the background-traffic play.

Backend-agnostic: it is handed the per-victim ``SetupAccess`` the ENVIRONMENT produced (scoped key +
bastion routing) and builds its ansible inventory straight from that — it no longer parses a topology,
reads a management key, or hand-builds a bastion ProxyCommand. Each access entry carries everything the
hop needs: ``host``/``user``/``port``, the scoped ``ssh_key``, and ``ssh_common_args`` (the env-owned
ProxyCommand through the bastion, with IdentitiesOnly so only the scoped key is offered).

It still reuses an *installed* ``ansible-playbook`` binary (resolved by the caller from the plugin's own
venv) and the keepalive/known-hosts SSH shape MHBench uses (UserKnownHostsFile=/dev/null on both hops —
the recycled-FIP host-key trap). It stays entirely inside the harness so the plugin is independent of
MHBench's playbook registry.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

_AUX = Path(__file__).resolve().parent / "aux"
_PLAY = _AUX / "install_bgtraffic.yml"

# Keepalive + known-hosts opts applied to every hop, merged with each entry's env-owned routing
# (ssh_common_args: the bastion ProxyCommand / IdentitiesOnly). /dev/null known-hosts avoids the
# recycled-bastion-FIP stale-host-key rejection.
_BASE_SSH_OPTS = (
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
)


def _common_args(entry: dict) -> str:
    """Merge the base SSH opts with this entry's env-owned routing (the bastion ProxyCommand etc.)."""
    extra = (entry.get("ssh_common_args") or "").strip()
    return (f"{_BASE_SSH_OPTS} {extra}").strip()


def _write_inventory(access: list[dict], tmp: Path) -> Path:
    """Build the ansible inventory straight from the env-produced SetupAccess entries."""
    hosts = {}
    for a in access:
        key = a.get("ssh_key")
        entry = {
            "ansible_host": a["host"],
            "ansible_port": a.get("port", 22),
            "ansible_user": a.get("user", "root"),
            "ansible_ssh_common_args": _common_args(a),
        }
        if key:
            entry["ansible_ssh_private_key_file"] = os.path.expanduser(key)
        hosts[a["name"]] = entry
    inv = {"victims": {"hosts": hosts}}
    path = tmp / "inventory.json"
    path.write_text(json.dumps(inv))
    return path


def run_play(
    *,
    action: str,
    access: list[dict],
    ansible_playbook_bin: str,
    extravars: dict,
    log_path: Optional[Path] = None,
) -> None:
    """Run install_bgtraffic.yml (action = install|start|stop|collect) against the victim hosts named by
    ``access`` (a list of SetupAccess dicts). Raises on failure (except tasks marked failed_when: false)."""
    if not access:
        raise RuntimeError("background traffic: no victim access entries (empty traffic_setup_access)")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inventory = _write_inventory(access, tmp)
        varfile = tmp / "extravars.json"
        varfile.write_text(json.dumps({"bgtraffic_action": action, **extravars}))

        cmd = [
            str(ansible_playbook_bin),
            str(_PLAY),
            "-i", str(inventory),
            "-e", f"@{varfile}",
        ]
        env = {
            **os.environ,
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_SSH_ARGS": (
                "-o ControlMaster=auto "
                f"-o ControlPath={tmp}/%C "
                "-o ControlPersist=60s "
                + _BASE_SSH_OPTS
            ),
            "ANSIBLE_PIPELINING": "True",
            "ANSIBLE_SSH_RETRIES": "3",
        }
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as lf:
                lf.write(f"\n=== bgtraffic play action={action} on {len(access)} victim(s) ===\n")
                lf.flush()
                result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
        else:
            result = subprocess.run(cmd, env=env)
        if result.returncode != 0:
            raise RuntimeError(
                f"bgtraffic play (action={action}) failed with exit {result.returncode}"
                + (f" (see {log_path})" if log_path else "")
            )
