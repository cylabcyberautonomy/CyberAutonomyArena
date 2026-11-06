"""Bastion-hop ansible runner for the persona_traffic play, built straight from the env-produced SetupAccess."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

_PLAY = Path(__file__).resolve().parent / "aux" / "bgtraffic.yml"

# Applied to every hop. /dev/null known-hosts avoids the recycled-bastion-FIP stale-host-key rejection.
_BASE_SSH_OPTS = (
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
)


def _write_inventory(access: list[dict], hostvars: dict[str, dict], tmp: Path) -> Path:
    """One inventory host per SetupAccess entry, with its scoped key, env-owned routing, and per-host vars."""
    hosts = {}
    for a in access:
        entry = {
            "ansible_host": a["host"],
            "ansible_port": a.get("port", 22),
            "ansible_user": a.get("user", "root"),
            "ansible_ssh_common_args": f"{_BASE_SSH_OPTS} {(a.get('ssh_common_args') or '').strip()}".strip(),
            **hostvars.get(a["name"], {}),
        }
        if a.get("ssh_key"):
            entry["ansible_ssh_private_key_file"] = os.path.expanduser(a["ssh_key"])
        hosts[a["name"]] = entry
    path = tmp / "inventory.json"
    path.write_text(json.dumps({"traffic_hosts": {"hosts": hosts}}))
    return path


def run_play(*, action: str, access: list[dict], ansible_playbook_bin: str, extravars: dict,
             hostvars: Optional[dict[str, dict]] = None, log_path: Optional[Path] = None) -> None:
    """Run bgtraffic.yml with bgtraffic_action=action (install|start|stop|collect). Raises on failure."""
    if not access:
        raise RuntimeError("persona_traffic: no host access entries to run the play against")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inventory = _write_inventory(access, hostvars or {}, tmp)
        varfile = tmp / "extravars.json"
        varfile.write_text(json.dumps({"bgtraffic_action": action, **extravars}))
        cmd = [str(ansible_playbook_bin), str(_PLAY), "-i", str(inventory), "-e", f"@{varfile}"]
        env = {
            **os.environ,
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_SSH_ARGS": (f"-o ControlMaster=auto -o ControlPath={tmp}/%C -o ControlPersist=60s "
                                 + _BASE_SSH_OPTS),
            "ANSIBLE_PIPELINING": "True",
            "ANSIBLE_SSH_RETRIES": "3",
        }
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as lf:
                lf.write(f"\n=== bgtraffic action={action} on {len(access)} host(s) ===\n")
                lf.flush()
                result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
        else:
            result = subprocess.run(cmd, env=env)
        if result.returncode != 0:
            raise RuntimeError(f"bgtraffic play (action={action}) failed with exit {result.returncode}"
                               + (f" (see {log_path})" if log_path else ""))
