"""Self-contained bastion-hop ansible runner for the background-traffic play.

Deliberately does NOT reimplement MHBench's inventory/mux machinery from scratch —
it reuses MHBench's *installed* ``ansible-playbook`` (from the MHBench venv) and the
same SSH argument shape MHBench uses (ProxyCommand through the bastion, with
``UserKnownHostsFile=/dev/null`` on BOTH hops — the recycled-FIP host-key trap that
was the real dominant cause of "SSH to kali never came up"). It stays entirely
inside the harness so the traffic plugin is independent of MHBench's playbook
registry.

Victim hosts are every topology host whose ``vm_type`` is not ``kali_running`` (the
attacker) — i.e. the hosts a defender is scored on, which is exactly where benign
background noise belongs.
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


def victim_hosts(topology_path: Path) -> list[tuple[str, str]]:
    """Return [(name, internal_ip)] for every non-attacker host in the topology."""
    topo = json.loads(Path(topology_path).read_text())
    out: list[tuple[str, str]] = []
    for net in topo.get("networks", []):
        for subnet in net.get("subnets", []):
            for host in subnet.get("hosts", []):
                if host.get("vm_type") == "kali_running":
                    continue  # the attacker host is not a victim
                ip = host.get("ip_address")
                if ip:
                    out.append((host["name"], str(ip)))
    return out


def _proxy_command(mgmt_ip: str, ssh_key: Path) -> str:
    # Mirrors MHBench's bastion hop: key-auth only (fail fast, no password hang) and
    # /dev/null known-hosts so a recycled bastion floating IP with a stale key doesn't
    # get rejected (the ProxyJump/known_hosts trap).
    return (
        f"ssh -W %h:%p -i {ssh_key} "
        f"-o BatchMode=yes -o PasswordAuthentication=no "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"root@{mgmt_ip}"
    )


def _write_inventory(hosts: list[tuple[str, str]], mgmt_ip: str, ssh_key: Path, tmp: Path) -> Path:
    proxy = _proxy_command(mgmt_ip, ssh_key)
    common = (
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=10 "
        f'-o ProxyCommand="{proxy}"'
    )
    inv = {
        "victims": {
            "hosts": {
                name: {
                    "ansible_host": ip,
                    "ansible_port": 22,
                    "ansible_user": "root",  # MHBench injects the key for root on victims too
                    "ansible_ssh_private_key_file": str(ssh_key),
                    "ansible_ssh_common_args": common,
                }
                for name, ip in hosts
            }
        }
    }
    path = tmp / "inventory.json"
    path.write_text(json.dumps(inv))
    return path


def run_play(
    *,
    action: str,
    topology_path: Path,
    mgmt_ip: str,
    ssh_key: Path,
    ansible_playbook_bin: Path,
    extravars: dict,
    log_path: Optional[Path] = None,
) -> None:
    """Run install_bgtraffic.yml against the victim hosts. Raises on failure
    (except phases whose tasks are individually ``failed_when: false``)."""
    hosts = victim_hosts(topology_path)
    if not hosts:
        raise RuntimeError(f"No victim hosts found in {topology_path}")

    ssh_key = Path(os.path.expanduser(str(ssh_key)))
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inventory = _write_inventory(hosts, mgmt_ip, ssh_key, tmp)
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
                "-o StrictHostKeyChecking=no "
                "-o UserKnownHostsFile=/dev/null "
                "-o ServerAliveInterval=30 -o ServerAliveCountMax=10"
            ),
            "ANSIBLE_PIPELINING": "True",
            "ANSIBLE_SSH_RETRIES": "3",
        }
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as lf:
                lf.write(f"\n=== bgtraffic play action={action} on {len(hosts)} victim(s) ===\n")
                lf.flush()
                result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
        else:
            result = subprocess.run(cmd, env=env)
        if result.returncode != 0:
            raise RuntimeError(
                f"bgtraffic play (action={action}) failed with exit {result.returncode}"
                + (f" (see {log_path})" if log_path else "")
            )
