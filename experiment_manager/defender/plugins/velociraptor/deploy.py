"""Generate Velociraptor configs and deploy server (bastion) + clients (victims).

Design (validated against velociraptor 0.77.2 in a local loopback test):
  * The server runs on the experiment BASTION (mgmt host). Victim clients beacon to
    the bastion's INTERNAL IP on the frontend port; the harness-side runner drives
    everything by SSHing to the bastion and running ``velociraptor --api_config ...
    query`` against the loopback API there (so the gRPC API is never network-exposed).
  * Configs are generated on the harness host with the vendored binary, the client
    server URL is pinned to the bastion's internal IP, and — crucially — the API
    user is created in the datastore BEFORE the frontend starts (a running frontend
    caches users in memory and won't see a later ``user add``; learned the hard way).

Deployment reuses MHBench's bastion-hop SSH shape (ProxyCommand with
``UserKnownHostsFile=/dev/null`` on both hops — the recycled-FIP host-key trap).
The bastion is reached directly on its floating IP; victims via the ProxyCommand.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import yaml

_AUX = Path(__file__).resolve().parent / "aux"
_PLAY = _AUX / "deploy_velociraptor.yml"
_ARTIFACTS = _AUX / "artifacts"

FRONTEND_PORT = 8000
INSTALL_DIR = "/opt/velociraptor"        # on both bastion and victims
API_USER = "harness-api"


def _bin(velociraptor_dir: Path) -> Path:
    b = Path(velociraptor_dir) / "bin" / "velociraptor"
    if not b.exists():
        raise RuntimeError(f"velociraptor binary not found at {b} (set cfg.velociraptor_dir)")
    return b


def victim_hosts(topology_path: Path) -> list[tuple[str, str]]:
    """[(name, internal_ip)] for every non-attacker host (the monitored victims)."""
    topo = json.loads(Path(topology_path).read_text())
    out: list[tuple[str, str]] = []
    for net in topo.get("networks", []):
        for subnet in net.get("subnets", []):
            for host in subnet.get("hosts", []):
                if host.get("vm_type") == "kali_running":
                    continue
                ip = host.get("ip_address")
                if ip:
                    out.append((host["name"], str(ip)))
    return out


# --------------------------------------------------------------------------- #
# Config generation (on the harness host, with the local binary)
# --------------------------------------------------------------------------- #
def generate_configs(velociraptor_dir: Path, bastion_internal_ip: str, out_dir: Path) -> dict:
    """Produce server.yaml / client.yaml / api.yaml in out_dir, wired for a server
    on the bastion at ``bastion_internal_ip``. Returns the paths + the API user/password."""
    binp = _bin(velociraptor_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    server_yaml = out_dir / "server.yaml"
    client_yaml = out_dir / "client.yaml"
    api_yaml = out_dir / "api.yaml"

    raw = subprocess.run([str(binp), "config", "generate"], capture_output=True, text=True)
    if raw.returncode != 0:
        raise RuntimeError(f"velociraptor config generate failed: {raw.stderr.strip()}")
    cfg = yaml.safe_load(raw.stdout)

    server_url = f"https://{bastion_internal_ip}:{FRONTEND_PORT}/"
    # Datastore + logs live under INSTALL_DIR on the bastion.
    cfg.setdefault("Datastore", {})
    cfg["Datastore"]["location"] = f"{INSTALL_DIR}/datastore"
    cfg["Datastore"]["filestore_directory"] = f"{INSTALL_DIR}/datastore"
    # Frontend must advertise the bastion IP (clients derive their URL from this),
    # and bind on all interfaces so victims on the internal net can reach it.
    cfg.setdefault("Frontend", {})
    cfg["Frontend"]["hostname"] = bastion_internal_ip
    cfg["Frontend"]["bind_address"] = "0.0.0.0"
    cfg["Frontend"]["bind_port"] = FRONTEND_PORT
    # The client section here is what `config client` copies out — pin the server URL.
    cfg.setdefault("Client", {})
    cfg["Client"]["server_urls"] = [server_url]
    server_yaml.write_text(yaml.safe_dump(cfg, sort_keys=False))

    # Derive the client config, then point its writeback somewhere writable.
    cli = subprocess.run([str(binp), "--config", str(server_yaml), "config", "client"],
                         capture_output=True, text=True)
    if cli.returncode != 0:
        raise RuntimeError(f"velociraptor config client failed: {cli.stderr.strip()}")
    client_cfg = yaml.safe_load(cli.stdout)
    client_cfg.setdefault("Client", {})
    client_cfg["Client"]["server_urls"] = [server_url]  # belt-and-suspenders
    client_cfg["Client"]["writeback_linux"] = f"{INSTALL_DIR}/client.writeback.yaml"
    client_yaml.write_text(yaml.safe_dump(client_cfg, sort_keys=False))

    # API client cert (CN == API_USER). NOTE: no --role here — that would write an ACL
    # into the datastore (a bastion path we can't touch from the harness). The user
    # record *with* the administrator role is created on the bastion by the play's
    # `user add --role administrator`, which is what actually authorizes API auth
    # (confirmed in the loopback test: the user record, not the cert role, is checked).
    api = subprocess.run(
        [str(binp), "--config", str(server_yaml), "config", "api_client",
         "--name", API_USER, str(api_yaml)],
        capture_output=True, text=True,
    )
    if api.returncode != 0:
        raise RuntimeError(f"velociraptor config api_client failed: {api.stderr.strip()}")
    # api_connection_string points at loopback on the bastion (queried via SSH there).
    api_cfg = yaml.safe_load(api_yaml.read_text())
    api_cfg["api_connection_string"] = "127.0.0.1:8001"
    api_yaml.write_text(yaml.safe_dump(api_cfg, sort_keys=False))

    import secrets
    return {
        "server_yaml": server_yaml,
        "client_yaml": client_yaml,
        "api_yaml": api_yaml,
        "api_user": API_USER,
        "api_password": secrets.token_urlsafe(18),  # GUI password for the user record; API auth is cert-based
        "server_url": server_url,
    }


# --------------------------------------------------------------------------- #
# SSH / ansible
# --------------------------------------------------------------------------- #
def _proxy_command(mgmt_ip: str, ssh_key: Path) -> str:
    return (
        f"ssh -W %h:%p -i {ssh_key} -o BatchMode=yes -o PasswordAuthentication=no "
        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{mgmt_ip}"
    )


def discover_bastion_internal_ip(mgmt_ip: str, ssh_key: Path, a_victim_ip: str) -> str:
    """Ask the bastion which source IP it routes to a victim from — that's the internal
    address victim clients should beacon to. Robust to whatever the mgmt network is named."""
    ssh_key = Path(os.path.expanduser(str(ssh_key)))
    cmd = [
        "ssh", "-i", str(ssh_key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", f"root@{mgmt_ip}",
        f"ip -o route get {a_victim_ip}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"could not discover bastion internal IP: {r.stderr.strip()}")
    # "... src 192.168.200.1 ..." -> 192.168.200.1
    for tok in r.stdout.split():
        if tok == "src":
            idx = r.stdout.split().index("src")
            return r.stdout.split()[idx + 1]
    raise RuntimeError(f"no src IP in route output: {r.stdout.strip()}")


def _write_inventory(mgmt_ip: str, victims: list[tuple[str, str]], ssh_key: Path, tmp: Path) -> Path:
    proxy = _proxy_command(mgmt_ip, ssh_key)
    victim_common = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=10 "
        f'-o ProxyCommand="{proxy}"'
    )
    inv = {
        "velo_server": {
            "hosts": {
                "bastion": {
                    "ansible_host": mgmt_ip,
                    "ansible_user": "root",
                    "ansible_ssh_private_key_file": str(ssh_key),
                    "ansible_ssh_common_args": (
                        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    ),
                }
            }
        },
        "velo_clients": {
            "hosts": {
                name: {
                    "ansible_host": ip,
                    "ansible_user": "root",
                    "ansible_ssh_private_key_file": str(ssh_key),
                    "ansible_ssh_common_args": victim_common,
                }
                for name, ip in victims
            }
        },
    }
    p = tmp / "inventory.json"
    p.write_text(json.dumps(inv))
    return p


def run_play(*, action: str, topology_path: Path, mgmt_ip: str, ssh_key: Path,
             ansible_playbook_bin: Path, velociraptor_dir: Path, extravars: dict,
             log_path: Optional[Path] = None) -> None:
    victims = victim_hosts(topology_path)
    if not victims:
        raise RuntimeError(f"No victim hosts found in {topology_path}")
    ssh_key = Path(os.path.expanduser(str(ssh_key)))
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inv = _write_inventory(mgmt_ip, victims, ssh_key, tmp)
        varfile = tmp / "vars.json"
        varfile.write_text(json.dumps({
            "velo_action": action,
            "velo_binary": str(_bin(velociraptor_dir)),
            "velo_install_dir": INSTALL_DIR,
            "velo_artifacts_dir": str(_ARTIFACTS),
            **extravars,
        }))
        cmd = [str(ansible_playbook_bin), str(_PLAY), "-i", str(inv), "-e", f"@{varfile}"]
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
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as lf:
                lf.write(f"\n=== velociraptor play action={action} (server=bastion, {len(victims)} clients) ===\n")
                lf.flush()
                r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
        else:
            r = subprocess.run(cmd, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"velociraptor play (action={action}) failed with exit {r.returncode}"
                               + (f" (see {log_path})" if log_path else ""))
