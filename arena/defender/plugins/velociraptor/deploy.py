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


def victims_from_spec(defender_env_spec) -> list[tuple[str, str]]:
    """[(name, internal_ip)] for every monitored victim, from the ENVIRONMENT-produced run spec — no
    backend topology parse (the defender is backend-agnostic). DefenderEnvSpec.hosts is already the
    defended victim inventory: the environment excluded the attacker (kali) AND the defender's own box,
    so this just reads name/ip. Accepts the pydantic DefenderEnvSpec or its model_dump() dict."""
    if defender_env_spec is None:
        return []
    hosts = getattr(defender_env_spec, "hosts", None)
    if hosts is None:  # a plain dict (e.g. from config JSON)
        hosts = defender_env_spec.get("hosts", [])
    out: list[tuple[str, str]] = []
    for h in hosts:
        name = getattr(h, "name", None) if not isinstance(h, dict) else h.get("name")
        ip = getattr(h, "ip", None) if not isinstance(h, dict) else h.get("ip")
        if name and ip:
            out.append((str(name), str(ip)))
    return out


# --------------------------------------------------------------------------- #
# Config generation (on the harness host, with the local binary)
# --------------------------------------------------------------------------- #
def generate_configs(velociraptor_dir: Path, advertise_ip: str, out_dir: Path) -> dict:
    """Produce server.yaml / client.yaml / api.yaml in out_dir. The server RUNS on the defender box
    (bound 0.0.0.0:FRONTEND_PORT), but clients reach it through the mgmt-host TCP forward, so the
    Frontend advertises ``advertise_ip`` (the mgmt host, e.g. 10.0.1.10) — that address is the cert CN,
    the client beacon URL, and the forward-listen address, all consistent so pinned-CA validation lines
    up through the raw-TCP hop. Returns the paths + the API user/password."""
    binp = _bin(velociraptor_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    server_yaml = out_dir / "server.yaml"
    client_yaml = out_dir / "client.yaml"
    api_yaml = out_dir / "api.yaml"

    raw = subprocess.run([str(binp), "config", "generate"], capture_output=True, text=True)
    if raw.returncode != 0:
        raise RuntimeError(f"velociraptor config generate failed: {raw.stderr.strip()}")
    cfg = yaml.safe_load(raw.stdout)

    server_url = f"https://{advertise_ip}:{FRONTEND_PORT}/"
    # Datastore + logs live under INSTALL_DIR on the box (where the server runs).
    cfg.setdefault("Datastore", {})
    cfg["Datastore"]["location"] = f"{INSTALL_DIR}/datastore"
    cfg["Datastore"]["filestore_directory"] = f"{INSTALL_DIR}/datastore"
    # Advertise the mgmt-host address clients beacon to (the forward's listen IP); bind on all
    # interfaces on the box so the forward (mgmt:8000 -> box:8000) can reach it.
    cfg.setdefault("Frontend", {})
    cfg["Frontend"]["hostname"] = advertise_ip
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
def _write_inventory(server_ip: str, victims: list[tuple[str, str]], ssh_key: Path,
                     proxy_common: str, tmp: Path) -> Path:
    """Inventory with the server on the DEFENDER BOX (velo_server) and clients on the victims
    (velo_clients). Both are behind the bastion, so BOTH reach through it via the same scoped-key
    ProxyCommand (proxy_common = the SetupAccess ssh_common_args). This is the key change from the
    old 'server on the bastion (direct FIP)' shape."""
    common = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=30 -o ServerAliveCountMax=10 "
        f"{proxy_common}"
    )
    inv = {
        "velo_server": {
            "hosts": {
                "defender_box": {
                    "ansible_host": server_ip,
                    "ansible_user": "root",
                    "ansible_ssh_private_key_file": str(ssh_key),
                    "ansible_ssh_common_args": common,
                }
            }
        },
        "velo_clients": {
            "hosts": {
                name: {
                    "ansible_host": ip,
                    "ansible_user": "root",
                    "ansible_ssh_private_key_file": str(ssh_key),
                    "ansible_ssh_common_args": common,
                }
                for name, ip in victims
            }
        },
    }
    p = tmp / "inventory.json"
    p.write_text(json.dumps(inv))
    return p


def run_play(*, action: str, victims: list[tuple[str, str]], server_ip: str, ssh_key: Path,
             proxy_common: str, ansible_playbook_bin: Path, velociraptor_dir: Path, extravars: dict,
             log_path: Optional[Path] = None) -> None:
    if not victims:
        raise RuntimeError("No victim hosts to deploy velociraptor clients on (empty defender_env_spec)")
    ssh_key = Path(os.path.expanduser(str(ssh_key)))
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        inv = _write_inventory(server_ip, victims, ssh_key, proxy_common, tmp)
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
                lf.write(f"\n=== velociraptor play action={action} (server=box, {len(victims)} clients) ===\n")
                lf.flush()
                r = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
        else:
            r = subprocess.run(cmd, env=env)
        if r.returncode != 0:
            raise RuntimeError(f"velociraptor play (action={action}) failed with exit {r.returncode}"
                               + (f" (see {log_path})" if log_path else ""))
