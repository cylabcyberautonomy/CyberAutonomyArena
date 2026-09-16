"""Run the Incalmo C2 stack on a dedicated attacker host (GCP-backed experiments).

On OpenStack the C2 is a local Docker container on the harness host and the VMs reach it
at host_ip. On GCP the deployed VMs live in a GCP VPC with no route back to the NAT'd
harness host, so the C2 runs on a SEPARATE dedicated attacker host: a GCP VM created in the
experiment's VPC with its own external IP, holding the incalmo/c2c container. Everyone
reaches it at that host's external IP — the harness (beluga) directly, the environment hosts
via their Cloud NAT egress. The attacker host is created after the environment is provisioned
(its VPC must exist) and destroyed on C2 teardown.
"""
from __future__ import annotations

import logging
import re
import subprocess
import time
import urllib.request
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_C2C_IMAGE = "incalmo/c2c:latest"
_C2_PORT = 8888
_C2_INTERNAL_IP = "10.0.1.20"   # mgmt subnet; .10 is the bastion


def _gcp_name(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]", "-", name.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    if not s or not s[0].isalpha():
        s = "m-" + s
    return s[:63].rstrip("-")


def _gcp_conf(cfg=None) -> dict:
    import os
    if cfg is not None:
        path = Path(cfg.mhbench_dir) / (cfg.mhbench_config or "config/config.gcp.yaml")
    else:
        path = Path(os.environ.get("MHBENCH_GCP_CONFIG",
                                   str(Path.home() / "MHBench" / "config" / "config.gcp.yaml")))
    return yaml.safe_load(path.read_text())["gcp"]


def _clients(gc: dict):
    from google.oauth2 import service_account
    from google.cloud import compute_v1
    creds = None
    if gc.get("credentials_file"):
        creds = service_account.Credentials.from_service_account_file(
            str(Path(gc["credentials_file"]).expanduser()))
    return compute_v1, ({"credentials": creds} if creds else {})


def _beluga_egress_ip() -> str | None:
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=10).read().decode().strip()
    except Exception:
        return None


def _ssh_opts(key_path: str) -> list[str]:
    return ["ssh", "-i", str(Path(key_path).expanduser()), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=15"]


def setup_c2(experiment_name: str, cfg) -> tuple[str, str]:
    """Create the attacker/C2 host in the experiment VPC, run the C2 container on it,
    return (vm_name, external_url)."""
    gc = _gcp_conf(cfg)
    c, k = _clients(gc)
    project = gc["project"]; region = gc.get("region", "us-central1"); zone = gc.get("zone", "us-central1-a")
    key_path = gc["ssh_key_path"]
    pub = Path(gc.get("ssh_public_key_path") or (gc["ssh_key_path"] + ".pub")).expanduser().read_text().strip()
    prefix = _gcp_name(experiment_name)
    name = _gcp_name(f"{experiment_name}-c2"); tag = name
    net = f"projects/{project}/global/networks/{_gcp_name(prefix + '-vpc')}"
    subnet = f"projects/{project}/regions/{region}/subnetworks/{_gcp_name(prefix + '-management-subnet')}"
    img = f"projects/{project}/global/images/ubuntu-base"

    inst = c.InstancesClient(**k); fw = c.FirewallsClient(**k)
    user_data = ("#cloud-config\ndisable_root: false\nruncmd:\n"
                 "  - install -d -m700 /root/.ssh\n"
                 f"  - echo '{pub}' >> /root/.ssh/authorized_keys\n"
                 "  - chmod 600 /root/.ssh/authorized_keys\n")
    nic = c.NetworkInterface(subnetwork=subnet, network_i_p=_C2_INTERNAL_IP,
                             access_configs=[c.AccessConfig(name="External NAT", type_="ONE_TO_ONE_NAT")])
    instance = c.Instance(
        name=name, hostname=f"{name}.mhbench.internal",
        machine_type=f"zones/{zone}/machineTypes/e2-small", tags=c.Tags(items=[tag]),
        disks=[c.AttachedDisk(boot=True, auto_delete=True,
               initialize_params=c.AttachedDiskInitializeParams(source_image=img, disk_size_gb=20))],
        network_interfaces=[nic],
        metadata=c.Metadata(items=[c.Items(key="ssh-keys", value=f"root:{pub}"),
                                   c.Items(key="enable-oslogin", value="FALSE"),
                                   c.Items(key="user-data", value=user_data)]))
    logger.info("[gcp-c2] creating attacker/C2 host %s", name)
    inst.insert(project=project, zone=zone, instance_resource=instance).result(timeout=600)

    beluga = _beluga_egress_ip()
    ssh_src = [f"{beluga}/32"] if beluga else ["0.0.0.0/0"]
    # SSH from beluga; beacon on 8888 from anywhere (env hosts arrive via their Cloud NAT egress IP).
    for fwname, src, ports in [(_gcp_name(prefix + "-c2-ssh"), ssh_src, ["22"]),
                               (_gcp_name(prefix + "-c2-beacon"), ["0.0.0.0/0"], [str(_C2_PORT)])]:
        try:
            fw.insert(project=project, firewall_resource=c.Firewall(
                name=fwname, network=net, direction="INGRESS", priority=1000,
                source_ranges=src, target_tags=[tag],
                allowed=[c.Allowed(I_p_protocol="tcp", ports=ports)])).result(timeout=300)
        except Exception as e:
            logger.warning("[gcp-c2] firewall %s: %s", fwname, e)

    ext = inst.get(project=project, zone=zone, instance=name).network_interfaces[0].access_configs[0].nat_i_p
    logger.info("[gcp-c2] attacker host up (internal=%s external=%s) — provisioning container", _C2_INTERNAL_IP, ext)
    _provision_container(ext, key_path, cfg)
    internal_url = f"http://{_C2_INTERNAL_IP}:{_C2_PORT}"  # env hosts beacon here (same VPC; NAT can't hairpin to the external IP)
    external_url = f"http://{ext}:{_C2_PORT}"              # beluga (attacker LLM + readiness polls) reaches here
    logger.info("[gcp-c2] C2 ready: internal=%s external=%s", internal_url, external_url)
    return name, internal_url, external_url


def _provision_container(ext_ip: str, key_path: str, cfg) -> None:
    ssh = _ssh_opts(key_path); target = f"root@{ext_ip}"
    for _ in range(30):
        if subprocess.run(ssh + [target, "true"], capture_output=True).returncode == 0:
            break
        time.sleep(10)
    else:
        raise RuntimeError(f"[gcp-c2] SSH to attacker host {ext_ip} never came up")
    subprocess.run(ssh + [target,
        "export DEBIAN_FRONTEND=noninteractive; command -v docker >/dev/null || "
        "(apt-get -qq update && apt-get -y -qq install docker.io && systemctl enable --now docker)"],
        check=True, timeout=360)
    save = subprocess.Popen(["docker", "save", _C2C_IMAGE], stdout=subprocess.PIPE)
    gz = subprocess.Popen(["gzip", "-1"], stdin=save.stdout, stdout=subprocess.PIPE)
    subprocess.run(ssh + [target, "gunzip | docker load"], stdin=gz.stdout, check=True, timeout=600)
    save.wait(); gz.wait()
    incalmo_dir = Path(cfg.incalmo_dir)
    tar = subprocess.Popen(
        ["tar", "czf", "-", "--exclude=.git", "--exclude=.venv", "--exclude=.venv-c2c",
         "--exclude=incalmo/frontend", "--exclude=output", "--exclude=__pycache__",
         "-C", str(incalmo_dir.parent), incalmo_dir.name], stdout=subprocess.PIPE)
    subprocess.run(ssh + [target,
        "rm -rf /incalmo && mkdir -p /incalmo && tar xzf - -C /incalmo --strip-components=1"],
        stdin=tar.stdout, check=True, timeout=600)
    tar.wait()
    subprocess.run(ssh + [target,
        f"docker rm -f c2 >/dev/null 2>&1; docker run -d --name c2 -p 0.0.0.0:{_C2_PORT}:{_C2_PORT} "
        f"-v /incalmo:/incalmo -e UV_PROJECT_ENVIRONMENT=/incalmo/.venv-c2c {_C2C_IMAGE}"],
        check=True, timeout=120)
    # The container runs `uv sync` (celery/flask) on first boot, which can take a few minutes —
    # longer than the harness's own 60s C2-readiness poll. Block here until the C2 actually serves
    # so the harness's subsequent wait_c2c_ready succeeds immediately.
    url = f"http://{ext_ip}:{_C2_PORT}/agents"
    for _ in range(48):  # up to ~4 min
        try:
            urllib.request.urlopen(url, timeout=5).read()
            logger.info("[gcp-c2] C2 HTTP endpoint is serving")
            return
        except Exception:
            time.sleep(5)
    raise RuntimeError(f"[gcp-c2] C2 container never served on {url} (uv sync / celery startup)")


def teardown_c2(experiment_name: str, cfg=None) -> None:
    gc = _gcp_conf(cfg); c, k = _clients(gc)
    from google.api_core.exceptions import NotFound
    project = gc["project"]; region = gc.get("region", "us-central1"); zone = gc.get("zone", "us-central1-a")
    prefix = _gcp_name(experiment_name)
    inst = c.InstancesClient(**k); fw = c.FirewallsClient(**k)
    try:
        inst.delete(project=project, zone=zone, instance=_gcp_name(f"{experiment_name}-c2")).result(timeout=600)
        logger.info("[gcp-c2] destroyed attacker/C2 host for %s", experiment_name)
    except NotFound:
        pass
    except Exception as e:
        logger.warning("[gcp-c2] C2 host delete: %s", e)
    for f in [_gcp_name(prefix + "-c2-ssh"), _gcp_name(prefix + "-c2-beacon")]:
        try:
            fw.delete(project=project, firewall=f).result(timeout=300)
        except NotFound:
            pass
        except Exception as e:
            logger.warning("[gcp-c2] fw delete %s: %s", f, e)
