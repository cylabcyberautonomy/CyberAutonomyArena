from __future__ import annotations
from ...config import env_backend

import asyncio
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from ....config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
from ....experiment import Experiment
from ....experiment_log import init_logger, log, output_root


_EXC_RE = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception): ")


def _mhbench_error(action: str, returncode: int, mhbench_log: Path) -> RuntimeError:
    """Build a failure whose message carries MHBench's real cause from the log tail."""
    detail = ""
    try:
        lines = [ln.rstrip() for ln in mhbench_log.read_text(errors="replace").splitlines() if ln.strip()]
        err_lines = [ln for ln in lines if _EXC_RE.match(ln.strip())]
        detail = (err_lines[-1] if err_lines else lines[-1]).strip()
    except Exception:
        pass
    detail = f": {detail}" if detail else ""
    return RuntimeError(f"MHBench {action} failed (exit {returncode}){detail} (see {mhbench_log})")


def _kali_ip_from_spec(topology_path: Path) -> Optional[str]:
    topology = json.loads(topology_path.read_text())
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                if host.get("vm_type") == "kali_running":
                    return host.get("ip_address")
    return None


def resolve_topology_path(environment_spec: str, cfg) -> Path:
    """Resolve environment_spec (absolute, or relative to mhbench_dir) to the topology JSON path."""
    p = Path(environment_spec)
    return p if p.is_absolute() else cfg.mhbench_dir / p


def _mhb_config_args(cfg) -> list:
    """The --config args routing MHBench at a non-default backend config, or []."""
    return ["--config", env_backend(cfg).mhbench_config] if env_backend(cfg).mhbench_config else []


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> str:
    """The key MHBench injected into the hosts, read from MHBench's own config (backend-aware)."""
    import yaml
    default = str(Path("~/.ssh/id_ed25519").expanduser())
    try:
        rel = env_backend(cfg).mhbench_config or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return os.path.expanduser(key) if key else default
    except Exception:  # noqa: BLE001
        return default


_KALI_FOOTHOLD = "kali"


def attacker_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Build the adversary-safe AttackerEnvSpec (objective + foothold identity only)."""
    from ....attacker.env_spec import AttackerEnvSpec, AttackerBox
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    return AttackerEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        box=AttackerBox(name=_KALI_FOOTHOLD, ip=kali_ip, user="root") if kali_ip else None,
    )


def attacker_setup_access(deployed: Optional[DeployedEnvironment], bastion_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Build the harness-only SetupAccess for the attacker's foothold (key + bastion routing)."""
    from ....attacker.env_spec import AttackerSetupAccess
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    if not kali_ip:
        return []
    key = _mhbench_ssh_key(cfg)
    proxy = ""
    if bastion_ip:
        proxy = (
            f'-o ProxyCommand="ssh -W %h:%p -i {key} -o BatchMode=yes -o PasswordAuthentication=no '
            f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{bastion_ip}"'
        )
    return [AttackerSetupAccess(name=_KALI_FOOTHOLD, host=kali_ip, user="root", ssh_key=key, ssh_common_args=proxy)]


_ATTACKER_SUBNET = "attacker_subnet"
_DEFENDER_SUBNET = "defender_subnet"


def _iter_victims(topology_path: Path):
    """Yield each victim host dict — every host that is neither the attacker foothold nor the defender box."""
    topo = json.loads(Path(topology_path).read_text())
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            if sub.get("name") in (_ATTACKER_SUBNET, _DEFENDER_SUBNET):
                continue
            for h in sub.get("hosts", []):
                if h.get("vm_type") == "kali_running":
                    continue
                yield h


def _defender_box_host(topology_path: Path) -> Optional[dict]:
    """Return the defender box host dict (the single host in defender_subnet), or None."""
    topo = json.loads(Path(topology_path).read_text())
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            if sub.get("name") == _DEFENDER_SUBNET:
                hosts = sub.get("hosts", [])
                return hosts[0] if hosts else None
    return None


def defender_box_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """The agent-facing DefenderBox derived from the topology's defender_subnet, or None if absent."""
    from ....defender.env_spec import DefenderBox
    topo = deployed.topology_spec if deployed else None
    if not (topo and Path(topo).exists()):
        return None
    bh = _defender_box_host(topo)
    if not bh:
        return None
    ip = bh.get("ip_address")
    return DefenderBox(name=bh["name"], ip=str(ip) if ip else None, subnet=_DEFENDER_SUBNET)


def _role_from_name(name: str) -> Optional[str]:
    """Derive a role from a host name by stripping the trailing index (webserver0 -> webserver)."""
    return re.sub(r"\d+$", "", name) or None


def _host_users(vm_type: str) -> list[str]:
    """Login accounts a host of this MHBench vm_type has (ubuntu everywhere, +tomcat on webservers)."""
    if vm_type.startswith("kali"):
        return []
    if vm_type.startswith("webserver"):
        return ["ubuntu", "tomcat"]
    return ["ubuntu"]


def _defender_subnets(topology_path: Path, project_name: Optional[str]):
    """Resolve the defended-estate subnet structure (backend network/sg names, attacker segment excluded)."""
    from ....defender.env_spec import DefenderSubnet, DefenderHost, DefenderUser

    topo = json.loads(Path(topology_path).read_text())
    nets = topo.get("networks", [])
    if not nets:
        return [], None, None
    network_data = nets[0]

    def _n(name: str) -> str:
        return f"{project_name}-{name}" if project_name else name

    subnets = []
    for sd in network_data["subnets"]:
        if sd["name"] in (_ATTACKER_SUBNET, _DEFENDER_SUBNET):
            continue
        if any(h.get("vm_type", "").startswith("kali") for h in sd["hosts"]):
            continue
        hosts = []
        for h in sd["hosts"]:
            ip = h.get("ip_address")
            hosts.append(DefenderHost(
                name=h["name"],
                ip=str(ip) if ip else None,
                role=_role_from_name(h["name"]),
                users=[DefenderUser(name=u) for u in _host_users(h.get("vm_type", ""))],
                telemetry=h.get("vm_type", "").endswith("_instrumented"),
            ))
        subnets.append(DefenderSubnet(
            name=sd["name"],
            network=_n(sd["name"]),
            sec_group=_n(f"{sd['name']}_sg"),
            hosts=hosts,
            perimeter=bool(sd.get("perimeter", False)),
        ))
    return subnets, network_data.get("name"), _n("management_sg")


def _bastion_proxy_args(bastion_ip: Optional[str], key: str) -> str:
    """ssh args that route through the bastion with IdentitiesOnly, so ssh offers only this scoped key."""
    if not bastion_ip:
        return ""
    return (
        f'-o IdentitiesOnly=yes '
        f'-o ProxyCommand="ssh -W %h:%p -i {key} -o IdentitiesOnly=yes -o BatchMode=yes '
        f'-o PasswordAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'root@{bastion_ip}"'
    )


def issue_scoped_keys(cfg: ExperimentManagerConfig) -> tuple[Path, Path]:
    """Generate (idempotently) the attacker_key + defender_key keypairs the env issues."""
    keydir = Path(cfg.mhbench_dir) / "keys"
    keydir.mkdir(parents=True, exist_ok=True)
    out = []
    for name in ("attacker_key", "defender_key"):
        p = keydir / name
        if not p.exists():
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(p), "-N", "", "-q",
                            "-C", f"arena-{name}"], check=True)
            p.chmod(0o600)
        out.append(p)
    return out[0], out[1]


def _inject_bastion_jump(pubkey: str, targets: list[str], bastion_ip: str, mgmt_key: str) -> bool:
    """Add a forward-only entry for pubkey to the bastion's authorized_keys (tunnel to targets only)."""
    if not targets:
        return True
    opts = ('command="/bin/false",restrict,port-forwarding,'
            + ",".join(f'permitopen="{t}"' for t in targets))
    entry = f"{opts} {pubkey}"
    keymat = pubkey.split()[1]
    remote = (
        "install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"{{ grep -vF {keymat!r} ~/.ssh/authorized_keys || true; }} > ~/.ssh/ak.tmp && "
        "mv ~/.ssh/ak.tmp ~/.ssh/authorized_keys && "
        f"printf '%s\\n' {entry!r} >> ~/.ssh/authorized_keys"
    )
    r = subprocess.run(
        ["ssh", "-i", mgmt_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15", f"root@{bastion_ip}", remote],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode == 0


def _inject_pubkey(pubkey: str, host_ip: str, bastion_ip: str, mgmt_key: str) -> bool:
    """Append pubkey to root's authorized_keys on host_ip (via the bastion with the mgmt key)."""
    proxy = (f"ssh -W %h:%p -i {mgmt_key} -o BatchMode=yes -o StrictHostKeyChecking=no "
             f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 root@{bastion_ip}")
    remote = ("install -d -m700 ~/.ssh && touch ~/.ssh/authorized_keys && "
              f"grep -qxF {pubkey!r} ~/.ssh/authorized_keys || echo {pubkey!r} >> ~/.ssh/authorized_keys")
    r = subprocess.run(
        ["ssh", "-i", mgmt_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
         "-o", f"ProxyCommand={proxy}", f"root@{host_ip}", remote],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode == 0


def inject_scoped_keys(experiment: Experiment, bastion_ip: Optional[str], cfg: ExperimentManagerConfig) -> None:
    """Issue + inject the per-system scoped keys (full shell on own hosts + forward-only on the bastion)."""
    name = experiment.experiment_name
    if not bastion_ip:
        log(name, "inject_scoped_keys: no bastion_ip; skipping per-system key injection.")
        return
    topo = resolve_topology_path(experiment.environment_spec, cfg)
    ak, dk = issue_scoped_keys(cfg)
    ak_pub = Path(str(ak) + ".pub").read_text().strip()
    dk_pub = Path(str(dk) + ".pub").read_text().strip()
    mgmt_key = _mhbench_ssh_key(cfg)

    kali_ip = _kali_ip_from_spec(topo)
    if kali_ip:
        ok = _inject_pubkey(ak_pub, kali_ip, bastion_ip, mgmt_key)
        log(name, f"per-system key: attacker_key -> foothold {kali_ip}: {'ok' if ok else 'FAILED'}")
        jok = _inject_bastion_jump(ak_pub, [f"{kali_ip}:22"], bastion_ip, mgmt_key)
        log(name, f"jump: attacker_key forward-only on bastion -> {kali_ip}:22: {'ok' if jok else 'FAILED'}")

    targets: list[tuple[str, str]] = []
    box = _defender_box_host(topo)
    if box and box.get("ip_address"):
        targets.append((box["name"], str(box["ip_address"])))
    for h in _iter_victims(topo):
        if h.get("ip_address"):
            targets.append((h["name"], str(h["ip_address"])))
    for hname, hip in targets:
        ok = _inject_pubkey(dk_pub, hip, bastion_ip, mgmt_key)
        log(name, f"per-system key: defender_key -> {hname} {hip}: {'ok' if ok else 'FAILED'}")
    if targets:
        jok = _inject_bastion_jump(dk_pub, [f"{ip}:22" for _, ip in targets], bastion_ip, mgmt_key)
        log(name, f"jump: defender_key forward-only on bastion -> {len(targets)} hosts: {'ok' if jok else 'FAILED'}")


async def inject_scoped_keys_env(experiment: Experiment, bastion_ip: Optional[str], cfg: ExperimentManagerConfig) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, inject_scoped_keys, experiment, bastion_ip, cfg)


def defender_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Build the agent-facing DefenderEnvSpec: objective, victim inventory, and subnet structure."""
    from ....defender.env_spec import DefenderEnvSpec, DefenderHost, DefenderUser
    topo = deployed.topology_spec if deployed else None
    project_name = deployed.project_name if deployed else None
    hosts = []
    subnets, network_name, management_sg = [], None, None
    if topo and Path(topo).exists():
        for h in _iter_victims(topo):
            ip = h.get("ip_address")
            hosts.append(DefenderHost(
                name=h["name"], ip=str(ip) if ip else None, role=_role_from_name(h["name"]),
                users=[DefenderUser(name=u) for u in _host_users(h.get("vm_type", ""))],
                telemetry=h.get("vm_type", "").endswith("_instrumented"),
            ))
        subnets, network_name, management_sg = _defender_subnets(Path(topo), project_name)
    return DefenderEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        hosts=hosts,
        subnets=subnets,
        network_name=network_name,
        management_sg=management_sg,
        box=defender_box_spec(deployed, cfg),
    )


def defender_setup_access(deployed: Optional[DeployedEnvironment], bastion_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Build the harness-only SetupAccess for each victim (+ defender box) — key + bastion routing."""
    from ....defender.env_spec import DefenderSetupAccess
    topo = deployed.topology_spec if deployed else None
    if not (topo and Path(topo).exists()):
        return []
    key = _mhbench_ssh_key(cfg)
    proxy = _bastion_proxy_args(bastion_ip, key)
    out = []
    for h in _iter_victims(topo):
        ip = h.get("ip_address")
        if ip:
            out.append(DefenderSetupAccess(name=h["name"], host=str(ip), user="root",
                                   ssh_key=key, ssh_common_args=proxy))
    box = _defender_box_host(topo)
    if box and box.get("ip_address"):
        out.append(DefenderSetupAccess(name=box["name"], host=str(box["ip_address"]), user="root",
                               ssh_key=key, ssh_common_args=proxy))
    return out


def _provision_sync(
    experiment_name: str,
    environment_spec: str,
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> tuple[DeployedEnvironment, Optional[str]]:
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    provision_result_path = (output_root(experiment_name, cfg) / experiment_name / "experiment" / "provision_result.json").resolve()

    cmd = [
        str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
        "provision", str(topology_path),
        "--project-name", experiment_name,
        "--output-file", str(provision_result_path),
    ]
    if c2c_url:
        cmd += ["--c2c-url", c2c_url]

    init_logger(experiment_name, output_root(experiment_name, cfg))
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Provisioning environment via MHBench CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error("provision", result.returncode, mhbench_log)

    bastion_ip: Optional[str] = None
    if provision_result_path.exists():
        bastion_ip = json.loads(provision_result_path.read_text()).get("mgmt_ip")

    kali_ip = _kali_ip_from_spec(topology_path)
    log(experiment_name, f"Provisioning complete. Kali IP: {kali_ip}, mgmt IP: {bastion_ip}")
    return DeployedEnvironment(
        topology_spec=str(topology_path),
        ip=kali_ip,
        spec=Path(environment_spec).stem,
        project_name=experiment_name,
    ), bastion_ip


def _configure_sync(
    experiment_name: str,
    environment_spec: str,
    bastion_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    if bastion_ip is None:
        return

    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"

    cmd = [
        str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
        "configure", str(topology_path),
        "--project-name", experiment_name,
        "--mgmt-ip", bastion_ip,
    ]
    if c2c_url:
        cmd += ["--c2c-url", c2c_url]

    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    ansible_log_dir = output_root(experiment_name, cfg) / experiment_name / cfg.ansible_log_dir
    ansible_log_dir.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Running Ansible configuration via MHBench CLI (per-host logs: {ansible_log_dir})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT,
                                env={**os.environ, "MHBENCH_ANSIBLE_LOG_DIR": str(ansible_log_dir)})
    if result.returncode != 0:
        raise _mhbench_error("configure", result.returncode, mhbench_log)

    log(experiment_name, "Configuration complete.")


async def provision_environment(
    experiment: Experiment,
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> tuple[DeployedEnvironment, Optional[str]]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, _provision_sync, experiment.experiment_name, experiment.environment_spec, c2c_url, cfg
    )


async def configure_environment(
    experiment: Experiment,
    bastion_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, _configure_sync, experiment.experiment_name, experiment.environment_spec, bastion_ip, c2c_url, cfg
    )


def _request_ingress_sync(experiment_name: str, environment_spec: str, bastion_ip: str,
                          cfg: ExperimentManagerConfig, ingress: dict) -> None:
    """Provision the defender-requested box ingress via `cli.py request-ingress`."""
    telemetry = list(ingress.get("telemetry", []))
    forward = list(ingress.get("forward", []))
    if not (telemetry or forward):
        return
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    cmd = [str(python), str(cli), *_mhb_config_args(cfg), "request-ingress", str(topology_path),
           "--project-name", experiment_name, "--mgmt-ip", bastion_ip]
    for p in telemetry:
        cmd += ["--telemetry", str(p)]
    for p in forward:
        cmd += ["--forward", str(p)]
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"Requesting defender box ingress {ingress} via MHBench CLI...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error("request-ingress", result.returncode, mhbench_log)
    log(experiment_name, "Defender box ingress provisioned.")


async def request_ingress_env(experiment: Experiment, bastion_ip: Optional[str],
                              cfg: ExperimentManagerConfig, ingress: dict) -> None:
    if not bastion_ip or not ingress:
        return
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _request_ingress_sync,
                               experiment.experiment_name, experiment.environment_spec, bastion_ip, cfg, ingress)


def _host_op_sync(op: str, experiment_name: str, environment_spec: str, cfg: ExperimentManagerConfig,
                  *, name: Optional[str] = None, role: Optional[str] = None,
                  subnet: Optional[str] = None, target: Optional[str] = None) -> dict:
    """Run one MHBench per-host CLI subcommand (add-host / rebuild-host / remove-host) and return its
    JSON result ({name, ip} for add-host, {ok: true} otherwise)."""
    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"
    out_path = (output_root(experiment_name, cfg) / experiment_name / "experiment" / f"{op}_result.json").resolve()
    cmd = [str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
           op, str(topology_path), "--project-name", experiment_name, "--output-file", str(out_path)]
    if name:
        cmd += ["--name", name]
    if role:
        cmd += ["--role", role]
    if subnet:
        cmd += ["--subnet", subnet]
    if target:
        cmd += ["--target", target]
    mhbench_log = output_root(experiment_name, cfg) / experiment_name / "experiment" / "mhbench.log"
    mhbench_log.parent.mkdir(parents=True, exist_ok=True)
    log(experiment_name, f"MHBench {op} via CLI (log: {mhbench_log})...")
    with open(mhbench_log, "a") as lf:
        result = subprocess.run(cmd, cwd=str(mhbench_dir), stdout=lf, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise _mhbench_error(op, result.returncode, mhbench_log)
    return json.loads(out_path.read_text()) if out_path.exists() else {}


def new_host_setup_access(name: str, ip: str, cfg: ExperimentManagerConfig):
    """SetupAccess for a freshly added host (decoy), box-relative: scoped key + empty routing."""
    from ....defender.env_spec import DefenderSetupAccess
    return DefenderSetupAccess(name=name, host=str(ip), user="root",
                       ssh_key=_mhbench_ssh_key(cfg), ssh_common_args="")
