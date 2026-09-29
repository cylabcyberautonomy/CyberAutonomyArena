from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from ..config import ExperimentManagerConfig
from .models import DeployedEnvironment
from ..experiment import Experiment
from ..experiment_log import init_logger, log, output_root


# Matches a Python exception summary line, e.g. "RuntimeError: mgmt FIP host key never matched ...".
_EXC_RE = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception): ")


def _mhbench_error(action: str, returncode: int, mhbench_log: Path) -> RuntimeError:
    """Build a failure whose message carries MHBench's real cause, not just an exit code.
    Pulls the most specific line from the log tail (a Python 'SomeError: ...' line if present,
    else the last non-empty line) so the reason survives up to the dashboard."""
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
    """environment_spec is a PATH to a topology JSON — absolute, or relative to mhbench_dir (e.g.
    'environments/instrumented/equifax_small_instrumented.json'). No library-name resolution: the env
    files live in subdirs (instrumented/, non-generated/, generated/), so a path points at the real
    file regardless of layout. Shared by the deployer, collect, rotate, teardown and the plugin."""
    p = Path(environment_spec)
    return p if p.is_absolute() else cfg.mhbench_dir / p


def _mhb_config_args(cfg) -> list:
    # Route MHBench at a non-default backend config (e.g. GCP). Group option, before the subcommand.
    return ["--config", cfg.mhbench_config] if getattr(cfg, "mhbench_config", None) else []


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> str:
    """The key MHBench injected into the hosts. Read from MHBench's own config (backend-aware)."""
    import yaml  # local import: only the attacker-spec adapter needs it
    default = str(Path("~/.ssh/id_ed25519").expanduser())
    try:
        rel = getattr(cfg, "mhbench_config", None) or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return os.path.expanduser(key) if key else default
    except Exception:  # noqa: BLE001 — config drift must not break the adapter; use the default key
        return default


_KALI_FOOTHOLD = "kali"  # logical name for the attacker's foothold (MHBench's kali box)


def attacker_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Stage-A adapter: MHBench serves up the ADVERSARY-SAFE AttackerEnvSpec (objective + foothold
    identity only — no keys, no bastion). Stage B: the env plugin returns it directly."""
    from ..attacker.env_spec import AttackerEnvSpec, AttackerFoothold  # lazy: avoid import cycle
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    return AttackerEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        footholds=[AttackerFoothold(name=_KALI_FOOTHOLD, host=kali_ip, user="root")] if kali_ip else [],
    )


def attacker_setup_access(deployed: Optional[DeployedEnvironment], mgmt_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Stage-A adapter: MHBench serves up the HARNESS-ONLY SetupAccess (how to reach the foothold
    to prep it — key + routing through the bastion). Never given to the adversary. MHBench uses one
    shared root key today; ssh_common_args routes through the bastion via ProxyCommand."""
    from ..attacker.env_spec import SetupAccess  # lazy: avoid import cycle
    kali_ip = str(deployed.ip) if (deployed and deployed.ip) else None
    if not kali_ip:
        return []
    key = _mhbench_ssh_key(cfg)
    proxy = ""
    if mgmt_ip:
        proxy = (
            f'-o ProxyCommand="ssh -W %h:%p -i {key} -o BatchMode=yes -o PasswordAuthentication=no '
            f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{mgmt_ip}"'
        )
    return [SetupAccess(name=_KALI_FOOTHOLD, host=kali_ip, user="root", ssh_key=key, ssh_common_args=proxy)]


def _iter_victims(topology_path: Path):
    """Yield each non-attacker host dict from the topology JSON."""
    topo = json.loads(Path(topology_path).read_text())
    for net in topo.get("networks", []):
        for sub in net.get("subnets", []):
            for h in sub.get("hosts", []):
                if h.get("vm_type") == "kali_running":
                    continue
                yield h


def _role_from_name(name: str) -> Optional[str]:
    """Derive a role from a host name by stripping the trailing index (webserver0 -> webserver)."""
    return re.sub(r"\d+$", "", name) or None


def _bastion_proxy_args(mgmt_ip: Optional[str], key: str) -> str:
    if not mgmt_ip:
        return ""
    return (
        f'-o ProxyCommand="ssh -W %h:%p -i {key} -o BatchMode=yes -o PasswordAuthentication=no '
        f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{mgmt_ip}"'
    )


def defender_env_spec(deployed: Optional[DeployedEnvironment], cfg: ExperimentManagerConfig):
    """Stage-A adapter: MHBench serves up the AGENT-FACING DefenderEnvSpec (objective + host inventory
    at the defender's knowledge level — no creds/routing). Carries topology_spec for the not-yet-migrated
    runners. Stage B: the env plugin returns it directly."""
    from ..defender.env_spec import DefenderEnvSpec, DefenderHost  # lazy: avoid import cycle
    hosts = []
    topo = deployed.topology_spec if deployed else None
    if topo and Path(topo).exists():
        for h in _iter_victims(topo):
            ip = h.get("ip_address")
            hosts.append(DefenderHost(name=h["name"], ip=str(ip) if ip else None,
                                      role=_role_from_name(h["name"])))
    return DefenderEnvSpec(
        objective=(deployed.spec if deployed else None) or "none",
        hosts=hosts,
        topology_spec=topo,
    )


def defender_setup_access(deployed: Optional[DeployedEnvironment], mgmt_ip: Optional[str], cfg: ExperimentManagerConfig):
    """Stage-A adapter: HARNESS-ONLY SetupAccess (shared type) for each victim the defender may reach —
    key + bastion routing. This replaces per-plugin _mhbench_ssh_key + hand-built ProxyCommand. Never
    given to the defender's brain."""
    from ..attacker.env_spec import SetupAccess  # lazy: avoid import cycle
    topo = deployed.topology_spec if deployed else None
    if not (topo and Path(topo).exists()):
        return []
    key = _mhbench_ssh_key(cfg)
    proxy = _bastion_proxy_args(mgmt_ip, key)
    out = []
    for h in _iter_victims(topo):
        ip = h.get("ip_address")
        if ip:
            out.append(SetupAccess(name=h["name"], host=str(ip), user="root",
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
    provision_result_path = output_root(experiment_name, cfg) / experiment_name / "experiment" / "provision_result.json"

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

    mgmt_ip: Optional[str] = None
    if provision_result_path.exists():
        mgmt_ip = json.loads(provision_result_path.read_text()).get("mgmt_ip")

    kali_ip = _kali_ip_from_spec(topology_path)
    log(experiment_name, f"Provisioning complete. Kali IP: {kali_ip}, mgmt IP: {mgmt_ip}")
    return DeployedEnvironment(
        topology_spec=str(topology_path),
        ip=kali_ip,
        spec=Path(environment_spec).stem,
    ), mgmt_ip


def _configure_sync(
    experiment_name: str,
    environment_spec: str,
    mgmt_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    if mgmt_ip is None:
        return

    mhbench_dir = cfg.mhbench_dir
    topology_path = resolve_topology_path(environment_spec, cfg)
    python = mhbench_dir / ".venv" / "bin" / "python"
    cli = mhbench_dir / "cli.py"

    cmd = [
        str(python), str(cli), *_mhb_config_args(cfg), "--ansible-verbosity", str(cfg.ansible_verbosity),
        "configure", str(topology_path),
        "--project-name", experiment_name,
        "--mgmt-ip", mgmt_ip,
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
    mgmt_ip: Optional[str],
    c2c_url: Optional[str],
    cfg: ExperimentManagerConfig,
) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, _configure_sync, experiment.experiment_name, experiment.environment_spec, mgmt_ip, c2c_url, cfg
    )

# NOTE: run_attacker_setup_play / the MHBench --attacker-play path was removed — the attacker owns its
# own foothold prep (attacker plugin's prepare_foothold, via SetupAccess), so the environment never
# runs an attacker play. (User-adjudicated; see WHAT_TO_REFACTOR_ENVIRONMENT.md.)
