"""Velociraptor EDR defender plugin.

Deploys a per-experiment Velociraptor deployment — server on the experiment
bastion, clients on the victim hosts — then runs an EDR loop that detects the
MHBench kill chain from process-execution telemetry and actively responds
(kill process / quarantine host) via Velociraptor collections. Server + clients
are torn down with the environment (no shared, long-lived infrastructure).

Self-contained in the harness (its own bastion-hop deploy + a stdlib runner that
drives the server over SSH), so it needs nothing from MHBench's playbook registry
or the Defense-MHBench (Perry) repo. The velociraptor binary is a single static Go
binary shipped from the harness (cfg.velociraptor_dir/bin/velociraptor) — no apt
or download on the range.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import PrivateAttr

from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin
from . import deploy


def _require_velociraptor_dir(cfg: ExperimentManagerConfig) -> Path:
    d = getattr(cfg, "velociraptor_dir", None)
    if not d:
        raise RuntimeError(
            "defender=velociraptor requested but cfg.velociraptor_dir is unset — point it at a dir "
            "holding bin/velociraptor (the static binary) in config.yaml."
        )
    return Path(d)


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> Path:
    default = Path("~/.ssh/id_ed25519").expanduser()
    try:
        rel = getattr(cfg, "mhbench_config", None) or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return Path(os.path.expanduser(key)) if key else default
    except Exception:  # noqa: BLE001
        return default


def _topology_path(cfg: ExperimentManagerConfig, environment_spec: str) -> Path:
    return cfg.mhbench_dir / "environments" / f"{environment_spec}.json"


def _ansible_playbook_bin(cfg: ExperimentManagerConfig) -> Path:
    return cfg.mhbench_dir / ".venv" / "bin" / "ansible-playbook"


def _defender_out(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "defender"


class VelociraptorDefenderPlugin(DefenderPlugin, config_type="velociraptor"):
    """Velociraptor endpoint DFIR/EDR defender: detection + active response."""

    type: Literal["velociraptor"]
    # off | kill | quarantine | both  — what to do when a kill-chain rule fires.
    response_mode: str = "kill"
    poll_interval: float = 15.0
    # Paths of planted data files to treat as crown jewels for the data-access rule.
    planted_data_paths: list[str] = []

    # Filled in setup(), consumed by build_config() (same instance, called right after).
    _server_ip: Optional[str] = PrivateAttr(default=None)
    _expected_clients: int = PrivateAttr(default=0)
    _ssh_key: Optional[str] = PrivateAttr(default=None)

    # -- lifecycle ---------------------------------------------------------
    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        if mgmt_ip is None:
            raise RuntimeError("Velociraptor defender needs the experiment bastion IP (mgmt_ip).")
        velo_dir = _require_velociraptor_dir(cfg)
        spec = environment.topology_spec if environment else None
        # topology_spec from the environment may be an absolute path; else derive it.
        topology_path = Path(spec) if spec and Path(spec).exists() else _topology_path(cfg, experiment_name if not spec else spec)
        if not topology_path.exists():
            # environment.topology_spec is the canonical path the deployer used.
            topology_path = Path(environment.topology_spec) if environment else topology_path
        ssh_key = _mhbench_ssh_key(cfg)
        self._ssh_key = str(ssh_key)
        victims = deploy.victim_hosts(topology_path)
        self._expected_clients = len(victims)
        out = _defender_out(experiment_name, cfg)
        log_path = out / "velociraptor_deploy.log"

        loop = asyncio.get_event_loop()
        # 1. discover the bastion's internal IP victims should beacon to
        self._server_ip = await loop.run_in_executor(
            None, lambda: deploy.discover_bastion_internal_ip(mgmt_ip, ssh_key, victims[0][1])
        )
        # 2. generate server/client/api configs pinned to that IP
        cfgs = await loop.run_in_executor(
            None, lambda: deploy.generate_configs(velo_dir, self._server_ip, out / "velociraptor_cfg")
        )
        # 3. deploy server (bastion) + clients (victims)
        await loop.run_in_executor(
            None,
            lambda: deploy.run_play(
                action="install",
                topology_path=topology_path,
                mgmt_ip=mgmt_ip,
                ssh_key=ssh_key,
                ansible_playbook_bin=_ansible_playbook_bin(cfg),
                velociraptor_dir=velo_dir,
                extravars={
                    "velo_server_yaml": str(cfgs["server_yaml"]),
                    "velo_client_yaml": str(cfgs["client_yaml"]),
                    "velo_api_yaml": str(cfgs["api_yaml"]),
                    "velo_api_user": cfgs["api_user"],
                    "velo_api_password": cfgs["api_password"],
                },
                log_path=log_path,
            ),
        )

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "topology_spec": environment.topology_spec if environment else None,
            "install_dir": deploy.INSTALL_DIR,
            "server_ip": self._server_ip,
            "expected_clients": self._expected_clients,
            "ssh_key": self._ssh_key or str(Path("~/.ssh/id_ed25519").expanduser()),
            "response_mode": self.response_mode,
            "poll_interval": self.poll_interval,
            "ready_timeout": 600,
            "planted_data_paths": self.planted_data_paths,
        }

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = _defender_out(experiment_name, cfg) / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        # stdlib-only runner (shells out to ssh + the remote binary) — run under the
        # harness's own interpreter; no extra venv needed.
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            env={**os.environ},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Server+clients live on VMs that MHBench destroys, so this is best-effort:
        # nothing to leak, nothing that blocks env reclaim if it fails.
        return None

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "velociraptor",
            "label": "Velociraptor EDR",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Response mode",
                    "key": "response_mode",
                    "options": ["off", "kill", "quarantine", "both"],
                    "short_names": {
                        "off": "detect_only",
                        "kill": "kill",
                        "quarantine": "quar",
                        "both": "kill_quar",
                    },
                },
            ],
        }
