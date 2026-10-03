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

from pydantic import PrivateAttr

from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin
from . import deploy

# The mgmt-host address Velo clients beacon to (where the env's mgmt:8000->box:8000 forward listens);
# same host as the falcosidekick relay. Constant across deploys (management subnet host).
_MGMT_ADVERTISE_IP = "10.0.1.10"


def _require_velociraptor_dir(cfg: ExperimentManagerConfig) -> Path:
    d = getattr(cfg, "velociraptor_dir", None)
    if not d:
        raise RuntimeError(
            "defender=velociraptor requested but cfg.velociraptor_dir is unset — point it at a dir "
            "holding bin/velociraptor (the static binary) in config.yaml."
        )
    return Path(d)


def _ansible_playbook_bin(cfg: ExperimentManagerConfig) -> Path:
    return cfg.mhbench_dir / ".venv" / "bin" / "ansible-playbook"


def _defender_out(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "defender"


class VelociraptorDefenderPlugin(DefenderPlugin, config_type="velociraptor"):
    """Velociraptor endpoint DFIR/EDR defender: detection + active response."""

    type: Literal["velociraptor"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "response_mode"})
    # off | kill | quarantine | both  — what to do when a kill-chain rule fires.
    response_mode: str = "kill"
    poll_interval: float = 15.0
    # Paths of planted data files to treat as crown jewels for the data-access rule.
    planted_data_paths: list[str] = []

    # Filled in setup(), consumed by build_config() (same instance, called right after).
    _server_ip: Optional[str] = PrivateAttr(default=None)
    _expected_clients: int = PrivateAttr(default=0)
    _ssh_key: Optional[str] = PrivateAttr(default=None)
    _server_proxy: Optional[str] = PrivateAttr(default=None)  # bastion ProxyCommand to reach the box

    # -- lifecycle ---------------------------------------------------------
    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
    ) -> None:
        if bastion_ip is None:
            raise RuntimeError("Velociraptor defender needs the experiment bastion IP (bastion_ip).")
        velo_dir = _require_velociraptor_dir(cfg)
        # The server runs ON the defender box. Read the box + the SCOPED defender access (key + bastion
        # routing) from the env-produced specs the arena injected (defender_env_spec / defender_access) —
        # NOT a specific backend's deployer — so this stays environment-agnostic. The box + victims sit
        # behind the bastion, so the deploy reaches both via that scoped-key ProxyCommand. This is the
        # same access the other defenders read out of their injected config (see base.prepare_box_es).
        box = getattr(defender_env_spec, "box", None)
        if not (box and box.ip):
            raise RuntimeError(
                "Velociraptor requires a defender box, but defender_env_spec provides none.")
        box_ip = str(box.ip)
        box_access = next((a for a in (defender_access or []) if str(a.host) == box_ip), None)
        if not box_access or not box_access.ssh_key:
            raise RuntimeError(f"no SetupAccess entry with an ssh_key for the defender box {box_ip}")
        scoped_key = box_access.ssh_key
        proxy_common = box_access.ssh_common_args
        self._ssh_key = str(scoped_key)
        self._server_ip = box_ip                 # server runs here; runner drives it over the box's proxy
        self._server_proxy = proxy_common        # runner SSHes to the box via this bastion ProxyCommand
        # Victims from the env-produced run spec (backend-agnostic) — NOT a topology parse. The env already
        # excluded the attacker + the defender box, so this is exactly the monitored estate.
        victims = deploy.victims_from_spec(defender_env_spec)
        if not victims:
            raise RuntimeError("Velociraptor: defender_env_spec carries no victim hosts to monitor.")
        self._expected_clients = len(victims)
        out = _defender_out(experiment_name, cfg)
        log_path = out / "velociraptor_deploy.log"

        loop = asyncio.get_event_loop()
        # 1. generate configs advertising the mgmt-host address clients beacon to (the forward-listen
        #    IP), while the server binds 0.0.0.0:8000 on the box.
        cfgs = await loop.run_in_executor(
            None, lambda: deploy.generate_configs(velo_dir, _MGMT_ADVERTISE_IP, out / "velociraptor_cfg")
        )
        # 2. deploy server (box) + clients (victims), both via the scoped-key bastion ProxyCommand
        await loop.run_in_executor(
            None,
            lambda: deploy.run_play(
                action="install",
                victims=victims,
                server_ip=box_ip,
                ssh_key=scoped_key,
                proxy_common=proxy_common,
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

    def box_ingress(self) -> dict[str, list[int]]:
        # Server-mediated EDR: clients beacon in via the victim->mgmt->box:8000 forward. No box ES.
        return {"forward": [8000]}

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        prepared=None,  # Phase-A baton; velociraptor has no box ES, so it is unused
    ) -> dict:
        # No topology_spec: the monitored estate came from the arena-injected defender_env_spec in setup()
        # (backend-agnostic); the runner drives the already-deployed server and never parses a topology.
        return {
            "experiment_name": experiment_name,
            "install_dir": deploy.INSTALL_DIR,
            "server_ip": self._server_ip,          # the defender box (server runs here)
            "server_proxy": self._server_proxy,    # bastion ProxyCommand so the runner can SSH to the box
            "expected_clients": self._expected_clients,
            "ssh_key": self._ssh_key,   # the injected scoped defender key (set in setup(); no god-key fallback)
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
