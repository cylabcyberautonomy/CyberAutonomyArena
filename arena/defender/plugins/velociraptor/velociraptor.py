"""Velociraptor EDR defender plugin: detection + active response over a per-experiment deployment."""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

from pydantic import PrivateAttr

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin, PreparedDefender
from . import deploy

_MGMT_ADVERTISE_IP = "10.0.1.10"


def _ansible_playbook_bin(cfg: ExperimentManagerConfig) -> Path:
    return cfg.mhbench_dir / ".venv" / "bin" / "ansible-playbook"


def _defender_out(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "defender"


class VelociraptorDefenderPlugin(DefenderPlugin, config_type="velociraptor"):
    """Velociraptor endpoint DFIR/EDR defender: detection + active response."""

    type: Literal["velociraptor"]
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "response_mode"})
    code_dir_field = "velociraptor_dir"
    response_mode: str = "kill"
    poll_interval: float = 15.0
    planted_data_paths: list[str] = []

    _server_ip: Optional[str] = PrivateAttr(default=None)
    _expected_clients: int = PrivateAttr(default=0)
    _ssh_key: Optional[str] = PrivateAttr(default=None)
    _server_proxy: Optional[str] = PrivateAttr(default=None)

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> "PreparedDefender":
        """Deploy the server (box) + clients (victims). Returns an empty baton (no box ES/agent)."""
        if bastion_ip is None:
            raise RuntimeError("Velociraptor defender needs the experiment bastion IP (bastion_ip).")
        velo_dir = self._code_dir(cfg)
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
        self._server_ip = box_ip
        self._server_proxy = proxy_common
        victims = deploy.victims_from_spec(defender_env_spec)
        if not victims:
            raise RuntimeError("Velociraptor: defender_env_spec carries no victim hosts to monitor.")
        self._expected_clients = len(victims)
        out = _defender_out(experiment_name, cfg)
        log_path = out / "velociraptor_deploy.log"

        loop = asyncio.get_event_loop()
        cfgs = await loop.run_in_executor(
            None, lambda: deploy.generate_configs(velo_dir, _MGMT_ADVERTISE_IP, out / "velociraptor_cfg")
        )
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
        return PreparedDefender()

    def box_ingress(self) -> dict[str, list[int]]:
        return {"forward": [8000]}

    def build_config(
        self,
        experiment_name: str,
        env_spec=None,
        prepared=None,
    ) -> dict:
        built = {
            "experiment_name": experiment_name,
            "install_dir": deploy.INSTALL_DIR,
            "server_ip": self._server_ip,
            "server_proxy": self._server_proxy,
            "expected_clients": self._expected_clients,
            "ssh_key": self._ssh_key,
            "response_mode": self.response_mode,
            "poll_interval": self.poll_interval,
            "ready_timeout": 600,
            "planted_data_paths": self.planted_data_paths,
        }
        return built

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = _defender_out(experiment_name, cfg) / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
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
        cfg: ExperimentManagerConfig,
    ) -> None:
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
