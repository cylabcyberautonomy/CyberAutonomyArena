"""Ludus environment plugin — a SECOND, non-MHBench backend, here as a STUB.

Ludus (ludus.cloud) deploys cyber ranges on Proxmox from a range config. This plugin exists to prove
the EnvironmentPlugin interface is backend-agnostic: it produces the same agent-facing specs +
SetupAccess and provides the same generic infra guarantees (an always-provisioned defender box in an
isolated subnet, and a fixed telemetry-relay ingest) as MHBench — through the identical methods.

Live provisioning (provision/configure/collect/teardown/capacity) is NOT wired (needs a Ludus server +
Proxmox), so those raise clearly. The spec/infra methods return Ludus-flavored values so the interface
can be exercised offline and pinned by the contract test.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema
from ..lifecycle import EnvironmentLifecycle
from ..models import DeployedEnvironment
from .base import EnvironmentPlugin

if TYPE_CHECKING:
    from ...experiment import Experiment

# A Ludus range keeps its own private mgmt network; the defender box lives there, reachable by
# range hosts but hidden from the attacker.
_LUDUS_DEFENDER_IP = "10.99.99.10"
_LUDUS_KALI_IP = "10.99.1.100"


def _stub(op: str):
    raise NotImplementedError(
        f"ludus {op} not wired (needs a Ludus server + Proxmox); this plugin currently exercises the "
        f"spec/infra interface only."
    )


class LudusEnvironment(EnvironmentPlugin, config_type="ludus"):
    """Deploys a Ludus range from a range-config file (stub)."""

    type: Literal["ludus"] = "ludus"
    environment_spec: str  # PATH to a Ludus range config (yaml/json)

    @property
    def spec(self) -> str:
        return Path(self.environment_spec).stem

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "ludus",
            "label": "Ludus",
            "cartesian_product": False,
            "fields": [
                {"field_type": "text", "label": "Range config (path)", "key": "environment_spec"},
            ],
        }

    # -- lifecycle (not wired) --------------------------------------------------------------------
    async def capacity(self, experiment, cfg): _stub("capacity")
    async def provision(self, experiment, c2c_url, cfg, lc=None): _stub("provision")
    async def configure(self, experiment, mgmt_ip, c2c_url, cfg, lc=None): _stub("configure")
    async def collect(self, experiment, cfg): _stub("collect")
    async def teardown(self, experiment, cfg, lc=None): _stub("teardown")

    # -- spec production (Ludus-flavored, same shapes as MHBench) ---------------------------------
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        from ...attacker.env_spec import AttackerEnvSpec, AttackerFoothold
        return AttackerEnvSpec(
            objective=(deployed.spec if deployed else None) or self.spec,
            footholds=[AttackerFoothold(name="kali", host=_LUDUS_KALI_IP, user="root")],
        )

    def attacker_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        from ...attacker.env_spec import SetupAccess
        # Ludus reaches range hosts via its own mgmt path (opaque ssh_common_args); the env issues a
        # per-SYSTEM key (attacker key scoped to the foothold only).
        return [SetupAccess(name="kali", host=_LUDUS_KALI_IP, user="root",
                            ssh_key=self.attacker_credential(deployed, cfg), ssh_common_args="")]

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        from ...defender.env_spec import DefenderEnvSpec, DefenderHost
        return DefenderEnvSpec(
            objective=(deployed.spec if deployed else None) or self.spec,
            hosts=[DefenderHost(name="webserver0", ip="10.99.1.10", role="webserver"),
                   DefenderHost(name="database0", ip="10.99.2.10", role="database")],
            box=self.defender_box(deployed, cfg),
        )

    def defender_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        from ...attacker.env_spec import SetupAccess
        key = self.defender_credential(deployed, cfg)  # scoped to the defender box + victims, not the foothold
        return [
            SetupAccess(name="webserver0", host="10.99.1.10", user="root", ssh_key=key),
            SetupAccess(name="database0", host="10.99.2.10", user="root", ssh_key=key),
            SetupAccess(name="defender_box", host=_LUDUS_DEFENDER_IP, user="root", ssh_key=key),
        ]

    # -- per-system credential issuance (Ludus mock: distinct per-range keys) ---------------------
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return "~/.ludus/attacker_key"

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return "~/.ludus/defender_key"

    # -- generic infra guarantees (defender box) --------------------------------------------------
    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        from ...defender.env_spec import DefenderBox
        return DefenderBox(name="defender_box", ip=_LUDUS_DEFENDER_IP, subnet="ludus-mgmt")
