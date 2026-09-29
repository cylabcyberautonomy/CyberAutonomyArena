"""Base class for the ENVIRONMENT plugin type — the 4th selectable system alongside
attacker/defender/traffic. A plugin deploys and tears down the network the experiment runs on
and answers "how big is it" for admission.

Stage 1a: `MHBenchEnvironment` wraps the existing (live-validated) environment functions by
delegation, so behavior is identical while the plugin interface goes in. Later stages move the
bodies in, split the agent-facing specs out, and remove the direct MHBench coupling.

Lifecycle the arena drives (see main.py):
    capacity(experiment, cfg)                 -> [(vcpus, ram_mb, disk_gb), ...]  # admission sizing
    provision(experiment, c2c_url, cfg)       -> (DeployedEnvironment, mgmt_ip)
    configure(experiment, mgmt_ip, c2c_url, cfg, setup_play=None) -> None
    collect(experiment, cfg)                  -> None   # pull host logs before teardown
    teardown(experiment, cfg)                 -> None

NOTE (Stage 1a): log rotation stays a separate main.py step for now (folding it into the mhbench
plugin's configure changes its timing — deferred to Stage 2, per the design doc).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema
from ..models import DeployedEnvironment
from ..lifecycle import EnvironmentLifecycle

if TYPE_CHECKING:
    from ...experiment import Experiment


class EnvironmentPlugin(BaseModel):
    """Base for environment deployers. Subclass with ``config_type="..."`` to register
    a selectable plugin (matches the attacker/defender/traffic pattern)."""

    _registry: ClassVar[dict[str, type["EnvironmentPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            EnvironmentPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    # -- lifecycle ---------------------------------------------------------
    async def capacity(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig
    ) -> list[tuple[int, int, int]]:
        """(vcpus, ram_mb, disk_gb) for each VM in the topology, incl. the management host —
        the environment's real footprint, for the CapacityTracker's admission math."""
        raise NotImplementedError(f"{type(self).__name__} must implement capacity()")

    async def provision(
        self, experiment: "Experiment", c2c_url: Optional[str], cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> tuple[DeployedEnvironment, Optional[str]]:
        """Emits DEPLOYING -> DEPLOYED (or FAILED) on `lc`."""
        raise NotImplementedError(f"{type(self).__name__} must implement provision()")

    async def configure(
        self,
        experiment: "Experiment",
        mgmt_ip: Optional[str],
        c2c_url: Optional[str],
        cfg: ExperimentManagerConfig,
        setup_play: Optional[str] = None,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Emits CONFIGURING -> CONFIGURED (or FAILED) on `lc`."""
        raise NotImplementedError(f"{type(self).__name__} must implement configure()")

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Pull host logs into the experiment's output tree before teardown. Best-effort."""
        raise NotImplementedError(f"{type(self).__name__} must implement collect()")

    async def teardown(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Emits TEARING_DOWN -> TORN_DOWN (or FAILED) on `lc`."""
        raise NotImplementedError(f"{type(self).__name__} must implement teardown()")

    # -- spec production (the env is the producer of the agent-facing specs + setup access) ------
    # Agent-facing (safe to hand the LLM); Setup-facing (harness-only, creds+routing, never to the agent).
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        """AGENT-FACING AttackerEnvSpec: objective + foothold identity (no creds/routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_spec()")

    def attacker_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        """HARNESS-ONLY list[SetupAccess] for the attacker's foothold(s) (key + routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_setup_access()")

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        """AGENT-FACING DefenderEnvSpec: objective + host inventory (no creds/routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_spec()")

    def defender_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        """HARNESS-ONLY list[SetupAccess] for the victims the defender may reach (key + routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_setup_access()")
