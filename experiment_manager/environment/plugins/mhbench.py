"""MHBench environment plugin — a wrapper making MHBench compatible with the harness.

The environment is identified by `environment_spec` — a PATH to a topology JSON (absolute, or relative
to mhbench_dir, e.g. 'environments/instrumented/equifax_small_instrumented.json'). Stage 1a delegation:
lifecycle methods call the existing (live-validated) environment functions, which resolve the path via
deployer.resolve_topology_path. The short label (Incalmo's env name) is the path stem.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema
from ..models import DeployedEnvironment
from ..lifecycle import EnvironmentLifecycle, EnvironmentSignal
from .base import EnvironmentPlugin

if TYPE_CHECKING:
    from ...experiment import Experiment


class MHBenchEnvironment(EnvironmentPlugin, config_type="mhbench"):
    """Deploys an MHBench topology by name (environments/<environment_spec>.json)."""

    type: Literal["mhbench"] = "mhbench"
    environment_spec: str  # PATH to a topology JSON (abs, or relative to mhbench_dir)

    @property
    def spec(self) -> str:
        """The short env label (Incalmo's env name) — the topology file's stem."""
        return Path(self.environment_spec).stem

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "mhbench",
            "label": "MHBench",
            "cartesian_product": False,
            "fields": [
                {"field_type": "text", "label": "Environment spec (path to topology JSON)",
                 "key": "environment_spec"},
            ],
        }

    async def capacity(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig
    ) -> list[tuple[int, int, int]]:
        from ..capacity import count_vm_specs
        from ..deployer import resolve_topology_path
        topology_path = resolve_topology_path(self.environment_spec, cfg)
        return await count_vm_specs(topology_path, cfg.mhbench_dir,
                                    flavor_cpu_cost=(cfg.gcp_flavor_cpu_cost or None))

    async def provision(
        self, experiment: "Experiment", c2c_url: Optional[str], cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> tuple[DeployedEnvironment, Optional[str]]:
        from ..deployer import provision_environment
        if lc:
            lc.emit(EnvironmentSignal.DEPLOYING)
        try:
            result = await provision_environment(experiment, c2c_url, cfg)
        except Exception as e:  # noqa: BLE001 — record FAILED then re-raise for the arena to handle
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.DEPLOYED)
        return result

    async def configure(
        self,
        experiment: "Experiment",
        mgmt_ip: Optional[str],
        c2c_url: Optional[str],
        cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        from ..deployer import configure_environment
        from ..rotate import rotate_environment
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURING)
        try:
            await configure_environment(experiment, mgmt_ip, c2c_url, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        # MHBench wrapper detail: rotate the host logs right after configuring so setup activity is
        # cleared before the attack (a clean ground-truth baseline). Internal to this plugin — NOT on
        # the base interface, and the arena never calls it. Best-effort: a rotation failure never fails
        # configure.
        try:
            await rotate_environment(experiment, cfg)
        except Exception:  # noqa: BLE001
            pass
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURED)

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        from ..collect import collect_environment
        await collect_environment(experiment, cfg)

    # -- spec production (delegates to the deployer adapters; env is the producer) ----------------
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        from ..deployer import attacker_env_spec
        return attacker_env_spec(deployed, cfg)

    def attacker_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        from ..deployer import attacker_setup_access
        return attacker_setup_access(deployed, mgmt_ip, cfg)

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        from ..deployer import defender_env_spec
        return defender_env_spec(deployed, cfg)

    def defender_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        from ..deployer import defender_setup_access
        return defender_setup_access(deployed, mgmt_ip, cfg)

    async def teardown(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        from ..teardown import teardown_environment
        if lc:
            lc.emit(EnvironmentSignal.TEARING_DOWN)
        try:
            await teardown_environment(experiment, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.TORN_DOWN)
