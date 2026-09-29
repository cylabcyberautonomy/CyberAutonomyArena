"""MHBench environment plugin — a wrapper making MHBench compatible with the harness.

Stage 1a: delegates to the existing (live-validated) environment functions, so behavior is
identical. Later stages move the bodies in, emit the agent-facing DefenderEnvSpec / AttackerEnvSpec
+ the SetupAccess list, provision the defender box, and stand up the per-experiment telemetry broker.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Optional

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema
from ..models import DeployedEnvironment
from ..lifecycle import EnvironmentLifecycle, EnvironmentSignal
from .base import EnvironmentPlugin

if TYPE_CHECKING:
    from ...experiment import Experiment


class MHBenchEnvironment(EnvironmentPlugin, config_type="mhbench"):
    """Deploys an MHBench topology by name (`spec`), via the MHBench CLI."""

    type: Literal["mhbench"] = "mhbench"
    spec: str  # MHBench environment name, e.g. "equifax_small_instrumented"

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "mhbench",
            "label": "MHBench",
            "cartesian_product": False,
            "fields": [
                {"field_type": "text", "label": "Environment spec", "key": "spec"},
            ],
        }

    async def capacity(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig
    ) -> list[tuple[int, int, int]]:
        from ..capacity import count_vm_specs
        topology_path = cfg.mhbench_dir / "environments" / f"{self.spec}.json"
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
        setup_play: Optional[str] = None,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        from ..deployer import configure_environment
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURING)
        try:
            await configure_environment(experiment, mgmt_ip, c2c_url, cfg, setup_play=setup_play)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURED)

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        from ..collect import collect_environment
        await collect_environment(experiment, cfg)

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
