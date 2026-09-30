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
        from ..deployer import configure_environment, inject_scoped_keys_env
        from ..rotate import rotate_environment
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURING)
        try:
            await configure_environment(experiment, mgmt_ip, c2c_url, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        # Issue + inject the per-system scoped keys (attacker_key on the foothold, defender_key on the
        # box+victims) BEFORE rotate, so this setup activity is cleared from the ground-truth baseline.
        # Best-effort: a per-host injection failure is logged, never fails configure.
        try:
            await inject_scoped_keys_env(experiment, mgmt_ip, cfg)
        except Exception:  # noqa: BLE001
            pass
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
        from ..deployer import attacker_setup_access, _bastion_proxy_args
        # The env ISSUES the attacker's scoped credential (foothold-only). Both hops in SetupAccess use
        # it: the final hop opens a shell on the foothold, and the bastion hop tunnels with the SAME key
        # (forward-only on the bastion). The broad management key never enters SetupAccess — assume a
        # plugin may forward SetupAccess to its agent, so nothing in it may out-scope the system.
        cred = self.attacker_credential(deployed, cfg)
        proxy = _bastion_proxy_args(mgmt_ip, cred)
        return [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                for a in attacker_setup_access(deployed, mgmt_ip, cfg)]

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        from ..deployer import defender_env_spec
        spec = defender_env_spec(deployed, cfg)
        spec.box = self.defender_box(deployed, cfg)  # every env provides the defender box
        return spec

    def defender_setup_access(self, deployed, mgmt_ip, cfg: ExperimentManagerConfig):
        from ..deployer import defender_setup_access, _defender_box_host, _bastion_proxy_args
        from ...attacker.env_spec import SetupAccess
        cred = self.defender_credential(deployed, cfg)  # env-issued defender credential (box + victims)
        # Both hops use the scoped defender key: final hop = shell on box/victims, bastion hop = tunnel
        # with the same key (forward-only on the bastion). No management key in SetupAccess (a plugin may
        # forward it to its agent).
        proxy = _bastion_proxy_args(mgmt_ip, cred)
        access = [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                  for a in defender_setup_access(deployed, mgmt_ip, cfg)]
        # When the topology declares a defender_subnet, the deployer already added the REAL box entry
        # (reached via the bastion, like the victims). Only fall back to the mgmt-host placeholder for
        # older topologies without an isolated box, so the defender always has somewhere to run.
        topo = deployed.topology_spec if deployed else None
        has_real_box = bool(topo and Path(topo).exists() and _defender_box_host(topo))
        if not has_real_box and mgmt_ip:
            box = self.defender_box(deployed, cfg)
            access.append(SetupAccess(name=box.name, host=mgmt_ip, user="root",
                                      ssh_key=cred, ssh_common_args=""))
        return access

    # -- per-system credential issuance -----------------------------------------------------------
    # DEFERRED live-injection: MHBench today injects ONE god-key everywhere; issuing SEPARATE per-system
    # keypairs (attacker key on the foothold only, defender key on the box+victims only, management key
    # harness-side) is an MHBench-wrapper provisioning item. Distinct paths here encode the intent; the
    # keygen+injection is the live piece (see ARENA_PLUGIN_REQUIREMENTS.md).
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "attacker_key")

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "defender_key")

    # -- generic infra guarantees (defender box + telemetry relay) --------------------------------
    def _mgmt_internal_ip(self, cfg: ExperimentManagerConfig) -> str:
        # The management host's internal IP is constant across runs (management.host_ip); reuse the
        # gcp_relay_ip default which already names it. This is the fixed relay/bake address.
        return getattr(cfg, "gcp_relay_ip", "10.0.1.10")

    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        from ..deployer import defender_box_spec
        from ...defender.env_spec import DefenderBox
        # Real, isolated box from the topology's defender_subnet (provisioned by MHBench, live-validated).
        box = defender_box_spec(deployed, cfg)
        if box:
            return box
        # Fallback for topologies without a defender_subnet: co-locate on the (attacker-hidden) mgmt host.
        return DefenderBox(name="defender_box", ip=self._mgmt_internal_ip(cfg), subnet="management")

    def telemetry_ingest(self, deployed, cfg: ExperimentManagerConfig):
        from ..telemetry import TelemetryIngest
        # Fixed bake target = the relay on the mgmt host, constant across runs.
        return TelemetryIngest(host=self._mgmt_internal_ip(cfg), port=9200, scheme="tcp")

    async def program_telemetry(self, deployed, cfg: ExperimentManagerConfig, routes) -> None:
        # The socat/Vector fan-out relay on the mgmt host is the not-yet-provisioned item; for now
        # record the intended routes so the wiring is observable. (Grouping by source_channel gives
        # multi-stream routing + same-stream fan-out.)
        from ...experiment_log import log
        for r in (routes or []):
            log(getattr(deployed, "spec", "env") or "env",
                f"telemetry route: {r.source_channel} -> {r.dest} ({r.protocol})")

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
