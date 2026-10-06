"""MHBench environment plugin: deploys an MHBench topology (named by ``environment_spec``) as the experiment's network."""
from __future__ import annotations
from ...config import env_backend  # env-layer backend settings

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from ....config import ExperimentManagerConfig
from ....ui_schema import PluginUISchema
from ...environment import DeployedEnvironment
from ...lifecycle import EnvironmentLifecycle, EnvironmentSignal
from ..base import EnvironmentPlugin

if TYPE_CHECKING:
    from ....experiment import Experiment


class MHBenchEnvironment(EnvironmentPlugin, config_type="mhbench"):
    """Deploys an MHBench topology by name (environments/<environment_spec>.json)."""

    type: Literal["mhbench"] = "mhbench"
    environment_spec: str  # PATH to a topology JSON (abs, or relative to mhbench_dir)

    @property
    def spec(self) -> str:
        """The short env label: the topology file's stem."""
        return Path(self.environment_spec).stem

    def resolve_spec(self, cfg: ExperimentManagerConfig) -> str:
        """The resolved, canonical deploy identifier: MHBench's absolute topology path."""
        from .deployer import resolve_topology_path
        return str(resolve_topology_path(self.environment_spec, cfg))

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
        from .capacity import count_vm_specs
        from .deployer import resolve_topology_path
        topology_path = resolve_topology_path(self.environment_spec, cfg)
        return await count_vm_specs(topology_path, cfg.mhbench_dir,
                                    flavor_cpu_cost=(env_backend(cfg).gcp_flavor_cpu_cost or None))

    async def provision(
        self, experiment: "Experiment", c2c_url: Optional[str], cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> tuple[DeployedEnvironment, Optional[str]]:
        from .deployer import provision_environment
        if lc:
            lc.emit(EnvironmentSignal.DEPLOYING)
        try:
            result = await provision_environment(experiment, c2c_url, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.DEPLOYED)
        return result

    async def configure(
        self,
        experiment: "Experiment",
        bastion_ip: Optional[str],
        c2c_url: Optional[str],
        cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        from .deployer import configure_environment
        from .rotate import rotate_environment
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURING)
        try:
            await configure_environment(experiment, bastion_ip, c2c_url, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        # Rotate the host logs right after configuring for a clean ground-truth baseline. Best-effort.
        try:
            await rotate_environment(experiment, cfg)
        except Exception:  # noqa: BLE001
            pass
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURED)

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        from .collect import collect_environment
        await collect_environment(experiment, cfg)

    @classmethod
    async def clean_slate(cls, cfg: ExperimentManagerConfig) -> None:
        # Backend reset at startup: sets OS_CLOUD and wipes leftover OpenStack resources, or no-ops on GCP.
        from .clean_slate import clean_slate as _mhbench_clean_slate
        await _mhbench_clean_slate(cfg)

    # -- spec production (the environment is the producer of the agent-facing specs + setup access) --
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import attacker_env_spec
        return attacker_env_spec(deployed, cfg)

    def attacker_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        from .deployer import attacker_setup_access, _bastion_proxy_args
        # Both hops in SetupAccess use the scoped foothold-only credential. The management key never enters it.
        cred = self.attacker_credential(deployed, cfg)
        proxy = _bastion_proxy_args(bastion_ip, cred)
        return [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                for a in attacker_setup_access(deployed, bastion_ip, cfg)]

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import defender_env_spec
        spec = defender_env_spec(deployed, cfg)
        spec.box = self.defender_box(deployed, cfg)
        return spec

    def defender_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        from .deployer import defender_setup_access, _defender_box_host, _bastion_proxy_args
        from ....defender.env_spec import DefenderSetupAccess
        cred = self.defender_credential(deployed, cfg)
        # Both hops use the scoped defender key. No management key enters SetupAccess.
        proxy = _bastion_proxy_args(bastion_ip, cred)
        access = [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                  for a in defender_setup_access(deployed, bastion_ip, cfg)]
        # Fall back to the mgmt-host placeholder only for older topologies without an isolated box.
        topo = deployed.topology_spec if deployed else None
        has_real_box = bool(topo and Path(topo).exists() and _defender_box_host(topo))
        if not has_real_box and bastion_ip:
            box = self.defender_box(deployed, cfg)
            access.append(DefenderSetupAccess(name=box.name, host=bastion_ip, user="root",
                                      ssh_key=cred, ssh_common_args=""))
        return access

    # -- per-system credential issuance -----------------------------------------------------------
    # MHBench generates and injects a separate scoped keypair per system during configure.
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "attacker_key")

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "defender_key")

    # -- generic infra guarantees (defender box) --------------------------------------------------
    def _mgmt_internal_ip(self, cfg: ExperimentManagerConfig) -> str:
        # The management host's internal IP is constant across runs. Reuse the gcp_relay_ip default.
        return env_backend(cfg).gcp_relay_ip

    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import defender_box_spec
        from ....defender.env_spec import DefenderBox
        # Real, isolated box from the topology's defender_subnet.
        box = defender_box_spec(deployed, cfg)
        if box:
            return box
        # Fallback for topologies without a defender_subnet: co-locate on the mgmt host.
        return DefenderBox(name="defender_box", ip=self._mgmt_internal_ip(cfg), subnet="management")

    def provides_defender_box(self, deployed, cfg: ExperimentManagerConfig) -> bool:
        """Whether a real, isolated defender box exists (the topology declared a defender_subnet)."""
        from .deployer import defender_box_spec
        return defender_box_spec(deployed, cfg) is not None

    async def program_ingress(self, experiment, bastion_ip, cfg: ExperimentManagerConfig, ingress: dict) -> None:
        # Provision exactly the defender-declared box ingress via MHBench's `request-ingress`. No-op for {}.
        from .deployer import request_ingress_env
        await request_ingress_env(experiment, bastion_ip, cfg, ingress)

    async def _teardown_dynamic_hosts(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Remove the dynamically-added decoy VMs on this experiment's networks before the network teardown.

        A decoy is a server tagged arena_dynamic_host (the add_host path) or unprefixed (the legacy
        actuator), on one of this experiment's networks. Best-effort: never fails teardown."""
        if env_backend(cfg).cloud_backend == "gcp":
            return  # MHBench's own teardown reaps GCP decoys
        import asyncio
        import openstack

        def _sync() -> None:
            conn = openstack.connect(cloud=env_backend(cfg).os_cloud)
            prefix = f"{experiment.experiment_name}-"
            for server in conn.compute.servers(details=True):
                name = server.name or ""
                md = server.metadata or {}
                # A decoy has the arena_dynamic_host tag or no name prefix. A real topology host has the prefix and no tag.
                is_decoy = md.get("arena_dynamic_host") == "true" or not name.startswith(prefix)
                if not is_decoy:
                    continue
                network_ids = {port.network_id for port in conn.network.ports(device_id=server.id)}
                network_names = {conn.network.get_network(nid).name for nid in network_ids}
                if not any(nm.startswith(prefix) for nm in network_names):
                    continue
                conn.compute.delete_server(server, ignore_missing=True)
                conn.compute.wait_for_delete(server, wait=120)

        try:
            await asyncio.get_event_loop().run_in_executor(None, _sync)
        except Exception:  # noqa: BLE001
            pass

    # -- dynamic topology mutation (defender-driven, during the run) ------------------------------
    def supports_dynamic_topology(self) -> bool:
        """MHBench honours EnvActionRequests via per-host CLI subcommands (below)."""
        return True

    async def add_host(self, experiment, deployed, request, cfg):
        """Provision one host via MHBench and return its name/ip + a defender-scoped, box-relative SetupAccess."""
        import asyncio
        from pathlib import Path
        from ....experiment_log import log
        from ...env_requests import EnvActionResult, EnvActionKind
        from .deployer import (_host_op_sync, new_host_setup_access, issue_scoped_keys,
                               _inject_pubkey, _mhbench_ssh_key)
        res = await asyncio.to_thread(
            _host_op_sync, "add-host", experiment.experiment_name, self.environment_spec, cfg,
            name=request.name, role=(request.role or "decoy"), subnet=request.subnet)
        ip, name = res.get("ip"), (res.get("name") or request.name)
        # Inject the scoped defender pubkey into the new decoy so the box's ConfigureDecoy SSH can reach it.
        # Reach the decoy via the bastion with the mgmt key (the decoy carries that key).
        bastion_ip = getattr(experiment, "_bastion_ip", None)
        if ip and bastion_ip:
            _, dk = issue_scoped_keys(cfg)
            dk_pub = Path(str(dk) + ".pub").read_text().strip()
            mgmt_key = _mhbench_ssh_key(cfg)
            # A just-created decoy needs ~60-90s before sshd accepts connections, so retry the inject.
            ok, attempts = False, 0
            for attempts in range(1, 13):
                ok = await asyncio.to_thread(_inject_pubkey, dk_pub, str(ip), bastion_ip, mgmt_key)
                if ok:
                    break
                await asyncio.sleep(10)
            log(experiment.experiment_name,
                f"add_host: inject defender_key -> decoy {name} ({ip}): "
                f"{'ok' if ok else 'FAILED'} after {attempts} attempt(s)")
        return EnvActionResult(
            kind=EnvActionKind.ADD_HOST, ok=bool(ip), name=name, ip=ip,
            access=new_host_setup_access(name, ip, cfg) if ip else None,
            error=None if ip else "MHBench add-host returned no ip")

    async def rebuild_host(self, experiment, deployed, request, cfg):
        """Rebuild one existing host from its base image (restore a compromised VM)."""
        import asyncio
        from ...env_requests import EnvActionResult, EnvActionKind
        from .deployer import _host_op_sync
        await asyncio.to_thread(_host_op_sync, "rebuild-host", experiment.experiment_name,
                                self.environment_spec, cfg, target=request.target)
        return EnvActionResult(kind=EnvActionKind.REBUILD_HOST, ok=True, name=request.target)

    async def remove_host(self, experiment, deployed, request, cfg):
        """Remove one existing host."""
        import asyncio
        from ...env_requests import EnvActionResult, EnvActionKind
        from .deployer import _host_op_sync
        await asyncio.to_thread(_host_op_sync, "remove-host", experiment.experiment_name,
                                self.environment_spec, cfg, target=request.target)
        return EnvActionResult(kind=EnvActionKind.REMOVE_HOST, ok=True, name=request.target)

    async def teardown(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        from .teardown import teardown_environment
        if lc:
            lc.emit(EnvironmentSignal.TEARING_DOWN)
        # Sweep stray decoy VMs first, so the network teardown below does not abort on a security group in use.
        await self._teardown_dynamic_hosts(experiment, cfg)
        try:
            await teardown_environment(experiment, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.TORN_DOWN)
