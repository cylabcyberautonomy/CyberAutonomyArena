"""MHBench environment plugin — deploys an MHBench topology as the experiment's network.

The topology is named by ``environment_spec``: a path to a topology JSON, absolute or relative to
``cfg.mhbench_dir`` (e.g. ``environments/instrumented/equifax_small_instrumented.json``). The short
env label is the path stem. Lifecycle methods delegate to the environment package's functions
(deployer / collect / teardown / rotate), which resolve the path via ``deployer.resolve_topology_path``.
"""
from __future__ import annotations

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
        """The short env label (Incalmo's env name) — the topology file's stem."""
        return Path(self.environment_spec).stem

    def resolve_spec(self, cfg: ExperimentManagerConfig) -> str:
        """The resolved, canonical deploy identifier — MHBench's absolute topology path (the arena
        stamps this into DeployedEnvironment.topology_spec before provisioning)."""
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
                                    flavor_cpu_cost=(cfg.env_backend.gcp_flavor_cpu_cost or None))

    async def provision(
        self, experiment: "Experiment", c2c_url: Optional[str], cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> tuple[DeployedEnvironment, Optional[str]]:
        from .deployer import provision_environment
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
        # Per-system scoped-key injection (attacker_key on the foothold, defender_key on the box +
        # victims) happens inside MHBench's own configure, so it runs on every deploy path.
        # Rotate the host logs right after configuring so setup activity is cleared before the attack
        # (a clean ground-truth baseline). This is internal to the plugin — not on the base interface,
        # and the arena never calls it. Best-effort: a rotation failure never fails configure.
        try:
            await rotate_environment(experiment, cfg)
        except Exception:  # noqa: BLE001
            pass
        if lc:
            lc.emit(EnvironmentSignal.CONFIGURED)

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        from .collect import collect_environment
        await collect_environment(experiment, cfg)

    # -- spec production (the environment is the producer of the agent-facing specs + setup access) --
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import attacker_env_spec
        return attacker_env_spec(deployed, cfg)

    def attacker_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        from .deployer import attacker_setup_access, _bastion_proxy_args
        # The env ISSUES the attacker's scoped credential (foothold-only). Both hops in SetupAccess use
        # it: the final hop opens a shell on the foothold, and the bastion hop tunnels with the SAME key
        # (forward-only on the bastion). The broad management key never enters SetupAccess — assume a
        # plugin may forward SetupAccess to its agent, so nothing in it may out-scope the system.
        cred = self.attacker_credential(deployed, cfg)
        proxy = _bastion_proxy_args(bastion_ip, cred)
        return [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                for a in attacker_setup_access(deployed, bastion_ip, cfg)]

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import defender_env_spec
        spec = defender_env_spec(deployed, cfg)
        spec.box = self.defender_box(deployed, cfg)  # every env provides the defender box
        return spec

    def defender_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        from .deployer import defender_setup_access, _defender_box_host, _bastion_proxy_args
        from ....attacker.env_spec import SetupAccess
        cred = self.defender_credential(deployed, cfg)  # env-issued defender credential (box + victims)
        # Both hops use the scoped defender key: final hop = shell on box/victims, bastion hop = tunnel
        # with the same key (forward-only on the bastion). No management key in SetupAccess (a plugin may
        # forward it to its agent).
        proxy = _bastion_proxy_args(bastion_ip, cred)
        access = [a.model_copy(update={"ssh_key": cred, "ssh_common_args": proxy})
                  for a in defender_setup_access(deployed, bastion_ip, cfg)]
        # When the topology declares a defender_subnet, the deployer already added the REAL box entry
        # (reached via the bastion, like the victims). Only fall back to the mgmt-host placeholder for
        # older topologies without an isolated box, so the defender always has somewhere to run.
        topo = deployed.topology_spec if deployed else None
        has_real_box = bool(topo and Path(topo).exists() and _defender_box_host(topo))
        if not has_real_box and bastion_ip:
            box = self.defender_box(deployed, cfg)
            access.append(SetupAccess(name=box.name, host=bastion_ip, user="root",
                                      ssh_key=cred, ssh_common_args=""))
        return access

    # -- per-system credential issuance -----------------------------------------------------------
    # The environment issues a SEPARATE scoped keypair per system (attacker key on the foothold only,
    # defender key on the box + victims only); the broad management key stays harness-side and is never
    # placed in a spec. MHBench generates and injects these keys during configure.
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "attacker_key")

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        return str(Path(cfg.mhbench_dir) / "keys" / "defender_key")

    # -- generic infra guarantees (defender box) --------------------------------------------------
    def _mgmt_internal_ip(self, cfg: ExperimentManagerConfig) -> str:
        # The management host's internal IP is constant across runs (management.host_ip); reuse the
        # gcp_relay_ip default which already names it.
        return cfg.env_backend.gcp_relay_ip

    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        from .deployer import defender_box_spec
        from ....defender.env_spec import DefenderBox
        # Real, isolated box from the topology's defender_subnet (provisioned by MHBench, live-validated).
        box = defender_box_spec(deployed, cfg)
        if box:
            return box
        # Fallback for topologies without a defender_subnet: co-locate on the (attacker-hidden) mgmt host.
        return DefenderBox(name="defender_box", ip=self._mgmt_internal_ip(cfg), subnet="management")

    def provides_defender_box(self, deployed, cfg: ExperimentManagerConfig) -> bool:
        """Whether a REAL, isolated defender box exists (the topology declared a defender_subnet). The
        arena's env↔defender contract check gates on this. Distinct from defender_box() above, which
        falls back to the mgmt host so a defender always has *somewhere* to run — that fallback must not
        satisfy the contract, so this checks the real box only."""
        from .deployer import defender_box_spec
        return defender_box_spec(deployed, cfg) is not None

    async def program_ingress(self, experiment, bastion_ip, cfg: ExperimentManagerConfig, ingress: dict) -> None:
        # Provision exactly the defender-declared box ingress via MHBench's `request-ingress` (relay
        # dests for telemetry ports; mgmt forward + SG for forward ports). No-op for {} — box isolated.
        from .deployer import request_ingress_env
        await request_ingress_env(experiment, bastion_ip, cfg, ingress)

    async def _teardown_decoys(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Delete any VMs standing on this experiment's networks that aren't topology hosts (decoys) -
        before the network teardown. A defender's DeployDecoy actuator creates OpenStack servers directly
        via openstacksdk, outside the topology JSON, so teardown_environment has no idea they exist; if
        left alive they keep this experiment's security groups "in use", and MHBench's teardown deletes in
        order and aborts on the first ConflictException, leaking every network/subnet/security-group for
        the whole experiment right along with the decoy (confirmed live, repeatedly). Reaping stray VMs on
        our own networks is the environment's job, not the defender's (the defender is backend-agnostic;
        deleting a VM is not).

        Identified by the experiment-name prefix, not a decoy name pattern: every server MHBench
        provisions is named "<experiment_name>-<host>" (see HostDeployer._n), while DeployDecoy creates
        servers under the bare `action.host_name` with no prefix. So on this experiment's own networks,
        "unprefixed" is exactly "not a real topology host" - i.e. a decoy. Cross-referencing the network
        name ("<experiment_name>-<subnet_name>") keeps this scoped to this experiment even under
        concurrency. Looked up via Neutron ports (device_id=server.id), not server.addresses: addresses is
        empty while a server is still BUILD (a slow/stuck decoy - exactly the case this must catch), but a
        port with its network exists as soon as create_server() returns.

        Best-effort: never fails teardown. No-op on backends without this escape hatch."""
        if cfg.env_backend.cloud_backend == "gcp":
            return  # GCP decoys are named/reaped by MHBench's own teardown; no stray-VM sweep needed
        import asyncio
        import openstack

        def _sync() -> None:
            conn = openstack.connect(cloud=cfg.env_backend.os_cloud)
            prefix = f"{experiment.experiment_name}-"
            for server in conn.compute.servers():
                if (server.name or "").startswith(prefix):
                    continue  # a real MHBench-provisioned host, not a decoy
                network_ids = {port.network_id for port in conn.network.ports(device_id=server.id)}
                network_names = {conn.network.get_network(nid).name for nid in network_ids}
                if not any(name.startswith(prefix) for name in network_names):
                    continue
                conn.compute.delete_server(server, ignore_missing=True)
                conn.compute.wait_for_delete(server, wait=120)

        try:
            await asyncio.get_event_loop().run_in_executor(None, _sync)
        except Exception:  # noqa: BLE001 — a decoy sweep failure must not block reclaiming the env's VMs
            pass

    # -- dynamic topology mutation (defender-driven, during the run) ------------------------------
    def supports_dynamic_topology(self) -> bool:
        """MHBench honours EnvActionRequests via per-host CLI subcommands (below)."""
        return True

    async def add_host(self, experiment, deployed, request, cfg):
        """Provision ONE host via MHBench (cloud op stays in MHBench — no god-key leaves the env) and
        return its name/ip + a DEFENDER-SCOPED, box-relative SetupAccess so the box agent can configure
        it in-env. role maps to the backend image inside MHBench (e.g. apache_vuln -> webserver image)."""
        import asyncio
        from ...env_requests import EnvActionResult, EnvActionKind
        from .deployer import _host_op_sync, new_host_setup_access
        res = await asyncio.to_thread(
            _host_op_sync, "add-host", experiment.experiment_name, self.environment_spec, cfg,
            name=request.name, role=(request.role or "decoy"), subnet=request.subnet)
        ip, name = res.get("ip"), (res.get("name") or request.name)
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
        """Delete one existing host (returns its budget slot to the defender's pool)."""
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
        # Sweep stray decoy VMs on this experiment's networks first, so the network teardown below doesn't
        # abort on a security group a decoy still holds "in use" (see _teardown_decoys).
        await self._teardown_decoys(experiment, cfg)
        try:
            await teardown_environment(experiment, cfg)
        except Exception as e:  # noqa: BLE001
            if lc:
                lc.emit(EnvironmentSignal.FAILED, str(e))
            raise
        if lc:
            lc.emit(EnvironmentSignal.TORN_DOWN)
