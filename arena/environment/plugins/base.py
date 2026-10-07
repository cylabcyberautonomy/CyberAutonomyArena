"""Base class for the environment plugin, one of the selectable systems (environment / attacker / defender)."""
from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema
from ..environment import DeployedEnvironment
from ..lifecycle import EnvironmentLifecycle

if TYPE_CHECKING:
    from ...experiment import Experiment


class EnvironmentPlugin(BaseModel):
    """Base for environment deployers. Subclass with ``config_type="..."`` to register a selectable plugin."""

    _registry: ClassVar[dict[str, type["EnvironmentPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            EnvironmentPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    # -- what to deploy ----------------------------------------------------
    def resolve_spec(self, cfg: ExperimentManagerConfig) -> str:
        """The resolved, canonical identifier of the environment to deploy. Default: the raw environment_spec."""
        return getattr(self, "environment_spec", "")

    # -- lifecycle ---------------------------------------------------------
    async def capacity(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig
    ) -> list[tuple[int, int, int]]:
        """(vcpus, ram_mb, disk_gb) for each VM in the topology, including the management host, for admission."""
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
        bastion_ip: Optional[str],
        c2c_url: Optional[str],
        cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Emits CONFIGURING -> CONFIGURED (or FAILED) on `lc`. Any post-configure step is internal to the plugin."""
        raise NotImplementedError(f"{type(self).__name__} must implement configure()")

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Pull host logs into the experiment's output tree before teardown. Best-effort."""
        raise NotImplementedError(f"{type(self).__name__} must implement collect()")

    @classmethod
    async def clean_slate(cls, cfg: ExperimentManagerConfig) -> None:
        """Reset this backend's global state at manager startup. Default: no-op. Must be best-effort."""
        return None

    async def teardown(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Reclaim everything this environment created for the experiment, then emit TEARING_DOWN -> TORN_DOWN (or FAILED).

        The contract covers hosts added via add_host during the run (decoys, restored VMs), not just the
        initial topology. An environment that implements add_host MUST track what it created and reap it here."""
        raise NotImplementedError(f"{type(self).__name__} must implement teardown()")

    # -- spec production (the env produces the agent-facing specs + setup access) ------
    def attacker_spec(self, deployed, cfg: ExperimentManagerConfig):
        """AGENT-FACING AttackerEnvSpec: objective + foothold identity (no creds/routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_spec()")

    def attacker_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        """SETUP ACCESS: list[SetupAccess] for the attacker's foothold(s) (setup-time key + routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_setup_access()")

    def defender_spec(self, deployed, cfg: ExperimentManagerConfig):
        """AGENT-FACING DefenderEnvSpec: objective + host inventory (no creds/routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_spec()")

    def defender_setup_access(self, deployed, bastion_ip, cfg: ExperimentManagerConfig):
        """SETUP ACCESS: list[SetupAccess] for the victims (+ the defender box) the defender may reach."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_setup_access()")

    # -- per-system credential issuance (the environment's job) ----------------------------------
    # The environment issues separate per-system credentials, each scoped to that system's own boxes.
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        """The credential issued for the attacker, scoped to the attacker's foothold box(es) only."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_credential()")

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        """The credential issued for the defender, scoped to the defender box + the victims it may act on."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_credential()")

    # The broad management credential stays harness-side and is never placed in any spec, so it has no accessor here.

    # -- generic infra guarantees every environment provides (backend-agnostic) ------------------
    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        """The always-provisioned DefenderBox (isolated subnet) the defender runs on. Every environment provides one."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_box()")

    def provides_defender_box(self, deployed, cfg: ExperimentManagerConfig) -> bool:
        """Whether this environment provisioned a real defender box for `deployed`. Default: true when defender_box() yields one."""
        return self.defender_box(deployed, cfg) is not None

    async def program_ingress(self, experiment, bastion_ip, cfg: ExperimentManagerConfig, ingress: dict) -> None:
        """Open exactly the box ingress the defender declared. {} opens nothing. Default no-op."""
        return None

    # -- dynamic topology mutation (defender-driven, during the run) ------------------------------
    # A running defender sends EnvActionRequest events to the arena, which calls handle_env_request here.
    # Default: unsupported (a static environment raises EnvRequestUnsupported). MHBench overrides the primitives below.

    async def handle_env_request(self, experiment, deployed, request, cfg):
        """Dispatch one EnvActionRequest to the matching primitive. A plugin overrides the primitives, not this."""
        from ..env_requests import EnvActionKind, EnvRequestUnsupported
        fn = {
            EnvActionKind.ADD_HOST: self.add_host,
            EnvActionKind.REMOVE_HOST: self.remove_host,
            EnvActionKind.REBUILD_HOST: self.rebuild_host,
        }.get(request.kind)
        if fn is None:
            raise EnvRequestUnsupported(f"{type(self).__name__} has no handler for {request.kind}")
        return await fn(experiment, deployed, request, cfg)

    async def add_host(self, experiment, deployed, request, cfg):
        """Provision one bare VM and return EnvActionResult with its name/ip + a defender-scoped SetupAccess.

        The env MUST record every host it creates here durably enough that teardown() can reclaim it."""
        from ..env_requests import EnvRequestUnsupported
        raise EnvRequestUnsupported(f"{type(self).__name__} does not support add_host")

    async def remove_host(self, experiment, deployed, request, cfg):
        """Delete one existing host (ShutdownServer)."""
        from ..env_requests import EnvRequestUnsupported
        raise EnvRequestUnsupported(f"{type(self).__name__} does not support remove_host")

    async def rebuild_host(self, experiment, deployed, request, cfg):
        """Rebuild one existing host from its base image (RestoreServer) — restore a compromised VM."""
        from ..env_requests import EnvRequestUnsupported
        raise EnvRequestUnsupported(f"{type(self).__name__} does not support rebuild_host")

    def supports_dynamic_topology(self) -> bool:
        """Whether this environment honours EnvActionRequests at all. Default: False. MHBench overrides to True."""
        return False
