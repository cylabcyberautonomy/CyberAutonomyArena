"""Base class for the environment plugin — one of the selectable systems
(environment / attacker / defender).

An environment plugin deploys and tears down the network an experiment runs on, sizes it for
admission, and produces the run specs (plus the setup access) the attacker and
defender need. See the repo-root ``CLAUDE.md`` ("Adding an ENVIRONMENT plugin") for how to add one.

Lifecycle the arena drives:
    capacity(experiment, cfg)                    -> [(vcpus, ram_mb, disk_gb), ...]  # admission sizing
    provision(experiment, c2c_url, cfg)          -> (DeployedEnvironment, bastion_ip)
    configure(experiment, bastion_ip, c2c_url, cfg) -> None
    collect(experiment, cfg)                     -> None   # pull host logs before teardown
    teardown(experiment, cfg)                    -> None
"""
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
    """Base for environment deployers. Subclass with ``config_type="..."`` to register
    a selectable plugin (matches the attacker/defender pattern)."""

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
        """The resolved, canonical identifier of the environment to deploy, which the arena stamps into
        DeployedEnvironment.topology_spec before provisioning. Default: the raw environment_spec. A
        backend whose spec needs resolving (MHBench resolves a topology PATH) overrides this."""
        return getattr(self, "environment_spec", "")

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
        bastion_ip: Optional[str],
        c2c_url: Optional[str],
        cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Emits CONFIGURING -> CONFIGURED (or FAILED) on `lc`. Any environment-specific
        post-configure step (e.g. MHBench log rotation) is internal to the plugin."""
        raise NotImplementedError(f"{type(self).__name__} must implement configure()")

    async def collect(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Pull host logs into the experiment's output tree before teardown. Best-effort."""
        raise NotImplementedError(f"{type(self).__name__} must implement collect()")

    @classmethod
    async def clean_slate(cls, cfg: ExperimentManagerConfig) -> None:
        """Reset this backend's GLOBAL state at manager startup — plugin-agnostically, the same way the
        arena asks every attacker TYPE to sweep_stale_state(). The arena calls clean_slate() on EVERY
        registered environment plugin at startup and NEVER touches the backend itself, so all backend
        reset (e.g. wiping leftover cloud resources, setting OS_CLOUD) lives here, in the backend that
        owns it. Default: no-op — a backend with nothing global to reset. Must be best-effort (log and
        continue if the backend is unreachable)."""
        return None

    async def teardown(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig,
        lc: Optional[EnvironmentLifecycle] = None,
    ) -> None:
        """Reclaim EVERYTHING this environment created for the experiment, then emit
        TEARING_DOWN -> TORN_DOWN (or FAILED) on `lc`.

        CONTRACT: "everything" includes hosts added dynamically via add_host DURING the run (decoys,
        restored VMs), not just the initial topology. The arena does NOT hand teardown a list of what was
        added — decoy teardown is the ENVIRONMENT's job, never the arena's or the defender's (the defender
        is backend-agnostic and never touches the cloud). So an environment that implements add_host MUST
        track what it created and reap it here. HOW it tracks that is this backend's PRIVATE business and
        is NOT part of this interface — a cloud tag, an own-side registry, or a naming scheme are all fine
        (MHBench stamps an `arena_dynamic_host` metadata tag on each add_host VM and sweeps tagged servers
        on this experiment's networks before the topology teardown). A backend that supports_dynamic_topology()
        but leaks add_host'd hosts here is in violation of this contract."""
        raise NotImplementedError(f"{type(self).__name__} must implement teardown()")

    # -- spec production (the env is the producer of the agent-facing specs + setup access) ------
    # Run spec (objective + identity, the runtime info the agent acts on); Setup access (creds+routing the
    # plugin uses at setup time). Split by purpose (runtime vs setup), not secrecy.
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
        """SETUP ACCESS: list[SetupAccess] for the victims (+ the defender box) the defender may reach
        (key + routing)."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_setup_access()")

    # -- per-system credential issuance (the environment's job) ----------------------------------
    # MHBench today injects ONE keypair as root on EVERY host — a god-key. Leaked to the attacker it is
    # `ssh root@victim` east-west, winning without exploitation (bastion isolation doesn't cover
    # east-west). So the environment MUST issue SEPARATE per-system credentials, each scoped to its own
    # boxes. INVARIANT: no credential in a system's SetupAccess may grant access that system couldn't
    # legitimately earn by playing the game (attacker key opens its foothold and nothing else).
    def attacker_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        """The credential issued for the attacker — scoped to the attacker's foothold box(es) ONLY
        (never victims/defender/bastion/relay). Stamped into attacker SetupAccess."""
        raise NotImplementedError(f"{type(self).__name__} must implement attacker_credential()")

    def defender_credential(self, deployed, cfg: ExperimentManagerConfig) -> str:
        """The credential issued for the defender — scoped to the defender box + the victims it may act
        on (legit); NOT the attacker box. Stamped into defender SetupAccess."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_credential()")

    # The management/provisioning credential (broad) is harness-side, used to deploy/configure, and is
    # NEVER placed in any spec — so it has no accessor here (it stays internal to the plugin's deploy path).

    # -- generic infra guarantees every environment provides (backend-agnostic) ------------------
    # These make "always-provisioned defender box" and "open the box ingress the defender asked for"
    # part of the ENVIRONMENT interface, not an MHBench-specific hack — any backend plugin must
    # implement them too.
    def defender_box(self, deployed, cfg: ExperimentManagerConfig):
        """The always-provisioned DefenderBox (isolated subnet) the defender runs on. Every environment
        MUST provide one; it is reachable via the defender_setup_access entry of the same name, and is
        hidden from the attacker (management-plane isolation is the environment's responsibility)."""
        raise NotImplementedError(f"{type(self).__name__} must implement defender_box()")

    def provides_defender_box(self, deployed, cfg: ExperimentManagerConfig) -> bool:
        """Whether this environment provisioned a REAL defender box for `deployed`. The arena gates its
        env↔defender contract on this (a configured defender requires a box). Default: true when
        defender_box() yields one. A backend whose defender_box() falls back to a shared host when no
        isolated box exists overrides this to report the real box only."""
        return self.defender_box(deployed, cfg) is not None

    async def program_ingress(self, experiment, bastion_ip, cfg: ExperimentManagerConfig, ingress: dict) -> None:
        """Open EXACTLY the box ingress the defender declared (ingress = {"telemetry": [ports],
        "forward": [ports]}). telemetry → route the relay to box:port; forward → victim→mgmt:port→box:port.
        The environment assumes NO defender port; a defender that declares {} opens nothing (box stays
        fully isolated). Default no-op so a backend without a relay/forwarder is still valid."""
        return None

    # -- dynamic topology mutation (defender-driven, DURING the run) ------------------------------
    # The dynamic counterpart to program_ingress above (which is declarative + one-shot at arm time). A
    # RUNNING defender sends EnvActionRequest events to the arena, which calls handle_env_request here.
    # The environment — the only party holding the management/cloud credential — actuates on its backend
    # and returns an EnvActionResult (an ADD_HOST comes back with a DEFENDER-SCOPED SetupAccess so the
    # defender configures the host itself). This is what lets the Perry actuators that today call
    # `openstack.connect()` directly (DeployDecoy/RestoreServer/ShutdownServer) instead forward the
    # cloud step as a backend-neutral event — fixing the god-key + GCP-lock + admission-bypass problems
    # in one move. Default: UNSUPPORTED (a static environment raises EnvRequestUnsupported); a backend
    # that supports dynamic topology (MHBench) overrides the three primitives below.

    async def handle_env_request(self, experiment, deployed, request, cfg):
        """Dispatch ONE EnvActionRequest to the matching primitive. Plugin-agnostic router so the arena
        calls a single method; a plugin overrides the primitives, not this. The request trace is the
        ARENA's job around this call, not here."""
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
        """Provision ONE bare VM (role/image hint + subnet) and return EnvActionResult with its
        name/ip + a DEFENDER-SCOPED SetupAccess. The env does ONLY the cloud step; the defender runs its
        own sensor-install/vuln/registration over the returned access (the provision/configure split).

        CONTRACT: the env MUST record every host it creates here durably enough that teardown() can
        reclaim it without being told which hosts were added — see teardown()'s contract. The bookkeeping
        mechanism (tag/registry/naming) is this backend's private choice, NOT part of this interface."""
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
        """Whether this environment honours EnvActionRequests at all. The arena uses it to validate the
        env↔defender contract up front: a defender that sets uses_env_actions paired with an env that
        returns False here is a contract violation (fail at deploy, like the defender-box contract), not a
        mid-run surprise. Default: False (static env); MHBench overrides to True."""
        return False
