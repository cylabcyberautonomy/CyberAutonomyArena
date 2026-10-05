import asyncio
import json
import os
import signal
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import log, output_root
from ...ui_schema import PluginUISchema
from ..env_spec import DefenderSetupAccess
from ..lifecycle import DefenderSignal
from ...env_action_server import resolve_socket_path


class PreparedDefender(BaseModel):
    """The setup-produced data baton handed provision_box() -> build_config() -> run(). OPAQUE at the base
    (empty, exactly like PreparedAttacker): a defender with box telemetry subclasses this with its OWN
    fields (es_url / indices / box-agent endpoint) and bakes them in its OWN build_config; a defender with
    no box telemetry (canary / velociraptor) produces this empty baton as-is. Mirrors PreparedAttacker + a
    C2 attacker's own Prepared subclass (e.g. IncalmoPreparedC2)."""


class DefenderPlugin(BaseModel):
    """Base class for a defender plugin. Its members fall into two groups (symmetric with AttackerPlugin).

    PLUGIN SURFACE — what you implement / override:
      Required:
        build_config(experiment_name, env_spec, prepared) -> dict  the contents of the runner's config file
        ui_schema() -> PluginUISchema                              the dashboard form for this plugin
        run(config_path, experiment_name, cfg)                     launch the reactive-loop process
      Optional HOOKS the setup() template calls (the base provides a safe default — override the HOOK, not
      setup()):
        provision_box(...) -> PreparedDefender  stand up the per-exp box ES / box agent (or other infra,
                                                e.g. velociraptor's server/clients); returns the baton the
                                                plugin's build_config bakes in           (default: empty baton)
        prepare(config_path, ...)               EXTERNAL arming (deploy decoys / plant honey-creds),
                                                reads the written config                 (default: no-op)
        teardown(experiment_name, cfg)          release host-side resources at env teardown (default: no-op)
        box_ingress() -> {kind: [ports]}        box ports the env should open            (default: {} = none)
        defender_vm_budget() -> [(vcpu,ram,disk)]  decoy VMs this defender may create    (default: [] = none)
        REQUIRED_CONFIG_KEYS / code_dir_field / code_python_field / executes_from_box  — declarations.

    FRAMEWORK — the arena calls these; do NOT override:
        run_setup(experiment, cfg) -> PreparedDefender — the SETUP phase the arena drives: emits
            SETUP_STARTED, then calls setup(). Shape-identical to the attacker's run_setup (a bare setup()).
        setup(experiment, cfg, bastion_ip, access) -> PreparedDefender — the arming TEMPLATE (do NOT
            override — override the provision_box()/prepare() hooks instead). It runs provision_box() +
            _write_runner_config (build_config + inject creds/routing + write) + prepare(), fully arming the
            defender. The arena never calls your provision_box()/prepare()/build_config() directly.
        wait_until_ready / ready_marker_path / clear_ready_marker — the readiness-marker gate: the arena
            blocks on it before the attacker runs; your RUNNER touches the marker once its loop is armed.
        validate_built_config, __init_subclass__ (registration), _lifecycle.
      Helpers you MAY call (not override): _code_dir(cfg) / _code_python(cfg). (defender_env_spec + the box
      baton are forwarded into the runner config by run_setup, so build_config never emits them itself — it
      just RECEIVES env_spec/prepared as args and may read them. The subprocess launch + prepare-mode wait
      are Perry-only and inlined in the Defense/Perry defenders that use them, not here.)
    """

    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    # Keys this plugin's runner REQUIRES in build_config()'s output — the plugin↔runner contract, declared
    # as data (symmetric with AttackerPlugin). The arena validates build_config()'s output against this
    # (before it injects the arena-provided keys like defender_env_spec), and the conformance test checks
    # it generically. Empty = no declared contract. Declare only keys build_config() itself always emits —
    # NOT the arena-injected ones (defender_env_spec / defender_setup_access / management_ip / …).
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # Per-plugin external code path: a defender backed by an external repo (the Defense/Perry defenders)
    # names its own config fields here, so no single field silently backs several plugins. Default None =
    # self-contained defender (canary) or a backend-specific one (velociraptor reads its own velociraptor_dir).
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    # Whether this defender executes its actions FROM THE DEFENDER BOX (in-env) via the box agent +
    # the env action channel, rather than from the arena host. When True the arena always deploys the box
    # agent and arms the env channel (box execution is the ONLY path — there is no arena-execution
    # orchestrator any more). Checks-only/self-contained defenders (canary, velociraptor) leave it False.
    executes_from_box: ClassVar[bool] = False

    # Whether this defender issues ENV ACTIONS (restore / BlockIP / deploy-decoy) that need the arena's
    # environment-plugin connection — i.e. it uses the token'd TCP env-action channel + the dynamic serving
    # window + a mid-run VM budget. The arena keys the env-channel (sets the token + box/tcp ports, starts
    # serve_env_actions_tcp) and the serving window on THIS, independent of where the runner physically runs
    # (a box-resident defender opens its own ssh -R tunnel to reach the channel — see llm_soc_box). Default
    # False = a detect-only defender (canary, a plain SOC) that mutates nothing and needs no channel.
    uses_env_actions: ClassVar[bool] = False

    def __init_subclass__(cls, config_type: str = None, **kwargs):  # FRAMEWORK: plugin registration
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            cls._registry[config_type] = cls

    # ========================================================================
    # PLUGIN SURFACE — implement / override these. (Required: build_config, ui_schema, run().)
    # ========================================================================

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        env_spec,
        prepared: "PreparedDefender",
    ) -> dict: ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """REQUIRED (unless you override start()). Launch the defender run loop and return it. start() calls
        this by default; override start() instead — e.g. a box-resident defender launching over SSH — if you
        need the scoped access at launch. Mirrors AttackerPlugin.run()."""
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def start(
        self,
        prepared: "PreparedDefender",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """OPTIONAL (default: call run()). Launch the defender run loop. Mirrors AttackerPlugin.start();
        the run_start wrapper calls this with the scoped `access`. The default runs run() as a local harness
        subprocess and ignores `prepared`/`access`. A box-resident defender OVERRIDES this to launch its
        runner ON THE BOX over SSH via `access` (and, if it issues env actions, to open its own ssh -R
        tunnel first) — the box-launch machinery lives on that plugin, not here (see llm_soc_box / canary)."""
        return await self.run(config_path, experiment_name, cfg)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        """OPTIONAL. Terminate the defender process. Local pid here (mirrors AttackerPlugin.stop) — for a
        box-resident defender this is the local `ssh -tt` process, whose SIGTERM tears the remote runner
        down with it; a plugin that needs a cleaner remote kill overrides this to use `access`."""
        if getattr(experiment, "defender_pid", None):
            try:
                os.kill(experiment.defender_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """OPTIONAL. Pull defender-side logs into dest. Default no-op — the harness-run defender's logs are
        already local. A box-resident defender overrides this to pull its box logs via `access`, mirroring
        AttackerPlugin.collect_logs."""

    @classmethod
    def example_prepared(cls) -> "PreparedDefender":
        """OPTIONAL. A representative PreparedDefender for exercising build_config() OFFLINE — without
        provision_box() or a cloud/box ES. Twin of AttackerPlugin.example_prepared: the default empty baton
        suits defenders whose build_config() ignores `prepared`; a telemetry defender that reads es_url /
        indices off its baton overrides this so the coupling is discoverable and conformance tests
        (tests/test_plugin_conformance.py) can build its config without provision_box()."""
        return PreparedDefender()

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedDefender":
        """Fully ARM the defender and RETURN its baton — the single arming entry, shape-identical to the
        attacker's setup(): stand up box infra (provision_box) → build + write the runner config → external
        arming (prepare) → return the baton. run_setup() just calls this, so BOTH agents' run_setup are the
        same shape (bare setup() call). Plugins override the HOOKS provision_box()/prepare() + build_config(),
        NOT setup() itself (the template).

        `access` is the scoped DefenderSetupAccess list (key + bastion routing); env_spec and the
        dynamic-topology flag are read off `experiment` (mirroring the attacker reading
        experiment._attacker_env_spec). `bastion_ip` is this experiment's own bastion floating IP — NOT
        cfg.arena_host_ip (the harness's own fixed address). Raising here fails the defender start."""
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec        # agent-facing DefenderEnvSpec (host inventory, NO creds)
        # If the arena stood up a TOKEN'd TCP env-action channel for this experiment (a uses_env_actions
        # BOX-RESIDENT defender — whose plugin opens its own ssh -R tunnel to it), bake the box-loopback url +
        # token into the runner config. Keyed on the arena having set the port/token, NOT on where the runner
        # runs.
        box_channel = None
        if getattr(experiment, "_env_action_box_port", None) and getattr(experiment, "_env_action_token", None):
            box_channel = {"env_action_url": f"http://127.0.0.1:{experiment._env_action_box_port}",
                           "env_action_token": experiment._env_action_token}
        # Otherwise, a HARNESS-RUN executes_from_box controller reaches the env-action channel over the
        # tokenless UDS (+ a thin box agent for host actions). The UDS and the box agent are armed only when
        # the dynamic window is open (experiment._env_dynamic) AND there is no TCP box_channel (a box-resident
        # engine uses neither — it reaches victims itself and the env over its tunnel).
        env_action_socket = (resolve_socket_path(cfg)
                             if getattr(experiment, "_env_dynamic", False) and box_channel is None else None)
        needs_agent = env_action_socket is not None
        # HOOK A — stand up the per-experiment box ES / box agent and produce the baton (default: empty).
        prepared = await self.provision_box(
            experiment_name, cfg, bastion_ip,
            defender_env_spec=env_spec, defender_access=access, needs_agent=needs_agent)
        # build + write the runner config from the baton (credential injection kept out of build_config).
        config_path = self._write_runner_config(
            experiment_name, cfg, env_spec, access, bastion_ip, prepared, env_action_socket, box_channel)
        # HOOK B — EXTERNAL arming (deploy decoys / plant honey-creds) that CONSUMES the written config;
        # blocks + raises before the attacker starts (default: no-op). The attacker's twin: it deploys its
        # foothold agent + waits-for-beacon inside its own setup().
        await self.prepare(config_path, experiment_name, cfg)
        log(experiment_name, f"Defender armed ({self.type})")
        return prepared

    def _write_runner_config(self, experiment_name: str, cfg: ExperimentManagerConfig, env_spec, access,
                             bastion_ip, prepared: "PreparedDefender", env_action_socket, box_channel=None) -> Path:
        """FRAMEWORK (called by setup()): build_config(env_spec, baton) → forward the credential-free
        DefenderEnvSpec → INJECT the credential-bearing SetupAccess/routing (kept OUT of build_config's own
        output by the leak guard) + management_ip/bastion_ip/log_dir + the dynamic-topology channel → write
        the runner config. Returns the config path. The written config IS part of arming: prepare() reads
        it, and so does the run loop. (The baton's box fields are baked by each plugin's own build_config —
        PreparedDefender is opaque to the base.)"""
        config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        built = self.build_config(experiment_name, env_spec, prepared)
        type(self).validate_built_config(built)  # fail fast if the config drifts from the runner contract (pre-injection)
        if env_spec is not None:
            built["defender_env_spec"] = env_spec.model_dump()
        # Box-only execution: a HARNESS-RUN executes_from_box controller gets ONLY the box entry — it never
        # acts on victims directly, it asks the box agent (which alone holds victim access) and the env. A
        # box-RESIDENT defender is the opposite: it runs IN-env and reaches victims itself (box-local keys,
        # threaded at launch by the plugin), so it leaves executes_from_box False and keeps the full access.
        _access = list(access or [])
        if getattr(type(self), "executes_from_box", False) and env_spec is not None:
            _box = getattr(env_spec, "box", None)
            _box_ip = getattr(_box, "ip", None) if _box else None
            if _box_ip:
                _access = [a for a in _access if getattr(a, "host", None) == _box_ip]
        built["defender_setup_access"] = [a.model_dump() for a in _access]
        # management_ip is the harness's own fixed host (NOT an ES address); bastion_ip is this experiment's
        # ephemeral bastion FIP the runner ProxyCommands through to reach internal hosts.
        built["management_ip"] = cfg.arena_host_ip
        built["bastion_ip"] = bastion_ip
        built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
        # Dynamic topology-mutation channel. A box-resident defender reaches it over the TOKEN'd TCP tunnel
        # (box-loopback url + token); a harness-run executes_from_box controller over the UDS (no token —
        # unreachable from in-env). The runner's RemoteEnvOrchestrator uses env_action_url+token if present,
        # else env_action_socket.
        if box_channel is not None:
            built["env_action_url"] = box_channel["env_action_url"]
            built["env_action_token"] = box_channel["env_action_token"]
            built["experiment_name"] = experiment_name  # the orchestrator stamps it into each request payload
        elif env_action_socket is not None:
            built["env_action_socket"] = env_action_socket
            built["experiment_name"] = experiment_name
        config_path.write_text(json.dumps(built, indent=2))
        log(experiment_name, f"Prepared defender ({self.type}) config: {config_path}")
        return config_path

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> "PreparedDefender":
        """PHASE A — produce the baton BEFORE build_config (symmetric with the attacker's setup()→prepared).
        A telemetry defender overrides this to stand up its per-experiment box ES (+ the box agent when
        needs_agent) and return a PreparedDefender carrying es_url / falco_index / sysflow_index /
        box_agent_* — which build_config() then bakes into the runner config. Taking env_spec/access as
        args (not reading a written config) is what lets it run before build_config. Default: an empty
        baton, for a defender with no box telemetry (canary / velociraptor)."""
        return PreparedDefender()

    async def prepare(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> "PreparedDefender":
        """EXTERNAL arming phase — the arena calls this AFTER build_config()/config-write and BEFORE
        run(), and blocks on it. A deception defender overrides it to run its strategy's external arming
        (deploy decoys / plant honey-creds) to completion, so the slow, failure-prone arming finishes —
        and raises HERE if it fails — before the attacker starts. It returns a PreparedDefender; run() then
        only launches the reactive loop.

        Default: no-op (an empty baton), for defenders with no external arming (e.g. canary). Whether any
        arming actually happens is the strategy's call (Perry's Strategy.ARMS_IN_SETUP): a strategy that
        arms inside its loop makes this a no-op and keeps using the readiness marker."""
        return PreparedDefender()

    async def teardown(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Best-effort cleanup of harness-side resources this defender created that the
        environment's own teardown doesn't already handle. Runs before the environment
        teardown. Default no-op; the caller (main.py) already wraps this in try/except,
        same best-effort treatment as log collection - a defender teardown failure must
        not block reclaiming the environment's VMs.

        NOTE: stray VMs a defender stood up outside the topology (decoys) are NOT the
        defender's problem to reap - deleting a VM is backend-specific, and defenders are
        backend-agnostic. The ENVIRONMENT sweeps those on its own networks as the first
        step of its teardown (see MHBenchEnvironment._teardown_dynamic_hosts)."""
        return None

    def box_ingress(self) -> dict[str, list[int]]:
        """The defender-requested box-ingress this plugin needs the ENVIRONMENT to open, by kind:

            "telemetry": [9200]  -> the env relay routes sensor telemetry to the box ES on these
                                    ports (no new victim-facing firewall port opens).
            "forward":   [8000]  -> a victim->mgmt->box raw-TCP passthrough + a victim->mgmt SG rule
                                    on these ports (server-mediated EDR clients beacon in).

        The harness reads this at defender arm and calls `request-ingress` with exactly these ports,
        so the box's exposed surface matches precisely what the defender uses. A defender that needs
        nothing returns {} (default) and opens ZERO box ports. Config-aware: e.g. a diagnostic-only
        canary that runs no telemetry checks opens nothing."""
        return {}

    def defender_vm_budget(self) -> list[tuple[int, int, int]]:
        """The MAX extra VMs this defender may spin up during the run, as (vcpus, ram_mb, disk_gb)
        specs — the same shape EnvironmentPlugin.capacity() returns, so the arena simply appends them to
        the topology's footprint at admission. The cluster then holds room for `topology + this budget`
        BEFORE the experiment is admitted, so every mid-run add_host draws from an already-reserved pool
        and can never block or oversubscribe; the arena rejects an add that would exceed the ceiling.

        OPT-IN, like box_ingress(): a defender that never changes topology (canary, velociraptor, a
        passive SOC) returns [] (default) and needs no other change — the whole dynamic-host path is
        inert for it (topology + 0 reserved, no env↔defender dynamic contract). Only a defender that
        actually requests hosts (a deception/decoy strategy) overrides this. Pairing a non-empty budget
        with an environment whose supports_dynamic_topology() is False is a contract violation the arena
        catches at deploy time."""
        return []

    # Resolve this plugin's own external code checkout + interpreter (helpers you may CALL from run()/
    # setup(); a self-contained defender with no code_dir_field never uses them).
    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    # ========================================================================
    # FRAMEWORK — the arena calls these; do NOT override. (See the class docstring.)
    # ========================================================================

    async def run_setup(self, experiment, cfg: ExperimentManagerConfig) -> "PreparedDefender":
        """The SETUP phase — the defender analog of AttackerPlugin.run_setup, and the SAME shape: emit
        SETUP_STARTED, then setup() fully arms the defender (stand up box infra → build+write the runner
        config → external arming) and returns the baton; run_defender then only launches run(). Both
        agents' run_setup are shape-identical — a bare setup() call around the lifecycle signals.

        It does NOT emit READY: a defender is READY only once its RUNNER has armed (the readiness marker,
        gated by wait_until_ready after run()), not when setup finishes — that readiness asymmetry is the
        one essential defender difference. FAILED stays centralized in the arena's defender error handler
        (it covers the whole setup→run block), so this just raises."""
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.SETUP_STARTED)
        experiment_name = experiment.experiment_name
        access = experiment._defender_access             # scoped SetupAccess list (key + bastion routing)
        bastion_ip = experiment._bastion_ip             # this experiment's ephemeral bastion floating IP
        # Persist the scoped access so run_start/run_stop/run_collect_logs can recover + thread it at launch
        # (mirroring the attacker). A box-resident defender's start() uses it to reach the box; a harness-run
        # defender's start() ignores it (its creds already travel in the written runner config).
        if access and cfg is not None:
            self._persist_access(experiment_name, cfg, access)
        return await self.setup(experiment, cfg, bastion_ip, access)

    async def run_start(self, experiment, prepared: "PreparedDefender", config_path: Path,
                        cfg: ExperimentManagerConfig) -> "asyncio.subprocess.Process":
        """Launch the defender run loop and return the process — the RUN phase, mirroring
        AttackerPlugin.run_start (the thin wrapper run_defender calls). Unlike the attacker it does NOT
        emit RUNNING here: a defender is READY/RUNNING only once its runner has armed (the readiness
        marker, see wait_until_ready), which the arena detects after this returns. (That asymmetry
        collapses in the box model — see docs/agent-symmetry.md.)"""
        access = self._load_access(experiment.experiment_name, cfg)
        return await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)

    async def run_stop(self, experiment, cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop() — mirrors AttackerPlugin.run_stop. Guarded against a prior
        terminal FAILED and against double-stop, because the arena calls it from several paths (arm
        failure, attacker-start failure, normal attack end); the arena reaps the process (process.wait)
        after this returns."""
        lc = self._lifecycle(experiment)
        if lc is not None and lc.status not in (DefenderSignal.STOPPED, DefenderSignal.FAILED):
            await lc.emit(DefenderSignal.STOPPING)
        access = self._load_access(experiment.experiment_name, cfg)
        try:
            await self.stop(experiment, cfg, access=access)
        finally:
            if lc is not None and lc.status != DefenderSignal.FAILED:
                await lc.emit(DefenderSignal.STOPPED)

    async def run_collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Load the persisted scoped access and hand it to collect_logs() — mirrors
        AttackerPlugin.run_collect_logs. A harness-run defender's collect_logs() ignores it (logs local);
        a box-resident defender uses it to pull box logs."""
        access = self._load_access(experiment.experiment_name, cfg)
        await self.collect_logs(experiment, cfg, dest, access=access)

    # ------------------------------------------------------------------ scoped access
    # Mirrors AttackerPlugin's foothold-access recovery. setup()/run_setup receive the scoped
    # DefenderSetupAccess list from the arena (experiment._defender_access), but run_start/run_stop/
    # run_collect_logs run later (a failure path, or a clean-slate stop after a restart) where it isn't in
    # scope — so run_setup persists it and the wrappers load it back + thread it to start()/stop()/
    # collect_logs() (symmetric with the attacker). A box-resident defender's start() reaches the box with
    # it; a harness-run defender's start() ignores it (creds already in the written config). The attacker
    # persists ONE entry (its single foothold); the defender persists the WHOLE list (box AND victims).
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @staticmethod
    def primary_access(access) -> "DefenderSetupAccess":
        """The first scoped DefenderSetupAccess (mirrors AttackerPlugin.primary_access by shape). WARNING:
        for the ATTACKER access[0] is the single foothold (correct), but the DEFENDER's access list is
        VICTIMS-FIRST / box-last (see deployer.defender_setup_access), so access[0] is a VICTIM, NOT the
        defender box. A box-resident defender MUST select its box by env_spec.box.ip (see the plugin's
        _launch_on_box) — this helper is only a last-resort fallback when no box ip is available."""
        if not access:
            raise RuntimeError("no DefenderSetupAccess passed to the defender — the arena must pass it to run_setup()")
        return access[0]

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig, access) -> None:
        """Internal (run_setup): write the scoped access list so the run_* wrappers can recover it.
        Persists the whole list (box + victims), unlike the attacker's single primary."""
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.model_dump() for a in (access or [])]))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig):
        """Internal (run_* wrappers): recover the persisted scoped access list, or None if none was
        persisted or it can't be read (mirrors AttackerPlugin._load_access)."""
        try:
            raw = json.loads(self._access_path(experiment_name, cfg).read_text())
            return [DefenderSetupAccess.model_validate(a) for a in raw]
        except Exception:  # noqa: BLE001 — no file / unreadable / no cfg -> nothing to thread through
            return None


    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS).
        Called by the arena right after build_config() — before it injects the arena-provided keys — so a
        plugin whose config drifts from what its runner reads fails fast with a precise message."""
        if not cls.REQUIRED_CONFIG_KEYS:
            return
        if not isinstance(built, dict):
            raise ValueError(f"{cls.__name__}.build_config() returned {type(built).__name__}, not a dict")
        missing = cls.REQUIRED_CONFIG_KEYS - built.keys()
        if missing:
            raise ValueError(
                f"{cls.__name__}.build_config() omitted required key(s) {sorted(missing)} declared in "
                f"REQUIRED_CONFIG_KEYS — its runner reads them. Got keys: {sorted(built)}")

    # ------------------------------------------------------------------
    # Readiness handshake
    #
    # A defender's strategy does all of its placement work in initialize()
    # (decoys, fake data, honey credentials) and only then enters the loop that
    # reacts to telemetry. run() just SPAWNS that process - it returns as
    # soon as the subprocess exists, long before arming is done. Starting the
    # attacker at that point meant the engagement could be over before the
    # defense existed: measured on a ReactiveLayered run, initialize() took
    # 3m45s while the attacker finished its whole chain in 1m38s, so the
    # reactive poll loop never executed a single iteration. These let the
    # harness block until the runner says it is actually armed.
    # ------------------------------------------------------------------
    @staticmethod
    def ready_marker_path(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_ready"

    @classmethod
    def clear_ready_marker(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Remove a stale marker before starting a defender. Re-running an
        experiment with overwrite=true reuses the same output dir, so a marker
        left by the previous run would otherwise make the gate pass instantly."""
        cls.ready_marker_path(experiment_name, cfg).unlink(missing_ok=True)

    @classmethod
    async def wait_until_ready(
        cls,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        process: asyncio.subprocess.Process,
        log=None,
    ) -> float:
        """Block until the defender's runner reports its strategy is armed.

        Returns seconds spent arming. Raises if the defender process dies first
        (a defender that crashed during initialize() must fail the experiment,
        not quietly hand an undefended environment to the attacker) or if
        arming exceeds cfg.defender_ready_timeout_seconds."""
        marker = cls.ready_marker_path(experiment_name, cfg)
        deadline = asyncio.get_event_loop().time() + cfg.defender_ready_timeout_seconds
        started = asyncio.get_event_loop().time()
        while True:
            if marker.exists():
                waited = asyncio.get_event_loop().time() - started
                if log:
                    log(experiment_name, f"Defender armed after {waited:.1f}s")
                return waited
            if process.returncode is not None:
                raise RuntimeError(
                    f"Defender exited (code {process.returncode}) while arming - "
                    f"see {marker.parent / 'defender.log'}"
                )
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(
                    f"Defender did not finish arming within "
                    f"{cfg.defender_ready_timeout_seconds}s - see {marker.parent / 'defender.log'}"
                )
            await asyncio.sleep(2)

    @staticmethod
    def _lifecycle(experiment):
        """The DefenderLifecycle the arena attached (mirrors AttackerPlugin._lifecycle); None in tests
        that drive run_setup without one."""
        return getattr(experiment, "_defender_lifecycle", None)

