import asyncio
import json
import os
import signal
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import output_root
from ...ui_schema import PluginUISchema
from ..env_spec import DefenderSetupAccess
from ..lifecycle import DefenderSignal


class PreparedDefender(BaseModel):
    """Opaque handoff from setup() to build_config()/start() — a marker that ARMING succeeded, passed
    setup() -> build_config() without the arena inspecting it (mirrors PreparedAttacker). A defender that
    must carry arming outputs (a box ES url / falco+sysflow indices, or the env-channel endpoint it picked)
    subclasses this and reads its own fields off it in its own build_config(); the arena never does."""


class DefenderPlugin(BaseModel):
    """Base class for a defender plugin — a MIRROR of AttackerPlugin (same members, same shapes). A defender
    is just an agent in the environment: it differs from an attacker only in its objective, not its lifecycle.

    PLUGIN SURFACE — what you implement / override:
      Required:
        build_config(experiment_name, env_spec, prepared) -> dict  the contents of the runner's config file
        ui_schema() -> PluginUISchema                              the dashboard form for this plugin
        run(...)   (or override start(...) instead)                launch the reactive-loop process
      Optional (the base provides a safe default, shown in parentheses):
        setup(...) -> PreparedDefender  ARM the defender (stand up box ES, deploy decoys / plant honey-creds)
                                        and BLOCK until it is actually armed       (default: empty baton)
        stop(...)                       terminate the process                      (default: SIGTERM local pid)
        teardown(experiment_name, cfg)  release host-side resources at env teardown (default: no-op)
        collect_logs(...)               pull defender-side logs                    (default: no-op)
        example_prepared()              a filled baton so offline tests can call build_config (default: empty)
        REQUIRED_CONFIG_KEYS / code_dir_field / code_python_field / uses_env_actions — declarations.

    FRAMEWORK — the arena calls these; do NOT override:
        run_setup / run_start / run_stop / run_collect_logs — the lifecycle wrappers the arena drives,
            IDENTICAL in shape to the attacker's. run_setup() emits SETUP_STARTED, runs setup() (full
            arming, which BLOCKS until armed), then build_config()+writes the runner config, emits READY,
            and returns prepared. There is NO readiness marker: setup() returning IS armed == READY (a
            box-resident defender blocks inside its OWN setup() by SSH-polling the box, exactly as a C2
            attacker blocks on its agent beacon — not a framework handshake). run_start() launches the
            reactive loop and emits RUNNING.
        __init_subclass__ (registration), validate_built_config, _lifecycle, and the
            _persist_access / _load_access scoped-access helpers.
      primary_access(access) is a helper you MAY call from setup()/start()/stop() to reach the box/victims.

    The ONE essential difference from the attacker: a defender's runner is a subprocess (or a box-resident
    process) that reads its scoped access from the written config, so run_setup injects the credential-bearing
    defender_setup_access + routing into the config AFTER build_config() (kept out of build_config's own
    output by the leak guard). An attacker's plugin uses its access in-process, so it needs no such injection.
    """

    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    # Keys this plugin's runner REQUIRES in build_config()'s output — the plugin↔runner contract, declared
    # as data (symmetric with AttackerPlugin). The arena validates build_config()'s output against this
    # before writing the config file, and the conformance test checks it generically. Empty = no declared
    # contract. Declare only keys build_config() itself always emits — NOT the arena-injected ones
    # (defender_env_spec / defender_setup_access / management_ip / …).
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # Per-plugin external code path: a defender backed by an external repo (the Defense/Perry defenders)
    # names its own config fields here, so no single field silently backs several plugins. Default None =
    # self-contained defender (canary) or a backend-specific one (velociraptor reads its own velociraptor_dir).
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    # Whether this defender issues ENV ACTIONS (restore / BlockIP / deploy-decoy) that need the arena's
    # environment-plugin connection. The arena keys EVERYTHING env-action on THIS — the serving window, the
    # mid-run VM budget, and the env-action channel it offers (the always-on UDS, and a token'd TCP port for
    # an in-env runner to tunnel to). The base is AGNOSTIC to HOW the defender executes or WHERE its runner
    # runs: the plugin stands up its own infra (box ES / box agent) in its own setup() and picks its own
    # env-channel door (UDS vs tunneled TCP), baking the endpoint it chose into its build_config via the
    # baton. Default False = a detect-only defender (canary, a plain SOC) that mutates nothing, needs no
    # channel.
    uses_env_actions: ClassVar[bool] = False

    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    def __init_subclass__(cls, config_type: str = None, **kwargs):  # FRAMEWORK: plugin registration
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            cls._registry[config_type] = cls

    # ========================================================================
    # PLUGIN SURFACE — implement / override these. (Required: build_config, ui_schema, and run() or start().)
    # ========================================================================

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        env_spec,
        prepared: "PreparedDefender",
    ) -> dict:
        """REQUIRED. The run config the runner reads. env_spec is the agent-facing DefenderEnvSpec (host
        inventory, NO creds); `prepared` is this plugin's own opaque arming handle — ignore it unless setup()
        produced state the config needs (e.g. a box ES url + indices, or the env-channel endpoint it picked,
        which the plugin reads off its own PreparedDefender subclass)."""
        ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        """REQUIRED. The dashboard form (fields + how they fan out into experiments) for this plugin."""
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """REQUIRED (unless you override start()). Launch the reactive-loop process and return it. start()
        calls this by default; override start() instead — e.g. a box-resident defender launching over SSH —
        if you need the scoped access at launch. Mirrors AttackerPlugin.run()."""
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedDefender":
        """OPTIONAL. ARM the defender and BLOCK until it is actually armed, then return the baton — the
        single arming entry, shape-identical to AttackerPlugin.setup() (which brings up the C2 and blocks
        until an agent beacons in). Stand up this run's box infra (per-experiment box ES, a box agent if the
        plugin uses one), deploy decoys / plant honey-creds — everything the defender needs in place BEFORE
        the attacker runs — and return a PreparedDefender carrying whatever build_config() needs (es_url /
        indices, the env-channel endpoint this plugin picked, …). Default: nothing to arm.

        `access` is the scoped DefenderSetupAccess list (key + bastion routing); reach the box/victims with
        self.primary_access(access).ssh_base() (or, for a box-resident defender, select the box by
        env_spec.box.ip). env_spec and the env-channel state are read off `experiment`. `bastion_ip` is this
        experiment's own bastion floating IP. Raising here fails the defender start (surfaced as FAILED by
        run_setup, exactly like the attacker)."""
        return PreparedDefender()

    async def start(
        self,
        prepared: "PreparedDefender",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """OPTIONAL (default: call run()). Launch the reactive loop and return the process. Arming was
        established in setup(). Mirrors AttackerPlugin.start(); the run_start wrapper calls this with the
        scoped `access`. A box-resident defender OVERRIDES this to launch its runner ON THE BOX over SSH via
        `access` — the box-launch machinery lives on that plugin, not here (see llm_soc_box / canary)."""
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

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Release host-side resources this defender stood up (a box agent, a tunnel) at ENVIRONMENT
        teardown — keyed by experiment_name. Symmetric with AttackerPlugin.teardown. Default no-op; the
        caller already wraps it in try/except, so it must be safe when there is nothing to tear down and must
        never raise. (Stray decoy VMs are reaped by the ENVIRONMENT's own teardown, not here — deleting a VM
        is backend-specific and defenders are backend-agnostic.)"""
        return None

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """OPTIONAL. Pull defender-side logs into dest. Default no-op — a harness-run defender's logs are
        already local. A box-resident defender overrides this to pull its box logs via `access`, mirroring
        AttackerPlugin.collect_logs."""

    @classmethod
    def example_prepared(cls) -> "PreparedDefender":
        """OPTIONAL. A representative PreparedDefender for exercising build_config() OFFLINE — without
        running setup() or a cloud/box ES. Twin of AttackerPlugin.example_prepared: the default empty baton
        suits defenders whose build_config() ignores `prepared`; a telemetry defender that reads es_url /
        indices off its baton overrides this so the coupling is discoverable and conformance tests
        (tests/test_plugin_conformance.py) can build its config without setup()."""
        return PreparedDefender()

    # ========================================================================
    # FRAMEWORK — the arena calls these; do NOT override. (See the class docstring.)
    # ========================================================================

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS).
        Called by run_setup right after build_config() — before it injects the arena-provided keys — so a
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

    @staticmethod
    def primary_access(access) -> "DefenderSetupAccess":
        """The first scoped DefenderSetupAccess (mirrors AttackerPlugin.primary_access by shape). WARNING:
        for the ATTACKER access[0] is the single foothold (correct), but the DEFENDER's access list is
        VICTIMS-FIRST / box-last (see deployer.defender_setup_access), so access[0] is a VICTIM, NOT the
        defender box. A box-resident defender MUST select its box by env_spec.box.ip — this helper is only a
        last-resort fallback when no box ip is available."""
        if not access:
            raise RuntimeError("no DefenderSetupAccess passed to the defender — the arena must pass it to run_setup()")
        return access[0]

    # ------------------------------------------------------------------ scoped access recovery
    # Mirrors AttackerPlugin's foothold-access recovery. setup()/run_setup receive the scoped
    # DefenderSetupAccess list from the arena (experiment._defender_access), but run_start/run_stop/
    # run_collect_logs run later (a failure path, or a clean-slate stop after a restart) where it isn't in
    # scope — so run_setup persists it and the wrappers load it back + thread it to start()/stop()/
    # collect_logs(). The attacker persists ONE entry (its single foothold); the defender persists the WHOLE
    # list (box AND victims).
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

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

    # ------------------------------------------------------------------ lifecycle handshake
    # Templates the arena drives (see lifecycle.py). They emit the defender's signals around the overridable
    # setup()/start()/stop() so the arena can wait for each — IDENTICAL in shape to the attacker's. The
    # lifecycle lives on the experiment (set by the arena); when absent (e.g. a clean-slate stop of a
    # registry-loaded run) these behave exactly like the plain methods.
    @staticmethod
    def _lifecycle(experiment):
        return getattr(experiment, "_defender_lifecycle", None)

    async def run_setup(self, experiment, cfg: ExperimentManagerConfig) -> "PreparedDefender":
        """The SETUP phase — IDENTICAL in shape to AttackerPlugin.run_setup: emit SETUP_STARTED, run setup()
        (full arming, which BLOCKS until armed), then build_config()+write the runner config, emit READY, and
        return prepared. setup() returning IS armed == READY — there is no readiness marker. FAILED is
        emitted if arming or config-write raises (the arena's error handler covers the whole setup→run block),
        then re-raised.

        After build_config() the base injects the credential-bearing scoped access + routing the runner reads
        (defender_setup_access / defender_env_spec / management_ip / bastion_ip / log_dir) — kept OUT of
        build_config()'s own output by the leak guard. That injection is the one essential defender-vs-attacker
        difference (the defender's runner is a subprocess reading its access from the config)."""
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.SETUP_STARTED)
        experiment_name = experiment.experiment_name
        access = experiment._defender_access             # scoped SetupAccess list (key + bastion routing)
        bastion_ip = experiment._bastion_ip             # this experiment's ephemeral bastion floating IP
        # Persist the scoped access so run_start/run_stop/run_collect_logs can recover + thread it (mirroring
        # the attacker). (cfg is None only in the lifecycle unit tests that isolate the handshake.)
        if access and cfg is not None:
            self._persist_access(experiment_name, cfg, access)
        try:
            prepared = await self.setup(experiment, cfg, bastion_ip, access)  # ARM (blocks until armed)
            # build_config runs in the SETUP phase (symmetric with the attacker): setup() produces `prepared`,
            # build_config(env_spec, prepared) derives the runner config from it, run_start then only launches.
            if cfg is not None:
                env_spec = experiment._defender_env_spec        # agent-facing DefenderEnvSpec (NO creds)
                config_path = (output_root(experiment_name, cfg)
                               / experiment_name / "defender" / "defender_config.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                built = self.build_config(experiment_name, env_spec, prepared)
                type(self).validate_built_config(built)  # fail fast if the config drifts from the runner contract
                # INJECT the credential-bearing scoped access + routing the runner reads (the leak guard keeps
                # these OUT of build_config's own output). This is the one essential defender difference.
                if env_spec is not None:
                    built["defender_env_spec"] = env_spec.model_dump()
                built["defender_setup_access"] = [a.model_dump() for a in (access or [])]
                built["management_ip"] = cfg.arena_host_ip
                built["bastion_ip"] = bastion_ip
                built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
                config_path.write_text(json.dumps(built, indent=2))
        except Exception as e:  # noqa: BLE001 — surface as a FAILED signal, then re-raise for the arena
            if lc is not None:
                await lc.emit(DefenderSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(DefenderSignal.READY)
        return prepared

    async def run_start(self, experiment, prepared: "PreparedDefender", config_path: Path,
                        cfg: ExperimentManagerConfig) -> "asyncio.subprocess.Process":
        """Launch the reactive loop, then emit RUNNING — IDENTICAL to AttackerPlugin.run_start. The defender
        is already READY (armed in setup()); this just starts the loop that reacts to telemetry."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.RUNNING)
        return process

    async def run_stop(self, experiment, cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop() — mirrors AttackerPlugin.run_stop. Guarded against a prior
        terminal FAILED and against double-stop, because the arena calls it from several paths (arm failure,
        attacker-start failure, normal attack end); the arena reaps the process after this returns."""
        lc = self._lifecycle(experiment)
        if lc is not None and lc.status not in (DefenderSignal.STOPPED, DefenderSignal.FAILED):
            await lc.emit(DefenderSignal.STOPPING)
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        try:
            await self.stop(experiment, cfg, access=access)
        finally:
            if lc is not None and lc.status != DefenderSignal.FAILED:
                await lc.emit(DefenderSignal.STOPPED)

    async def run_collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Load the persisted scoped access and hand the primary entry to collect_logs() — mirrors
        AttackerPlugin.run_collect_logs."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        await self.collect_logs(experiment, cfg, dest, access=access)
