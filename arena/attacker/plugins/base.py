import asyncio
import json
import os
import signal
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ..env_spec import AttackerEnvSpec, AttackerSetupAccess
from ..lifecycle import AttackerSignal
from ...experiment_log import output_root
from ...ui_schema import PluginUISchema

if TYPE_CHECKING:
    from ...experiment import Experiment


@dataclass
class PreparedAttacker:
    """Opaque handoff from setup() to start(): a marker that setup succeeded, passed setup() -> start()
    without the arena inspecting it. A plugin that must carry setup outputs (e.g. a C2's URLs) subclasses
    this and reads its own fields off it in its own build_config()/run(); the arena never does."""


class AttackerPlugin(BaseModel):
    """Base class for an attacker plugin. Its members fall into two groups — see the section banners below.

    PLUGIN SURFACE — what you implement / override:
      Required:
        build_config(experiment_name, env_spec, prepared) -> dict  the contents of the runner's config file
        ui_schema() -> PluginUISchema                              the dashboard form for this plugin
        run(...)   (or override start(...) instead)                launch the agent process
      Optional (the base provides a safe default, shown in parentheses):
        setup(...) -> PreparedAttacker  foothold prep / C2 bring-up          (default: empty baton)
        stop(...)                       terminate the process                (default: SIGTERM the local pid)
        teardown(experiment_name, cfg)  release resources at env teardown, e.g. a C2  (default: no-op)
        collect_logs(...)               pull agent-side logs                 (default: no-op)
        sweep_stale_state(cfg)          reap orphaned global state on clean-slate (default: no-op)
        example_prepared()              a filled baton so offline tests can call build_config (default: empty)
        REQUIRED_CONFIG_KEYS            declare the keys your runner needs    (default: none)

    FRAMEWORK — the arena calls these; do NOT override:
        run_setup / run_start / run_stop / run_collect_logs — the lifecycle wrappers the arena drives. They
            emit this attacker's signals around your setup()/start()/stop()/collect_logs(), and run_setup()
            also calls build_config() and writes the config. The arena calls the run_* wrappers, never your
            setup()/start()/stop() directly.
        __init_subclass__ (registration), validate_built_config, _lifecycle, and the
            _persist_access / _load_access access-recovery helpers.
      primary_access(access) is a helper you MAY call from setup()/start()/stop() to reach the foothold.
    """

    _registry: ClassVar[dict[str, type["AttackerPlugin"]]] = {}

    # Keys this plugin's runner REQUIRES in build_config()'s output — the plugin↔runner contract, declared
    # as data. The arena validates build_config()'s output against this before writing the config file (so
    # a drift fails fast with a precise message, not a KeyError deep in the run), and the conformance test
    # (tests/test_plugin_conformance.py) checks it generically. Empty = no declared contract (only
    # well-formedness is checked). Declare only ALWAYS-emitted keys; per-config-optional keys stay out.
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # Per-plugin external code path: an attacker backed by an external repo (Incalmo, Sliver, …) names its
    # own config fields here, so no single field silently backs several plugins. Default None = a
    # self-contained attacker. Mirrors DefenderPlugin — the attacker reaches its repo via cwd/PYTHONPATH
    # (resolved with these), it never writes the path into the agent config.
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

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
        env_spec: AttackerEnvSpec,
        prepared: "PreparedAttacker",
    ) -> dict:
        """REQUIRED. The run config the agent process reads. env_spec is the adversary-safe spec; `prepared`
        is this plugin's own opaque setup handle — ignore it unless setup() produced state the config needs
        (e.g. a C2's URLs, which the plugin reads off its own PreparedAttacker subclass)."""
        ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        """REQUIRED. The dashboard form (fields + how they fan out into experiments) for this plugin."""
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def run(
        self,
        prepared: "PreparedAttacker",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """REQUIRED (unless you override start()). Launch the agent process and return it. start() calls
        this by default; override start() instead if you need the scoped foothold access at launch."""
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, bastion_ip: Optional[str],
                    access: Optional[list[AttackerSetupAccess]] = None) -> PreparedAttacker:
        """OPTIONAL. Prepare the foothold and block until the attacker is ready to run. Default: nothing to do.

        `access` is the scoped foothold AttackerSetupAccess list the arena passes to run_setup(). run_setup()
        persists it automatically, so start()/stop()/collect_logs() receive the primary entry without
        the plugin touching disk. Use `self.primary_access(access)` to reach the foothold here.

        An attacker that runs a C2 (e.g. Incalmo) overrides this to bring the C2 up and wait for an
        agent to beacon in before returning."""
        return PreparedAttacker()

    async def start(
        self,
        prepared: PreparedAttacker,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access: Optional[AttackerSetupAccess] = None,
    ) -> asyncio.subprocess.Process:
        """OPTIONAL. Launch the attacker process (exit code = verdict). Channel readiness was established in
        setup(). `access` is the scoped foothold AttackerSetupAccess, loaded and passed by run_start(). Default:
        call run()."""
        return await self.run(prepared, config_path, experiment_name, cfg)

    async def stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig,
                   access: Optional[AttackerSetupAccess] = None) -> None:
        """OPTIONAL. Terminate the attacker process(es). Local pid here; override to also kill remote procs.
        `access` is the scoped foothold AttackerSetupAccess, loaded and passed by run_stop()."""
        if experiment.pid:
            try:
                os.kill(experiment.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Release host-side resources this attacker stood up (e.g. tear down a C2) at ENVIRONMENT
        teardown — keyed by experiment_name (the plugin persists its own teardown state). Symmetric with
        DefenderPlugin.teardown. Default no-op: an attacker with nothing to release does nothing. The arena
        calls this unconditionally in its teardown/clean-slate paths, so it must be safe when there is
        nothing to tear down and must never raise."""
        return None

    async def collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path,
                           access: Optional[AttackerSetupAccess] = None) -> None:
        """OPTIONAL. Pull attacker-specific logs into dest. Default no-op — logs already local.
        `access` is the scoped foothold AttackerSetupAccess, loaded and passed by run_collect_logs()."""

    @classmethod
    def sweep_stale_state(cls, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL — most attackers do NOT implement this; the default is a no-op, and an attacker that
        keeps no global host-side state (temp tunnels, containers, statefiles) simply omits it.

        It matters ONLY on an ABNORMAL manager exit — a crash or SIGKILL. On a clean shutdown each run's
        teardown() already reaped its own C2 state, so by the next clean-slate there is nothing left and
        this is a no-op. Its sole job is crash recovery: reclaim this attacker TYPE's GLOBAL host-side state
        that a crashed prior manager orphaned (e.g. C2 `ssh -L` tunnels, Docker containers, temp dirs) —
        leftovers teardown() can't reach because the in-memory registry it keys on died with the manager.

        The arena calls it once per registered attacker plugin on clean-slate, plugin-agnostically (the core
        never imports a specific plugin to clean up after it), BEFORE any experiment runs. A C2-based
        attacker (e.g. Incalmo) overrides it to reap its own leftovers; a plugin with no global state skips it."""
        return None

    @classmethod
    def example_prepared(cls) -> "PreparedAttacker":
        """OPTIONAL. A representative PreparedAttacker for exercising build_config() OFFLINE — without
        running setup() or a cloud/C2. The default bare baton suits attackers whose build_config() ignores
        `prepared`; an attacker that reads setup state off its own PreparedAttacker subclass (e.g. a
        C2's URLs) overrides this to return a filled-in instance, so that the coupling is discoverable
        and conformance tests (tests/test_plugin_conformance.py) can build its config without setup()."""
        return PreparedAttacker()

    # ========================================================================
    # FRAMEWORK — the arena calls these; do NOT override. (See the class docstring.)
    # ========================================================================

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS).
        Called by the arena right after build_config(), so a plugin whose config drifts from what its
        runner reads fails the experiment immediately with a precise message."""
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
    def primary_access(access: Optional[list[AttackerSetupAccess]]) -> AttackerSetupAccess:
        """Helper (call, don't override): the foothold the attacker operates from — the first AttackerSetupAccess
        the arena passed to run_setup()."""
        if not access:
            raise RuntimeError("no AttackerSetupAccess passed to the attacker — the arena must pass it to run_setup()")
        return access[0]

    # ------------------------------------------------------------------ foothold access recovery
    # setup() receives the scoped `access` (an AttackerSetupAccess list) as a parameter, but start()/stop()/
    # collect_logs() run later, in contexts where it isn't in scope — a failure path, or a clean-slate
    # stop after an arena restart that reloaded the experiment from disk. So run_setup() persists the access
    # LIST (symmetric with DefenderPlugin — an attacker whose env grants several footholds keeps them all),
    # and the run_start/run_stop/run_collect_logs wrappers load it back and hand the plugin its PRIMARY
    # foothold (self.primary_access) — the common single-foothold case, unchanged for existing plugins.
    # Plugins never call persist/load themselves; they just use the `access` they are handed.
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "attacker" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig,
                        access: Optional[list[AttackerSetupAccess]]) -> None:
        """Internal (run_setup): write the scoped foothold access LIST so the run_* wrappers can recover it
        (symmetric with DefenderPlugin._persist_access; supports an env that grants several footholds)."""
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.model_dump() for a in (access or [])]))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig) -> Optional[list[AttackerSetupAccess]]:
        """Internal (run_* wrappers): recover the persisted foothold access LIST, or None if none was
        persisted (an attacker with no foothold) or it can't be read (symmetric with DefenderPlugin)."""
        try:
            raw = json.loads(self._access_path(experiment_name, cfg).read_text())
            return [AttackerSetupAccess.model_validate(a) for a in raw]
        except Exception:  # noqa: BLE001 — no file / unreadable / no cfg -> nothing to thread through
            return None

    # ------------------------------------------------------------------ lifecycle handshake
    # Templates the arena drives (see lifecycle.py). They emit the attacker's signals around the
    # overridable setup()/stop() so the arena can wait for each. The lifecycle lives on the
    # experiment (set by the arena); when absent (e.g. clean-slate stop of a registry-loaded run)
    # these behave exactly like the plain methods.
    @staticmethod
    def _lifecycle(experiment: "Experiment"):
        return getattr(experiment, "_attacker_lifecycle", None)

    async def run_setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, bastion_ip: Optional[str],
                        access: Optional[list[AttackerSetupAccess]] = None) -> "PreparedAttacker":
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.SETUP_STARTED)
        if access and cfg is not None:
            self._persist_access(experiment.experiment_name, cfg, access)  # so run_start/stop/collect recover it
        try:
            prepared = await self.setup(experiment, cfg, bastion_ip, access)
            # build_config runs in the SETUP phase (symmetric with the defender): setup() produces
            # `prepared`, build_config(env_spec, prepared) derives the runner config from it, and run_start
            # then only launches. (cfg is None only in the lifecycle unit tests that isolate the handshake.)
            if cfg is not None:
                config_path = (output_root(experiment.experiment_name, cfg)
                               / experiment.experiment_name / "attacker" / "attacker_config.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                built = self.build_config(experiment.experiment_name, experiment._attacker_env_spec, prepared)
                type(self).validate_built_config(built)  # fail fast if the config drifts from the runner contract
                config_path.write_text(json.dumps(built, indent=2))
        except Exception as e:  # noqa: BLE001 — surface as a FAILED signal, then re-raise for the arena
            if lc is not None:
                await lc.emit(AttackerSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(AttackerSignal.READY)
        return prepared

    async def run_start(self, experiment: "Experiment", prepared: PreparedAttacker, config_path: Path,
                        cfg: ExperimentManagerConfig) -> "asyncio.subprocess.Process":
        """Launch the attack process, then emit RUNNING — the attacker telling the arena its process
        is up. The arena waits for RUNNING (it does not emit it), same as READY."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.RUNNING)
        return process

    async def run_stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop() (twin of DefenderPlugin.run_stop). Guarded against a prior
        terminal FAILED and double-stop, since the arena may reach it from more than one path (graceful
        stop, timeout, teardown)."""
        lc = self._lifecycle(experiment)
        if lc is not None and lc.status not in (AttackerSignal.STOPPED, AttackerSignal.FAILED):
            await lc.emit(AttackerSignal.STOPPING)
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        try:
            await self.stop(experiment, cfg, access=access)
        finally:
            if lc is not None and lc.status != AttackerSignal.FAILED:
                await lc.emit(AttackerSignal.STOPPED)

    async def run_collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Load the persisted foothold access list and hand the primary foothold to collect_logs()."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        await self.collect_logs(experiment, cfg, dest, access=access)
