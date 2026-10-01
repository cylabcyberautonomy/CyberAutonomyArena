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
from ..env_spec import AttackerEnvSpec, SetupAccess
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
    _registry: ClassVar[dict[str, type["AttackerPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            AttackerPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        env_spec: AttackerEnvSpec,
        prepared: "PreparedAttacker",
    ) -> dict:
        """The run config the agent process reads. env_spec is the adversary-safe spec; `prepared` is
        this plugin's own opaque setup handle — ignore it unless setup() produced state the config
        needs (e.g. a C2's URLs, which the plugin reads off its own PreparedAttacker subclass)."""
        ...

    async def run(
        self,
        prepared: "PreparedAttacker",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str],
                    access: Optional[list[SetupAccess]] = None) -> PreparedAttacker:
        """Prepare the foothold and block until the attacker is ready to run. Default: nothing to do.

        `access` is the scoped foothold SetupAccess list the arena passes to run_setup(). run_setup()
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
        access: Optional[SetupAccess] = None,
    ) -> asyncio.subprocess.Process:
        """Launch the attacker process (exit code = verdict). Channel readiness was established in
        setup(). `access` is the scoped foothold SetupAccess, loaded and passed by run_start()."""
        return await self.run(prepared, config_path, experiment_name, cfg)

    async def stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig,
                   access: Optional[SetupAccess] = None) -> None:
        """Terminate the attacker process(es). Local pid here; override to also kill remote procs.
        `access` is the scoped foothold SetupAccess, loaded and passed by run_stop()."""
        if experiment.pid:
            try:
                os.kill(experiment.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def stop_c2c(self, experiment_name: str) -> None:
        """Tear down any C2 this attacker stood up, keyed by experiment_name (the plugin persists its
        own teardown state). Default no-op: an attacker with no C2 has nothing to tear down. The arena
        calls this unconditionally in its teardown/clean-slate paths, so it must be safe when no C2
        exists and must never raise."""
        return None

    async def collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path,
                           access: Optional[SetupAccess] = None) -> None:
        """Pull attacker-specific logs into dest. Default no-op — logs already local.
        `access` is the scoped foothold SetupAccess, loaded and passed by run_collect_logs()."""

    # ------------------------------------------------------------------ foothold access recovery
    # setup() receives the scoped `access` (a SetupAccess list) as a parameter, but start()/stop()/
    # collect_logs() run later, in contexts where it isn't in scope — a failure path, or a clean-slate
    # stop after an arena restart that reloaded the experiment from disk. So run_setup() persists the
    # primary access, and the run_start/run_stop/run_collect_logs wrappers load it back and pass it in.
    # Plugins never call persist/load themselves; they just use the `access` they are handed.
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @staticmethod
    def primary_access(access: Optional[list[SetupAccess]]) -> SetupAccess:
        """The foothold the attacker operates from — the first SetupAccess the arena passed to run_setup()."""
        if not access:
            raise RuntimeError("no SetupAccess passed to the attacker — the arena must pass it to run_setup()")
        return access[0]

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "attacker" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig,
                        access: Optional[list[SetupAccess]]) -> None:
        """Internal (run_setup): write the primary foothold access so the run_* wrappers can recover it."""
        fa = self.primary_access(access)
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(fa.model_dump()))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig) -> Optional[SetupAccess]:
        """Internal (run_* wrappers): recover the persisted foothold access, or None if none was
        persisted (an attacker with no foothold) or it can't be read."""
        try:
            return SetupAccess.model_validate(json.loads(self._access_path(experiment_name, cfg).read_text()))
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

    async def run_setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str],
                        access: Optional[list[SetupAccess]] = None) -> "PreparedAttacker":
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.SETUP_STARTED)
        if access and cfg is not None:
            self._persist_access(experiment.experiment_name, cfg, access)  # so run_start/stop/collect recover it
        try:
            prepared = await self.setup(experiment, cfg, mgmt_ip, access)
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
        access = self._load_access(experiment.experiment_name, cfg)
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.RUNNING)
        return process

    async def run_stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.STOPPING)
        access = self._load_access(experiment.experiment_name, cfg)
        try:
            await self.stop(experiment, cfg, access=access)
        finally:
            if lc is not None:
                await lc.emit(AttackerSignal.STOPPED)

    async def run_collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Load the persisted foothold access and hand it to collect_logs()."""
        access = self._load_access(experiment.experiment_name, cfg)
        await self.collect_logs(experiment, cfg, dest, access=access)

