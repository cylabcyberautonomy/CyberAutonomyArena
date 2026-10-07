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
    """Opaque handoff from setup() to start(). A plugin subclasses this to carry setup outputs."""


class AttackerPlugin(BaseModel):
    """Base class for an attacker plugin: the plugin surface to override, and the framework wrappers the arena drives."""

    _registry: ClassVar[dict[str, type["AttackerPlugin"]]] = {}

    # Keys this plugin's runner requires in build_config()'s output. Empty means no declared contract.
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # External-code-path fields: an attacker backed by an external repo names its own config fields here.
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            cls._registry[config_type] = cls

    # PLUGIN SURFACE — implement or override these.

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        env_spec: AttackerEnvSpec,
        prepared: "PreparedAttacker",
    ) -> dict:
        """REQUIRED. The run config the agent reads. Ignore prepared unless setup() produced state the config needs."""
        ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        """REQUIRED. The dashboard form for this plugin."""
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def run(
        self,
        prepared: "PreparedAttacker",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """REQUIRED (unless you override start()). Launch the agent process and return it."""
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, bastion_ip: Optional[str],
                    access: Optional[list[AttackerSetupAccess]] = None) -> PreparedAttacker:
        """OPTIONAL. Prepare the foothold and block until the attacker is ready to run. Default: nothing to do."""
        return PreparedAttacker()

    async def start(
        self,
        prepared: PreparedAttacker,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access: Optional[AttackerSetupAccess] = None,
    ) -> asyncio.subprocess.Process:
        """OPTIONAL. Launch the attacker process. setup() established readiness. Default: call run()."""
        return await self.run(prepared, config_path, experiment_name, cfg)

    async def stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig,
                   access: Optional[AttackerSetupAccess] = None) -> None:
        """OPTIONAL. Stop the attacker process. Local pid here. Override to also kill remote processes."""
        if experiment.pid:
            try:
                os.kill(experiment.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Release host-side resources this attacker created at environment teardown. Must be safe to call with nothing to release and must never raise."""
        return None

    async def collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path,
                           access: Optional[AttackerSetupAccess] = None) -> None:
        """OPTIONAL. Copy attacker-specific logs into dest. Default no-op, because the logs are already local."""

    @classmethod
    def sweep_stale_state(cls, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Crash-recovery only: reclaim this attacker type's global leftovers after an abnormal manager exit."""
        return None

    @classmethod
    def example_prepared(cls) -> "PreparedAttacker":
        """OPTIONAL. A representative PreparedAttacker to exercise build_config() offline, without setup() or a cloud or C2."""
        return PreparedAttacker()

    # FRAMEWORK — the arena calls these. Do NOT override.

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS)."""
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
        """Helper (call, do not override): the foothold the attacker operates from — the first AttackerSetupAccess."""
        if not access:
            raise RuntimeError("no AttackerSetupAccess passed to the attacker — the arena must pass it to run_setup()")
        return access[0]

    # Foothold-access recovery: run_setup() persists the scoped access list and the run_* wrappers load it back.
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "attacker" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig,
                        access: Optional[list[AttackerSetupAccess]]) -> None:
        """Internal (run_setup): write the scoped foothold access list so the run_* wrappers can recover it."""
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.model_dump() for a in (access or [])]))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig) -> Optional[list[AttackerSetupAccess]]:
        """Internal (run_* wrappers): recover the persisted foothold access list, or None if absent or unreadable."""
        try:
            raw = json.loads(self._access_path(experiment_name, cfg).read_text())
            return [AttackerSetupAccess.model_validate(a) for a in raw]
        except Exception:  # noqa: BLE001
            return None

    # Lifecycle templates the arena drives (see lifecycle.py): emit the attacker's signals around setup() and stop().
    @staticmethod
    def _lifecycle(experiment: "Experiment"):
        return getattr(experiment, "_attacker_lifecycle", None)

    async def run_setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, bastion_ip: Optional[str],
                        access: Optional[list[AttackerSetupAccess]] = None) -> "PreparedAttacker":
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.SETUP_STARTED)
        if access and cfg is not None:
            self._persist_access(experiment.experiment_name, cfg, access)
        try:
            prepared = await self.setup(experiment, cfg, bastion_ip, access)
            # build_config runs in the setup phase: setup() produces prepared, build_config derives the config.
            if cfg is not None:
                config_path = (output_root(experiment.experiment_name, cfg)
                               / experiment.experiment_name / "attacker" / "attacker_config.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                built = self.build_config(experiment.experiment_name, experiment._attacker_env_spec, prepared)
                type(self).validate_built_config(built)
                config_path.write_text(json.dumps(built, indent=2))
        except Exception as e:  # noqa: BLE001
            if lc is not None:
                await lc.emit(AttackerSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(AttackerSignal.READY)
        return prepared

    async def run_start(self, experiment: "Experiment", prepared: PreparedAttacker, config_path: Path,
                        cfg: ExperimentManagerConfig) -> "asyncio.subprocess.Process":
        """Launch the attack process, then emit RUNNING. The arena waits for RUNNING, same as READY."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.RUNNING)
        return process

    async def run_stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop(). Guarded against a prior terminal FAILED and against double-stop."""
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
