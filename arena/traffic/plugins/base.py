import asyncio
import json
import os
import signal
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import get_logger, output_root
from ...ui_schema import PluginUISchema
from ..env_spec import TrafficSetupAccess
from ..lifecycle import TrafficSignal


class PreparedTraffic(BaseModel):
    """Opaque handoff from setup() to build_config()/start(). A traffic plugin subclasses this to carry setup outputs."""


class TrafficPlugin(BaseModel):
    """Base class for a traffic plugin: benign background activity on the hosts, same lifecycle as the defender.

    Traffic acts on every host it was given, so stop()/collect_logs() receive the WHOLE scoped access list
    (not one primary entry, as the attacker/defender do)."""

    _registry: ClassVar[dict[str, type["TrafficPlugin"]]] = {}

    # Keys this plugin's build_config() always emits. Empty means no declared contract.
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # External-code-path fields: a traffic plugin backed by an external repo names its own config fields here.
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    # Seconds the arena lets traffic run before the attacker starts, so the defender sees a baseline.
    warmup_seconds: int = 0

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
        env_spec,
        prepared: "PreparedTraffic",
    ) -> dict:
        """REQUIRED. The run config (the record of what traffic was generated where). No credentials."""
        ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        """REQUIRED. The dashboard form for this plugin."""
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedTraffic":
        """OPTIONAL. Install and start the generators, and block until they are actually producing activity.
        Raising fails the experiment: a run that asked for traffic is never reported as a quiet run."""
        return PreparedTraffic()

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> Optional[asyncio.subprocess.Process]:
        """OPTIONAL. Launch a harness-side traffic process and return it. Default None: the generators live
        on the hosts (started in setup()), so there is nothing to launch here."""
        return None

    async def start(
        self,
        prepared: "PreparedTraffic",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> Optional[asyncio.subprocess.Process]:
        """OPTIONAL (default: call run()). setup() already started the generators."""
        return await self.run(config_path, experiment_name, cfg)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        """OPTIONAL. Stop the generators. Default: SIGTERM a harness-side process, if there is one."""
        if getattr(experiment, "traffic_pid", None):
            try:
                os.kill(experiment.traffic_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """OPTIONAL. Copy the labelled activity logs (the benign ground truth) into dest. Default no-op."""

    async def rearm(self, experiment, cfg: ExperimentManagerConfig, access: "TrafficSetupAccess") -> None:
        """OPTIONAL. Re-install and restart the generator on ONE host the environment just rebuilt from its
        base image (a defender restore). Without this a restored host goes silent, which tells the defender
        the restore happened. Default no-op."""

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Release harness-side resources at environment teardown. Must never raise."""
        return None

    @classmethod
    def example_prepared(cls) -> "PreparedTraffic":
        """OPTIONAL. A representative PreparedTraffic to exercise build_config() offline."""
        return PreparedTraffic()

    # FRAMEWORK — the arena calls these. Do NOT override.

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key in REQUIRED_CONFIG_KEYS."""
        if not cls.REQUIRED_CONFIG_KEYS:
            return
        if not isinstance(built, dict):
            raise ValueError(f"{cls.__name__}.build_config() returned {type(built).__name__}, not a dict")
        missing = cls.REQUIRED_CONFIG_KEYS - built.keys()
        if missing:
            raise ValueError(
                f"{cls.__name__}.build_config() omitted required key(s) {sorted(missing)} declared in "
                f"REQUIRED_CONFIG_KEYS. Got keys: {sorted(built)}")

    # Scoped access recovery: run_setup persists the access list and the run_* wrappers load it back.
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "traffic" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig, access) -> None:
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.model_dump() for a in (access or [])]))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig):
        try:
            raw = json.loads(self._access_path(experiment_name, cfg).read_text())
            return [TrafficSetupAccess.model_validate(a) for a in raw]
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _lifecycle(experiment):
        return getattr(experiment, "_traffic_lifecycle", None)

    async def run_setup(self, experiment, cfg: ExperimentManagerConfig) -> "PreparedTraffic":
        """The setup phase: emit SETUP_STARTED, run setup() (blocks until generating), write the config, emit READY."""
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(TrafficSignal.SETUP_STARTED)
        experiment_name = experiment.experiment_name
        access = experiment._traffic_access
        bastion_ip = experiment._bastion_ip
        if access and cfg is not None:
            self._persist_access(experiment_name, cfg, access)
        try:
            prepared = await self.setup(experiment, cfg, bastion_ip, access)
            if cfg is not None:
                env_spec = experiment._traffic_env_spec
                config_path = (output_root(experiment_name, cfg)
                               / experiment_name / "traffic" / "traffic_config.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                built = self.build_config(experiment_name, env_spec, prepared)
                type(self).validate_built_config(built)
                if env_spec is not None:
                    built["traffic_env_spec"] = env_spec.model_dump()
                built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "traffic")
                config_path.write_text(json.dumps(built, indent=2))
        except Exception as e:  # noqa: BLE001
            if lc is not None:
                await lc.emit(TrafficSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(TrafficSignal.READY)
        return prepared

    async def run_start(self, experiment, prepared: "PreparedTraffic", config_path: Path,
                        cfg: ExperimentManagerConfig) -> Optional["asyncio.subprocess.Process"]:
        """Launch the harness-side process (if any), then emit RUNNING."""
        access = self._load_access(experiment.experiment_name, cfg)
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(TrafficSignal.RUNNING)
        return process

    async def run_stop(self, experiment, cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop(). Idempotent: a second call after STOPPED does nothing."""
        lc = self._lifecycle(experiment)
        if lc is not None and lc.status == TrafficSignal.STOPPED:
            return
        if lc is not None and lc.status != TrafficSignal.FAILED:
            await lc.emit(TrafficSignal.STOPPING)
        access = self._load_access(experiment.experiment_name, cfg)
        try:
            await self.stop(experiment, cfg, access=access)
        finally:
            if lc is not None and lc.status != TrafficSignal.FAILED:
                await lc.emit(TrafficSignal.STOPPED)

    async def run_collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Load the persisted scoped access and hand the whole list to collect_logs()."""
        access = self._load_access(experiment.experiment_name, cfg)
        await self.collect_logs(experiment, cfg, dest, access=access)

    async def run_rearm(self, experiment, cfg: ExperimentManagerConfig, host_name: str) -> None:
        """Rearm one rebuilt host, if traffic covers it and is still running. Never raises."""
        lc = self._lifecycle(experiment)
        if lc is not None and lc.status != TrafficSignal.RUNNING:
            return
        for a in (self._load_access(experiment.experiment_name, cfg) or []):
            if a.name == host_name:
                try:
                    await self.rearm(experiment, cfg, a)
                except Exception:  # noqa: BLE001
                    get_logger(experiment.experiment_name).exception("traffic rearm of %s failed", host_name)
                return
