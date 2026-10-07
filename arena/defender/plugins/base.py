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
    """Opaque handoff from setup() to build_config()/start(). A defender subclasses this to carry arming outputs."""


class DefenderPlugin(BaseModel):
    """Base class for a defender plugin: a mirror of AttackerPlugin that differs only in objective, not lifecycle."""

    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    # Keys this plugin's runner requires in build_config()'s output. Empty means no declared contract.
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # External-code-path fields: a defender backed by an external repo names its own config fields here.
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    # Whether this defender issues env actions (restore / BlockIP / deploy-decoy) that need the env channel.
    uses_env_actions: ClassVar[bool] = False

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
        prepared: "PreparedDefender",
    ) -> dict:
        """REQUIRED. The run config the runner reads. Ignore prepared unless setup() produced state the config needs."""
        ...

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        """REQUIRED. The dashboard form for this plugin."""
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """REQUIRED (unless you override start()). Launch the reactive-loop process and return it."""
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedDefender":
        """OPTIONAL. Arm the defender and block until it is actually armed, then return the baton. Default: nothing to arm."""
        return PreparedDefender()

    async def start(
        self,
        prepared: "PreparedDefender",
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        access=None,
    ) -> asyncio.subprocess.Process:
        """OPTIONAL (default: call run()). Launch the reactive loop and return the process. setup() established arming."""
        return await self.run(config_path, experiment_name, cfg)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        """OPTIONAL. Stop the defender process. Local pid here. Override to use access for a cleaner remote kill."""
        if getattr(experiment, "defender_pid", None):
            try:
                os.kill(experiment.defender_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def teardown(self, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """OPTIONAL. Release host-side resources this defender created at environment teardown. Must be safe to call with nothing to release and must never raise."""
        return None

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        """OPTIONAL. Copy defender-side logs into dest. Default no-op, because a harness-run defender's logs are already local."""

    @classmethod
    def example_prepared(cls) -> "PreparedDefender":
        """OPTIONAL. A representative PreparedDefender to exercise build_config() offline, without setup() or a cloud or box ES."""
        return PreparedDefender()

    # Defender-only surface hook (no attacker twin): the environment opens box ports for telemetry or forwarding.
    def box_ingress(self) -> dict[str, list[int]]:
        """OPTIONAL. The box-ingress ports this defender needs the environment to open, by kind. Default {} opens none."""
        return {}

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
    def primary_access(access) -> "DefenderSetupAccess":
        """The first scoped DefenderSetupAccess. WARNING: the defender access list is victims-first and box-last, so access[0] is a victim, NOT the box. A box-resident defender MUST select its box by env_spec.box.ip."""
        if not access:
            raise RuntimeError("no DefenderSetupAccess passed to the defender — the arena must pass it to run_setup()")
        return access[0]

    # Scoped access recovery: run_setup persists the whole access list (box and victims) and the run_* wrappers load it back.
    _ACCESS_FILE: ClassVar[str] = "setup_access.json"

    @classmethod
    def _access_path(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / cls._ACCESS_FILE

    def _persist_access(self, experiment_name: str, cfg: ExperimentManagerConfig, access) -> None:
        """Internal (run_setup): write the whole scoped access list (box and victims) so the run_* wrappers can recover it."""
        path = self._access_path(experiment_name, cfg)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([a.model_dump() for a in (access or [])]))

    def _load_access(self, experiment_name: str, cfg: ExperimentManagerConfig):
        """Internal (run_* wrappers): recover the persisted scoped access list, or None if absent or unreadable."""
        try:
            raw = json.loads(self._access_path(experiment_name, cfg).read_text())
            return [DefenderSetupAccess.model_validate(a) for a in raw]
        except Exception:  # noqa: BLE001
            return None

    # Lifecycle templates the arena drives (see lifecycle.py): emit the defender's signals around setup(), start() and stop().
    @staticmethod
    def _lifecycle(experiment):
        return getattr(experiment, "_defender_lifecycle", None)

    async def run_setup(self, experiment, cfg: ExperimentManagerConfig) -> "PreparedDefender":
        """The setup phase: emit SETUP_STARTED, run setup() (blocks until armed), write the runner config, emit READY, return prepared."""
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.SETUP_STARTED)
        experiment_name = experiment.experiment_name
        access = experiment._defender_access             # scoped SetupAccess list (key + bastion routing)
        bastion_ip = experiment._bastion_ip             # this experiment's ephemeral bastion floating IP
        if access and cfg is not None:
            self._persist_access(experiment_name, cfg, access)
        try:
            prepared = await self.setup(experiment, cfg, bastion_ip, access)  # arm (blocks until armed)
            # build_config runs in the setup phase: setup() produces prepared, build_config derives the config.
            if cfg is not None:
                env_spec = experiment._defender_env_spec        # agent-facing DefenderEnvSpec (NO creds)
                config_path = (output_root(experiment_name, cfg)
                               / experiment_name / "defender" / "defender_config.json")
                config_path.parent.mkdir(parents=True, exist_ok=True)
                built = self.build_config(experiment_name, env_spec, prepared)
                type(self).validate_built_config(built)
                # Inject the credential-bearing scoped access and routing the runner reads (kept out of build_config by the leak guard).
                if env_spec is not None:
                    built["defender_env_spec"] = env_spec.model_dump()
                built["defender_setup_access"] = [a.model_dump() for a in (access or [])]
                built["management_ip"] = cfg.arena_host_ip
                built["bastion_ip"] = bastion_ip
                built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
                config_path.write_text(json.dumps(built, indent=2))
        except Exception as e:  # noqa: BLE001
            if lc is not None:
                await lc.emit(DefenderSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(DefenderSignal.READY)
        return prepared

    async def run_start(self, experiment, prepared: "PreparedDefender", config_path: Path,
                        cfg: ExperimentManagerConfig) -> "asyncio.subprocess.Process":
        """Launch the reactive loop, then emit RUNNING. The defender is already READY (armed in setup())."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, access=access)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.RUNNING)
        return process

    async def run_stop(self, experiment, cfg: ExperimentManagerConfig) -> None:
        """Emit STOPPING/STOPPED around stop(). Guarded against a prior terminal FAILED and against double-stop."""
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
        """Load the persisted scoped access and hand the primary entry to collect_logs()."""
        access_list = self._load_access(experiment.experiment_name, cfg)
        access = self.primary_access(access_list) if access_list else None
        await self.collect_logs(experiment, cfg, dest, access=access)
