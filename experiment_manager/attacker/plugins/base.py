import asyncio
import os
import signal
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ..env_spec import AttackerEnvSpec
from ..lifecycle import AttackerSignal
from ...ui_schema import PluginUISchema

if TYPE_CHECKING:
    from ...experiment import Experiment


@dataclass
class PreparedAttacker:
    container_id: Optional[str] = None
    remote_url: Optional[str] = None
    local_url: Optional[str] = None


class AttackerPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["AttackerPlugin"]]] = {}
    requires_docker: ClassVar[bool] = False  # True if setup needs a local Docker daemon (e.g. a C2 container); gates an early preflight

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
        c2c_url: str,
    ) -> dict: ...

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        c2c_url: str,
        agent_c2c_url: Optional[str] = None,
    ) -> asyncio.subprocess.Process:
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def launch_c2c(  # noqa: D401
        self, experiment_name: str, cfg: ExperimentManagerConfig, mgmt_ip: Optional[str] = None,
        kali_ip: Optional[str] = None,
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Start the C2 server. Returns (container_id, kali_url, local_url) or (None, None, None).
        mgmt_ip/kali_ip are accepted (and ignored here) so setup() can pass them uniformly; the GCP
        C2 needs mgmt_ip and the in-env Kali C2 (c2_on_kali) needs kali_ip. Any plugin not overriding
        this must still accept the call."""
        return None, None, None

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        """Block until the C2 server is accepting requests."""

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        """Block until at least one agent has beaconed to the C2 server."""

    async def stop_c2c(self, container_id: str) -> None:
        """Stop and remove the C2 server container."""

    async def prepare_foothold(
        self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str],
        remote_url: Optional[str],
    ) -> None:
        """Attacker-owned prep of its own foothold box (default: nothing). The environment only
        provides the box + access; the attacker does everything ON it here, over the bastion using
        the AttackerEnvSpec credentials — NOT via MHBench. Runs after the C2 is up and before the
        attacker channel/agent is awaited."""
        return

    async def setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str]) -> PreparedAttacker:
        """Attacker-specific setup on the ready (attacker-neutral) environment: bring up any C2, let
        the attacker prep its own foothold, and block until the attacker channel is ready.
        Transactional: tears down its own partial C2 on failure."""
        # kali_ip: the in-environment Kali VM's (internal) address, where the C2 runs when
        # c2_on_kali is set. deployed_environment.ip holds it; None for envs without one.
        kali_ip = experiment.deployed_environment.ip if experiment.deployed_environment else None
        container_id, remote_url, local_url = await self.launch_c2c(experiment.experiment_name, cfg, mgmt_ip, kali_ip)
        try:
            if local_url:
                await self.wait_c2c_ready(local_url, experiment.experiment_name)
            await self.prepare_foothold(experiment, cfg, mgmt_ip, remote_url)
            if local_url:
                await self.wait_c2c_agent(local_url, experiment.experiment_name)
        except Exception:
            if container_id:
                await self.stop_c2c(container_id)
            raise
        return PreparedAttacker(container_id, remote_url, local_url)

    async def start(
        self,
        prepared: PreparedAttacker,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        c2c_url: Optional[str],
        agent_c2c_url: Optional[str] = None,
    ) -> asyncio.subprocess.Process:
        """Launch the attacker process (exit code = verdict). Channel readiness was established in setup()."""
        return await self.run(config_path, experiment_name, cfg, c2c_url, agent_c2c_url)

    async def stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        """Terminate the attacker process(es). Local pid here; override to also kill remote procs.
        C2/range infra is torn down separately (stop_c2c) so its log can be saved first."""
        if experiment.pid:
            try:
                os.kill(experiment.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    async def collect_logs(self, experiment: "Experiment", cfg: ExperimentManagerConfig, dest: Path) -> None:
        """Pull attacker-specific logs into dest. Default no-op — logs already local."""

    # ------------------------------------------------------------------ lifecycle handshake
    # Templates the arena drives (see lifecycle.py). They emit the attacker's signals around the
    # overridable setup()/stop() so the arena can wait for each. The lifecycle lives on the
    # experiment (set by the arena); when absent (e.g. clean-slate stop of a registry-loaded run)
    # these behave exactly like the plain methods.
    @staticmethod
    def _lifecycle(experiment: "Experiment"):
        return getattr(experiment, "_attacker_lifecycle", None)

    async def run_setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str]) -> "PreparedAttacker":
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.SETUP_STARTED)
        try:
            prepared = await self.setup(experiment, cfg, mgmt_ip)
        except Exception as e:  # noqa: BLE001 — surface as a FAILED signal, then re-raise for the arena
            if lc is not None:
                await lc.emit(AttackerSignal.FAILED, error=str(e))
            raise
        if lc is not None:
            await lc.emit(AttackerSignal.READY)
        return prepared

    async def run_start(self, experiment: "Experiment", prepared: PreparedAttacker, config_path: Path,
                        cfg: ExperimentManagerConfig, c2c_url: Optional[str],
                        agent_c2c_url: Optional[str] = None) -> "asyncio.subprocess.Process":
        """Launch the attack process, then emit RUNNING — the attacker telling the arena its process
        is up. The arena waits for RUNNING (it does not emit it), same as READY."""
        process = await self.start(prepared, config_path, experiment.experiment_name, cfg, c2c_url, agent_c2c_url)
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.RUNNING)
        return process

    async def run_stop(self, experiment: "Experiment", cfg: ExperimentManagerConfig) -> None:
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(AttackerSignal.STOPPING)
        try:
            await self.stop(experiment, cfg)
        finally:
            if lc is not None:
                await lc.emit(AttackerSignal.STOPPED)
