import asyncio
import os
import signal
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
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
    setup_play: ClassVar[Optional[str]] = None  # kali runtime play the harness runs instead of the registry default; None = registry default
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
        environment: Optional[DeployedEnvironment],
        c2c_url: str,
    ) -> dict: ...

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        c2c_url: str,
    ) -> asyncio.subprocess.Process:
        raise NotImplementedError(f"{type(self).__name__} must implement run() or override start()")

    async def launch_c2c(
        self, experiment_name: str, cfg: ExperimentManagerConfig
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Start the C2 server. Returns (container_id, kali_url, local_url) or (None, None, None)."""
        return None, None, None

    async def wait_c2c_ready(self, local_url: str, experiment_name: str) -> None:
        """Block until the C2 server is accepting requests."""

    async def wait_c2c_agent(self, local_url: str, experiment_name: str) -> None:
        """Block until at least one agent has beaconed to the C2 server."""

    async def stop_c2c(self, container_id: str) -> None:
        """Stop and remove the C2 server container."""

    async def setup(self, experiment: "Experiment", cfg: ExperimentManagerConfig, mgmt_ip: Optional[str]) -> PreparedAttacker:
        """Attacker-specific setup on the ready (attacker-neutral) environment: bring up any C2, run the
        attacker's setup_play on the kali host, and block until the attacker channel is ready. Transactional:
        tears down its own partial C2 on failure."""
        from ...environment.deployer import run_attacker_setup_play
        container_id, remote_url, local_url = await self.launch_c2c(experiment.experiment_name, cfg)
        try:
            if local_url:
                await self.wait_c2c_ready(local_url, experiment.experiment_name)
            if self.setup_play:
                await run_attacker_setup_play(experiment, mgmt_ip, self.setup_play, remote_url, cfg)
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
    ) -> asyncio.subprocess.Process:
        """Launch the attacker process (exit code = verdict). Channel readiness was established in setup()."""
        return await self.run(config_path, experiment_name, cfg, c2c_url)

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
