import asyncio
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
from ...ui_schema import PluginUISchema


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
        environment: Optional[DeployedEnvironment],
        c2c_url: str,
    ) -> dict: ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        c2c_url: str,
    ) -> asyncio.subprocess.Process: ...

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
