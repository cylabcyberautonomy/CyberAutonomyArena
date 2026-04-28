import asyncio
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
from ...ui_schema import PluginUISchema


class DefenderPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            DefenderPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict: ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process: ...
