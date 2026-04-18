import asyncio
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ..config import ExperimentManagerConfig
from ..environment import DeployedEnvironment


class AttackerPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["AttackerPlugin"]]] = {}
    c2c_image: ClassVar[str]

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            if not hasattr(cls, "c2c_image"):
                raise TypeError(f"{cls.__name__} must define c2c_image")
            AttackerPlugin._registry[config_type] = cls

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
