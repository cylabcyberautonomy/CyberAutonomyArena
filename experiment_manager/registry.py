import asyncio
from pathlib import Path
from typing import List
from datetime import datetime, timezone

import yaml

from .models import Experiment


class Registry:
    def __init__(self, path: str = "registry.yaml"):
        self._path = Path(path)
        self._lock = asyncio.Lock()

    def _read(self) -> List[dict]:
        if not self._path.exists():
            return []
        with open(self._path) as f:
            data = yaml.safe_load(f) or {}
        return data.get("experiments", [])

    def _write(self, experiments: List[Experiment]) -> None:
        with open(self._path, "w") as f:
            yaml.dump(
                {"experiments": [e.model_dump(mode="json") for e in experiments]},
                f,
                default_flow_style=False,
            )

    def load(self) -> List[Experiment]:
        return [Experiment(**e) for e in self._read()]

    async def add(self, experiment: Experiment) -> None:
        async with self._lock:
            experiments = self.load()
            if any(e.experiment_name == experiment.experiment_name for e in experiments):
                raise ValueError(f"Experiment '{experiment.experiment_name}' already exists")
            experiments.append(experiment)
            self._write(experiments)

    async def update(self, experiment: Experiment) -> None:
        async with self._lock:
            experiments = self.load()
            for i, e in enumerate(experiments):
                if e.experiment_name == experiment.experiment_name:
                    experiment.updated_at = datetime.now(timezone.utc)
                    experiments[i] = experiment
                    self._write(experiments)
                    return
            raise KeyError(f"Experiment '{experiment.experiment_name}' not found")

    async def clear(self) -> None:
        async with self._lock:
            self._write([])

    def get(self, experiment_name: str) -> Experiment:
        for e in self.load():
            if e.experiment_name == experiment_name:
                return e
        raise KeyError(f"Experiment '{experiment_name}' not found")
