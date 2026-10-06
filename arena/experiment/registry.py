import asyncio
from datetime import datetime, timezone
from typing import List, Optional

from .models import Experiment


class Registry:
    """In-memory store of live experiments, keyed by name."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._store: dict[str, Experiment] = {}
        self._lock = asyncio.Lock()

    def load(self) -> List[Experiment]:
        return list(self._store.values())

    async def add(self, experiment: Experiment) -> None:
        async with self._lock:
            if experiment.experiment_name in self._store:
                raise ValueError(f"Experiment '{experiment.experiment_name}' already exists")
            self._store[experiment.experiment_name] = experiment

    async def update(self, experiment: Experiment) -> None:
        async with self._lock:
            if experiment.experiment_name not in self._store:
                raise KeyError(f"Experiment '{experiment.experiment_name}' not found")
            experiment.updated_at = datetime.now(timezone.utc)
            self._store[experiment.experiment_name] = experiment

    async def remove(self, experiment_name: str) -> None:
        async with self._lock:
            self._store.pop(experiment_name, None)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    def get(self, experiment_name: str) -> Experiment:
        return self._store[experiment_name]
