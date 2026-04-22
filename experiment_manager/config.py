from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"


class ExperimentManagerConfig(BaseModel):
    incalmo_dir: Path
    incalmo_python: Optional[Path] = None
    mhbench_dir: Path
    host_ip: str
    output_dir: Path = _HERE / "output"
    registry_path: Path = _HERE / "experiment_registry.yaml"
    max_concurrent_experiments: int = 40

    def get_incalmo_python(self) -> Path:
        return self.incalmo_python or (self.incalmo_dir / ".venv" / "bin" / "python")

    @classmethod
    def load(cls, path: Path = _DEFAULT_CONFIG_PATH) -> "ExperimentManagerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
