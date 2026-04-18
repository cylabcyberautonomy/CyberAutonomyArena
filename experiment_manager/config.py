from pathlib import Path

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"


class ExperimentManagerConfig(BaseModel):
    incalmo_dir: Path
    output_dir: Path = _HERE / "output"
    registry_path: Path = _HERE / "experiment_registry.yaml"
    c2c_dockerfile_dir: Path = _HERE / "docker" / "c2c"

    @classmethod
    def load(cls, path: Path = _DEFAULT_CONFIG_PATH) -> "ExperimentManagerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
