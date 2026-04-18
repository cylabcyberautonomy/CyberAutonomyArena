from pathlib import Path

import yaml
from pydantic import BaseModel

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


_DOCKER_DIR = Path(__file__).parent.parent / "docker"


class ExperimentManagerConfig(BaseModel):
    incalmo_dir: Path
    output_dir: Path
    registry_path: Path
    c2c_port: int = 8888
    c2c_dockerfile_dir: Path = _DOCKER_DIR / "c2c"
    c2c_image_tag: str = "experiment-harness/c2c:latest"

    @classmethod
    def load(cls, path: Path = _DEFAULT_CONFIG_PATH) -> "ExperimentManagerConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
