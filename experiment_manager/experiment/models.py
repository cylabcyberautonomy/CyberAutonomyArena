from enum import Enum
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

from ..attacker import AttackerConfig
from ..environment import DeployedEnvironment


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    DEPLOYING = "Deploying"
    READY = "Ready"
    RUNNING = "Running"
    ERROR = "Error"
    FINISHED = "Finished"


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[str] = None
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup


class Experiment(BaseModel):
    experiment_name: str
    status: ExperimentStatus
    environment_spec: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[str] = None
    deployed_environment: Optional[DeployedEnvironment] = None
    pid: Optional[int] = None
    c2c_container_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
