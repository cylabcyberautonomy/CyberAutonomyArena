from enum import Enum
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

from ..attacker import AttackerConfig
from ..defender import DefenderConfig
from ..environment import DeployedEnvironment


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    DEPLOYING = "Deploying"
    RUNNING = "Running"
    ERROR = "Error"
    FINISHED = "Finished"


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup


class Experiment(BaseModel):
    experiment_name: str
    status: ExperimentStatus
    environment_spec: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    deployed_environment: Optional[DeployedEnvironment] = None
    pid: Optional[int] = None
    c2c_container_id: Optional[str] = None
    retry_count: int = 0
    base_name: str = ""
    created_at: datetime
    updated_at: datetime
    environment_deploy_started_at: Optional[datetime] = None
    environment_deploy_finished_at: Optional[datetime] = None
    defender_started_at: Optional[datetime] = None
    defender_finished_at: Optional[datetime] = None
    attacker_started_at: Optional[datetime] = None
    attacker_finished_at: Optional[datetime] = None
    teardown_started_at: Optional[datetime] = None
    teardown_finished_at: Optional[datetime] = None
