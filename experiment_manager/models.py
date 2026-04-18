from enum import Enum
from typing import Optional
from pydantic import BaseModel
from datetime import datetime


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    READY = "Ready"
    RUNNING = "Running"
    ERROR = "Error"
    FINISHED = "Finished"


class DeployedEnvironment(BaseModel):
    openstack_id: str
    ip: str
    spec: str


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: str
    attacker: Optional[str] = None
    defender: Optional[str] = None
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup


class Experiment(BaseModel):
    experiment_name: str
    status: ExperimentStatus
    environment_spec: str
    attacker: Optional[str] = None
    defender: Optional[str] = None
    deployed_environment: Optional[DeployedEnvironment] = None
    pid: Optional[int] = None
    c2c_container_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
