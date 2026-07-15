from enum import Enum
from typing import Optional
from pydantic import BaseModel, model_validator
from datetime import datetime

from ..attacker import AttackerConfig
from ..defender import DefenderConfig
from ..environment import DeployedEnvironment


class ExperimentStatus(str, Enum):
    QUEUED = "Queued"
    DEPLOYING = "Deploying"
    RUNNING = "Running"
    RETRYING = "Retrying"   # non-terminal: an attempt failed but the harness is auto-retrying it in place
    ERROR = "Error"
    FINISHED = "Finished"


class ExperimentSpecs(BaseModel):
    experiment_name: str
    environment: str
    attacker: Optional[AttackerConfig] = None
    defender: Optional[DefenderConfig] = None
    c2c_server: Optional[str] = None  # TEST ONLY: bypasses C2 container startup
    trial: int = 0
    output_dir: Optional[str] = None  # write this experiment's output tree here instead of cfg.output_dir
    teardown: bool = True  # set False to leave the env + C2 standing (success AND failure) to run an exploit by hand


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
    vcpus_reserved: Optional[int] = None
    ram_mb_reserved: Optional[int] = None
    teardown: bool = True
    created_at: datetime
    updated_at: Optional[datetime] = None

    @model_validator(mode="after")
    def _default_updated_at(self) -> "Experiment":
        if self.updated_at is None:
            self.updated_at = self.created_at
        return self
    environment_deploy_started_at: Optional[datetime] = None
    environment_deploy_finished_at: Optional[datetime] = None
    defender_started_at: Optional[datetime] = None
    defender_finished_at: Optional[datetime] = None
    attacker_started_at: Optional[datetime] = None
    attacker_finished_at: Optional[datetime] = None
    teardown_started_at: Optional[datetime] = None
    teardown_finished_at: Optional[datetime] = None
    trial: int = 0
