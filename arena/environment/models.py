from typing import Optional
from pydantic import BaseModel


class DeployedEnvironment(BaseModel):
    topology_spec: str
    ip: Optional[str] = None    # kali floating IP
    spec: Optional[str] = None  # environment name passed to Incalmo as "environment"
