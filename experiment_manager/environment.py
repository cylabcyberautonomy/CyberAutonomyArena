from typing import Optional
from pydantic import BaseModel


class DeployedEnvironment(BaseModel):
    network: str
    subnet: str
    router: str
    security_group: str
    keypair: str
    manage_server: str
    kali_server: str
    ip: Optional[str] = None   # set once deployment completes
    spec: Optional[str] = None  # set once deployment completes
