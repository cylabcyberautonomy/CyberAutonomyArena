from pydantic import BaseModel


class DeployedEnvironment(BaseModel):
    openstack_id: str
    ip: str
    spec: str
