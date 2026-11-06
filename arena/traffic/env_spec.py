"""Traffic-facing environment types (mirror of attacker/env_spec.py and defender/env_spec.py)."""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class TrafficUser(BaseModel):
    """A login account on a host (mirrors AttackerUser/DefenderUser)."""
    name: str


class TrafficHost(BaseModel):
    """A host the traffic system generates benign activity on (mirrors AttackerHost/DefenderHost)."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None
    users: list[TrafficUser] = Field(default_factory=list)
    telemetry: bool = False


class TrafficSubnet(BaseModel):
    """A subnet as the environment exposes it (mirrors AttackerSubnet/DefenderSubnet)."""
    name: str
    network: Optional[str] = None
    sec_group: Optional[str] = None
    hosts: list[TrafficHost] = Field(default_factory=list)
    perimeter: bool = False


class TrafficBox(BaseModel):
    """A box the traffic system runs on (mirrors AttackerBox/DefenderBox). MHBench populates none."""
    name: str = "traffic_box"
    ip: Optional[str] = None
    subnet: Optional[str] = None
    user: str = "root"


class TrafficEnvSpec(BaseModel):
    """The run spec (same fields as AttackerEnvSpec/DefenderEnvSpec). The producer populates objective + hosts."""
    objective: str = "none"
    box: Optional[TrafficBox] = None
    hosts: list[TrafficHost] = Field(default_factory=list)
    subnets: list[TrafficSubnet] = Field(default_factory=list)
    network_name: Optional[str] = None
    management_sg: Optional[str] = None


class TrafficSetupAccess(BaseModel):
    """Setup-time access to one host (key + routing). Mirrors AttackerSetupAccess/DefenderSetupAccess."""
    name: str = "traffic_host"
    host: str
    user: str = "root"
    port: int = 22
    ssh_key: Optional[str] = None
    ssh_common_args: str = ""

    def ssh_base(self) -> list[str]:
        """An ssh command prefix that runs a remote command on this host using its env-provided routing."""
        cmd = ["ssh"]
        if self.ssh_key:
            cmd += ["-i", os.path.expanduser(self.ssh_key)]
        cmd += [
            "-p", str(self.port),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=10",
        ]
        if self.ssh_common_args:
            cmd += shlex.split(self.ssh_common_args)
        cmd += [f"{self.user}@{self.host}"]
        return cmd
