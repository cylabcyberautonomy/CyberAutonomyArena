"""Defender-facing environment types (mirror of attacker/env_spec.py)."""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class DefenderUser(BaseModel):
    """A login account on a host (mirrors AttackerUser)."""
    name: str


class DefenderHost(BaseModel):
    """Identity of a host in the defended estate (mirrors AttackerHost)."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None
    users: list[DefenderUser] = Field(default_factory=list)
    telemetry: bool = False


class DefenderSubnet(BaseModel):
    """A subnet of the defended estate as the environment exposes it (mirrors AttackerSubnet)."""
    name: str
    network: Optional[str] = None
    sec_group: Optional[str] = None
    hosts: list[DefenderHost] = Field(default_factory=list)
    perimeter: bool = False


class DefenderBox(BaseModel):
    """The isolated box the defender runs on (mirrors AttackerBox)."""
    name: str = "defender_box"
    ip: Optional[str] = None
    subnet: Optional[str] = None
    user: str = "root"


class DefenderEnvSpec(BaseModel):
    """The run spec (same fields as AttackerEnvSpec)."""
    objective: str = "none"
    box: Optional[DefenderBox] = None
    hosts: list[DefenderHost] = Field(default_factory=list)
    subnets: list[DefenderSubnet] = Field(default_factory=list)
    network_name: Optional[str] = None
    management_sg: Optional[str] = None


class DefenderSetupAccess(BaseModel):
    """Setup-time access to one box (key + routing). Mirrors AttackerSetupAccess."""
    name: str = "defender_box"
    host: str
    user: str = "root"
    port: int = 22
    ssh_key: Optional[str] = None
    ssh_common_args: str = ""

    def ssh_base(self) -> list[str]:
        """An ssh command prefix that runs a remote command on this box using its env-provided routing."""
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
