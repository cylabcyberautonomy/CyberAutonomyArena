"""Attacker-facing environment types."""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class AttackerUser(BaseModel):
    """A login account on a host."""
    name: str


class AttackerHost(BaseModel):
    """Identity of a host, at the attacker's knowledge level."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None
    users: list[AttackerUser] = Field(default_factory=list)
    telemetry: bool = False


class AttackerSubnet(BaseModel):
    """A subnet as the environment exposes it."""
    name: str
    network: Optional[str] = None
    sec_group: Optional[str] = None
    hosts: list[AttackerHost] = Field(default_factory=list)
    perimeter: bool = False


class AttackerBox(BaseModel):
    """The box this system runs on. For the attacker, this is the foothold."""
    name: str = "foothold"
    ip: Optional[str] = None
    subnet: Optional[str] = None
    user: str = "root"


class AttackerEnvSpec(BaseModel):
    """The run spec. The attacker populates only objective and box."""
    objective: str = "none"
    box: Optional[AttackerBox] = None
    hosts: list[AttackerHost] = Field(default_factory=list)
    subnets: list[AttackerSubnet] = Field(default_factory=list)
    network_name: Optional[str] = None
    management_sg: Optional[str] = None

    @property
    def primary(self) -> Optional[AttackerBox]:
        """The attacker's starting box (the foothold)."""
        return self.box

    @property
    def footholds(self) -> list[AttackerBox]:
        """Every box the attacker has a foothold on, derived from the spec."""
        out: list[AttackerBox] = []
        if self.box is not None:
            out.append(self.box)
        seen = {self.box.ip} if self.box else set()
        hosts = list(self.hosts) + [h for s in self.subnets for h in s.hosts]
        for h in hosts:
            if h.users and h.ip not in seen:
                out.append(AttackerBox(name=h.name, ip=h.ip, subnet=None, user=h.users[0].name))
                seen.add(h.ip)
        return out


class AttackerSetupAccess(BaseModel):
    """Setup access: how the trusted plugin reaches one box to prep it."""
    name: str = "foothold"
    host: str
    user: str = "root"
    port: int = 22
    ssh_key: Optional[str] = None
    ssh_common_args: str = ""

    def ssh_base(self) -> list[str]:
        """An ssh command prefix that runs a remote command on this box."""
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
