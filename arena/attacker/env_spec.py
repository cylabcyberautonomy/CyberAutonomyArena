"""Attacker-facing environment types.

This file MIRRORS defender/env_spec.py exactly: the two define the SAME parallel type tree with the SAME
fields (AttackerUser/DefenderUser, AttackerHost/DefenderHost, AttackerSubnet/DefenderSubnet,
AttackerBox/DefenderBox, AttackerEnvSpec/DefenderEnvSpec, AttackerSetupAccess/DefenderSetupAccess). The
ONLY difference between a run and the other is which fields the environment POPULATES — the information a
system is entitled to know about the environment, not the format of the transfer:

  - the ATTACKER gets only what it already knows about *itself*: the objective + its own box (the foothold).
    hosts/subnets stay empty — the attacker discovers the estate, it isn't handed an inventory.
  - the DEFENDER gets what a blue team knows about its *own* estate: the objective + the subnet/host
    inventory + its own box.

Two deliberately separate objects (same split on both sides):

  AttackerEnvSpec  — the RUN SPEC: the runtime information the attacker acts on. Carries only identity the
                     adversary already knows (objective + the foothold box's own in-env address/account).
                     NO keys, NO bastion, NO routing. This is what build_config() consumes.

  AttackerSetupAccess — the SETUP ACCESS: how the trusted attacker *plugin* reaches a box to set it up
                     (ssh key + routing, e.g. a bastion ProxyCommand). Produced by the environment and
                     handed to the plugin's prepare step. It carries the key because that's what SETUP
                     needs — the split is setup vs runtime, not a secret the agent must never see.

They're separate because they're used at different times, not because the run spec is secret: it carries
nothing that would matter if it leaked. The management plane's safety rests on credential scoping (no god
key) + the environment decoupling the bastion's ingress — not on hiding the spec (see docs/security-model.md).

Both are provider-agnostic DTOs the ENVIRONMENT produces (MHBench today via environment/.../deployer.py).
"""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class AttackerUser(BaseModel):
    """A login account on a host (mirrors DefenderUser). A host the attacker holds creds for is a foothold."""
    name: str


class AttackerHost(BaseModel):
    """Identity of a host, at the attacker's knowledge level (mirrors DefenderHost). For the attacker this
    is populated only for hosts it already has standing on — the estate at large is discovered, not given."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None                        # e.g. "webserver", "database"
    users: list[AttackerUser] = Field(default_factory=list)  # accounts the attacker holds here (creds ⇒ foothold)
    telemetry: bool = False


class AttackerSubnet(BaseModel):
    """A subnet as the environment exposes it (mirrors DefenderSubnet). Empty for the attacker today."""
    name: str
    network: Optional[str] = None                     # env-resolved backend network name
    sec_group: Optional[str] = None                   # env-resolved security group
    hosts: list[AttackerHost] = Field(default_factory=list)
    perimeter: bool = False                            # internet-facing / DMZ tier (legit estate property)


class AttackerBox(BaseModel):
    """The box this system runs on / operates from (mirrors DefenderBox). For the attacker it's the
    foothold: the adversary knows its own box's address + account."""
    name: str = "foothold"
    ip: Optional[str] = None                           # the box's own in-env address
    subnet: Optional[str] = None                       # the subnet it lives on
    user: str = "root"                                 # the login account the system operates as


class AttackerEnvSpec(BaseModel):
    """The run spec (SAME fields as DefenderEnvSpec). The attacker populates only objective + box."""
    objective: str = "none"
    box: Optional[AttackerBox] = None                 # the system's own box — here, the foothold
    hosts: list[AttackerHost] = Field(default_factory=list)      # flat inventory (empty for the attacker today)
    subnets: list[AttackerSubnet] = Field(default_factory=list)  # subnet structure (empty for the attacker today)
    network_name: Optional[str] = None               # backend network name
    management_sg: Optional[str] = None              # shared management security group

    @property
    def primary(self) -> Optional[AttackerBox]:
        """The attacker's starting box (the foothold)."""
        return self.box

    @property
    def footholds(self) -> list[AttackerBox]:
        """Every box the attacker has a foothold on — DERIVED from the spec, not stored: the starting box
        plus any known host it holds creds on (a host with `users` is a foothold). Today only the box is
        populated, so this is just `[box]`; it grows automatically as credentialed hosts are added."""
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
    """Setup access: how the trusted plugin reaches one box to prep it (setup-time key + routing).
    MIRRORS DefenderSetupAccess field-for-field."""
    name: str = "foothold"
    host: str
    user: str = "root"
    port: int = 22
    ssh_key: Optional[str] = None
    ssh_common_args: str = ""   # e.g. a ProxyCommand for a bastion/relay; "" = directly reachable

    def ssh_base(self) -> list[str]:
        """An ssh command prefix that runs a remote command on this box, using its env-provided routing
        (ssh_common_args carries the ProxyCommand/relay opts; "" = directly reachable). Pure operation on
        the access data — any system the environment grants a scoped SetupAccess reaches its box this way."""
        cmd = ["ssh"]
        if self.ssh_key:
            cmd += ["-i", os.path.expanduser(self.ssh_key)]
        cmd += [
            "-p", str(self.port),
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=10",
        ]
        if self.ssh_common_args:
            cmd += shlex.split(self.ssh_common_args)  # env-owned routing (e.g. -o ProxyCommand="...")
        cmd += [f"{self.user}@{self.host}"]
        return cmd
