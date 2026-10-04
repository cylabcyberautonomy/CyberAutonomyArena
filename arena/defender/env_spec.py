"""Defender-facing environment types.

This file MIRRORS attacker/env_spec.py exactly: the two define the SAME parallel type tree with the SAME
fields (DefenderUser/AttackerUser, DefenderHost/AttackerHost, DefenderSubnet/AttackerSubnet,
DefenderBox/AttackerBox, DefenderEnvSpec/AttackerEnvSpec, DefenderSetupAccess/AttackerSetupAccess). The
ONLY difference is which fields the environment POPULATES — the information a system is entitled to know,
not the format of the transfer:

  - the DEFENDER gets what a blue team knows about its OWN estate: the objective + the subnet/host
    inventory (name/ip/role/users — a real org knows its own assets) + its own box.
  - the ATTACKER gets only what it already knows about itself: the objective + its own box (the foothold);
    hosts/subnets stay empty (it discovers the estate).

Two deliberately separate objects (same split on both sides):

  DefenderEnvSpec — the RUN SPEC: the runtime information the defender acts on (objective + inventory +
                    subnet structure + the defender's own box). NO credentials, NO routing — the
                    defender's brain doesn't need them at runtime. This is what build_config() consumes.

  DefenderSetupAccess — the SETUP ACCESS: how the trusted defender *plugin* reaches a host to set itself
                    up / install bespoke sensors (ssh key + routing). Produced by the environment and used
                    at setup time. It carries the key because that's what SETUP needs — the split is setup
                    vs runtime, not a secret the defender must never see.

They're separate because they're used at different times, not because the run spec is secret: it carries
nothing that would matter if it leaked (see docs/security-model.md). Both are provider-agnostic DTOs the
environment produces (MHBench today). The spec is fully self-describing: the ENVIRONMENT resolves the
backend network / security-group NAMES into `subnets` so the defender never parses a backend topology.
"""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class DefenderUser(BaseModel):
    """A login account on a host (mirrors AttackerUser). The defender uses these for honey-cred placement."""
    name: str


class DefenderHost(BaseModel):
    """Identity of a host in the defended estate, at the defender's knowledge level (mirrors AttackerHost).
    A real org knows its own assets, so for the defender this is fully populated."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None                        # e.g. "webserver", "database" (derived from the name)
    users: list[DefenderUser] = Field(default_factory=list)   # login accounts the host has (honey-cred placement)
    telemetry: bool = False                            # the env ships this host's sysflow/falco to the box


class DefenderSubnet(BaseModel):
    """A subnet of the DEFENDED estate as the environment exposes it (mirrors AttackerSubnet).

    Only the defended estate appears here — the attacker's own segment is NOT included (a real blue team
    doesn't know where the red team sits). Backend-neutral: the environment has already resolved the cloud
    network / security-group NAMES, so a decoy defender places a decoy by naming `network`/`sec_group`
    without knowing the backend convention. `perimeter` is the one placement hint — the internet-facing /
    DMZ tier, a legitimate property the org knows about its own estate — so deception can bait the ingress."""
    name: str                                          # logical subnet name (e.g. "webserver_subnet")
    network: Optional[str] = None                      # backend network to attach a new host to (env-resolved)
    sec_group: Optional[str] = None                    # the subnet's security group (env-resolved)
    hosts: list[DefenderHost] = Field(default_factory=list)
    perimeter: bool = False                            # the internet-facing / DMZ tier (legit; bait here)


class DefenderBox(BaseModel):
    """The box this system runs on / operates from (mirrors AttackerBox). For the defender it's the
    always-provisioned, isolated box it RUNS on: it can reach the victims + the telemetry relay but is
    hidden from the attacker. Part of the run spec (the defender knows its own box); the harness reaches it
    at setup time via a DefenderSetupAccess entry of the same name.

    REQUIREMENT (design, not a self-reported field): the environment MUST give this box internet EGRESS
    (outbound-only, for the LLM API) and NO ingress from the internet — see docs/security-model.md."""
    name: str = "defender_box"
    ip: Optional[str] = None                           # the box's own in-env address
    subnet: Optional[str] = None                       # the isolated subnet it lives on
    user: str = "root"                                 # the login account the system operates as


class DefenderEnvSpec(BaseModel):
    """The run spec (SAME fields as AttackerEnvSpec). The defender populates objective + box + the estate
    (hosts + subnets)."""
    objective: str = "none"
    box: Optional[DefenderBox] = None                 # the system's own box — here, the isolated defender box
    hosts: list[DefenderHost] = Field(default_factory=list)       # flat victim inventory (no attacker/box)
    subnets: list[DefenderSubnet] = Field(default_factory=list)   # full defended-estate structure
    network_name: Optional[str] = None               # the backend network name (Perry Network.name)
    management_sg: Optional[str] = None              # the shared management security group (env-resolved)


class DefenderSetupAccess(BaseModel):
    """Setup access: how the trusted plugin reaches one box to prep it (setup-time key + routing).
    MIRRORS AttackerSetupAccess field-for-field."""
    name: str = "defender_box"
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
