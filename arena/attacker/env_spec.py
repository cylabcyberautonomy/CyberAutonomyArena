"""Attacker-facing environment types.

Two deliberately separate objects:

  AttackerEnvSpec  — the RUN SPEC: the runtime information the attacker acts on. It carries only the
                     objective and the foothold IDENTITY (name/host/user — the box's own in-env address
                     and account, which the adversary already knows about itself). NO keys, NO bastion,
                     NO routing — the agent doesn't need them at runtime. This is what build_config()
                     consumes and what conceptually "the attacker gets".

  SetupAccess   — the SETUP ACCESS: how the trusted attacker *plugin* reaches a foothold to set it up
                     (ssh key + routing, e.g. a bastion ProxyCommand). Produced by the environment and
                     handed to the plugin's prepare_foothold(). It carries the key because that's what
                     SETUP needs — the split is setup vs runtime, not a secret the agent must never see.

They're separate because they're used at different times, not because the run spec is secret: it carries
nothing that would matter if it leaked anyway. The management plane's safety rests on credential scoping
(no god key) + the environment decoupling the bastion's ingress — not on hiding the spec (see
docs/security-model.md).

Both are provider-agnostic DTOs the ENVIRONMENT produces (MHBench today via
environment/deployer.py; other env plugins later).
"""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class AttackerFoothold(BaseModel):
    """Identity of a box the attacker starts on / operates from (part of the run spec)."""
    name: str = "foothold"
    host: Optional[str] = None   # the box's own in-env IP (the adversary knows its own address)
    user: str = "root"


class AttackerEnvSpec(BaseModel):
    """The run spec: objective + foothold identities only."""
    objective: str = "none"
    footholds: list[AttackerFoothold] = Field(default_factory=list)

    @property
    def primary(self) -> Optional[AttackerFoothold]:
        return self.footholds[0] if self.footholds else None


class SetupAccess(BaseModel):
    """Setup access: how the trusted plugin reaches one foothold to prep it (setup-time key + routing)."""
    name: str = "foothold"
    host: str
    user: str = "root"
    port: int = 22
    ssh_key: Optional[str] = None
    ssh_common_args: str = ""   # e.g. a ProxyCommand for a bastion/relay; "" = directly reachable

    def ssh_base(self) -> list[str]:
        """An ssh command prefix that runs a remote command on this box, using its env-provided
        routing (ssh_common_args carries the ProxyCommand/relay opts; "" = directly reachable).

        This is a pure operation on the access data, not an attacker concern — any system the
        environment grants a scoped SetupAccess (attacker foothold, defender box, traffic host) reaches
        its box the same way, so the transport lives on the DTO, callable as `access.ssh_base()`."""
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
