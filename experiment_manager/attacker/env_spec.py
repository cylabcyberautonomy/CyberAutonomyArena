"""Attacker-facing environment types.

Two deliberately separate objects:

  AttackerEnvSpec  — ADVERSARY-SAFE. You could hand this to the adversary under evaluation and
                     nothing bad happens: it carries only the objective and the foothold IDENTITY
                     (name/host/user — the box's own in-env address and account, which the adversary
                     already knows about itself). NO keys, NO bastion, NO routing. This is what
                     build_config() consumes and what conceptually "the attacker gets".

  SetupAccess   — HARNESS-ONLY. How the trusted attacker *plugin* reaches a foothold to set it up
                     (ssh key + routing, e.g. a bastion ProxyCommand). Produced by the environment,
                     handed to the plugin's prepare_foothold(), and NEVER given to the adversary.

Keeping them separate makes the invariant checkable: AttackerEnvSpec has no field that would matter
if it leaked. The management plane's safety does not rest on hiding it here — it rests on the
environment decoupling the bastion's ingress from the environment (see WHAT_TO_REFACTOR.md).

Both are provider-agnostic DTOs the ENVIRONMENT produces (MHBench today via
environment/deployer.py; other env plugins later).
"""
from __future__ import annotations

import os
import shlex
from typing import Optional

from pydantic import BaseModel, Field


class AttackerFoothold(BaseModel):
    """Adversary-safe identity of a box the attacker starts on / operates from."""
    name: str = "foothold"
    host: Optional[str] = None   # the box's own in-env IP (the adversary knows its own address)
    user: str = "root"


class AttackerEnvSpec(BaseModel):
    """Adversary-safe. objective + foothold identities only."""
    objective: str = "none"
    footholds: list[AttackerFoothold] = Field(default_factory=list)

    @property
    def primary(self) -> Optional[AttackerFoothold]:
        return self.footholds[0] if self.footholds else None


class SetupAccess(BaseModel):
    """Harness-only: how the trusted plugin reaches one foothold to prep it. Never given to the
    adversary. Routing (bastion/relay/direct/IAP) is opaque in ssh_common_args and owned by the
    environment; ssh_key should be scoped to user@host."""
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
