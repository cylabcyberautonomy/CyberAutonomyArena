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
