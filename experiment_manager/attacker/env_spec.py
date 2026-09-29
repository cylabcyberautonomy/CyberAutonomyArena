"""AttackerEnvSpec — the attacker-facing view of a deployed environment.

A pure, provider-agnostic DTO: only the entry point + objective + box access an attacker
legitimately gets, never the full topology. The ENVIRONMENT produces it (MHBench today, other
env plugins later) and hands it to the arena, which passes it to the attacker — the attacker never
parses raw environment internals.

Consumed by the trusted attacker *plugin* (harness setup code), NOT by the adversary under
evaluation (the strategy/LLM only ever gets the C2 + the landed foothold). Still, credentials are
scoped on purpose: `entry_ssh_key` should authenticate ONLY to `entry_user@entry_ip`, and if the
box is only reachable through a jump, `jump` carries its own (ideally forward-only) credential —
never one management key that opens the bastion, the box and every victim. MHBench currently uses
one shared root key for both hops (over-privileged); the split here lets scoped keys drop in later
without changing this contract.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class AttackerJump(BaseModel):
    """How to route to the box when it isn't directly reachable (e.g. a bastion). Its credential
    should be scoped to forwarding only — not a key that grants a shell on the jump host."""
    host: str
    user: str = "root"
    ssh_key: Optional[str] = None
    port: int = 22


class AttackerEnvSpec(BaseModel):
    # Env label / goal context the strategy or LLM keys off (Incalmo's "environment" field).
    objective: str = "none"
    # The attacker's foothold box (its entry point).
    entry_ip: Optional[str] = None
    entry_port: int = 22
    entry_user: str = "root"
    # Key valid ONLY for entry_user@entry_ip. Never a management/global key.
    entry_ssh_key: Optional[str] = None
    # Present only when the box must be reached through a jump; the environment owns routing.
    jump: Optional[AttackerJump] = None
