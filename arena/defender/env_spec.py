"""Defender-facing environment types — mirrors attacker/env_spec.py.

Two deliberately separate objects:

  DefenderEnvSpec — the RUN SPEC: the runtime information the defender acts on. It carries the
                    objective and the host inventory at the defender's knowledge level (name/ip/role —
                    a real org knows its own estate), plus the defender's own box. NO credentials, NO
                    routing — the defender's brain doesn't need them at runtime. This is what
                    build_config() consumes and what conceptually "the defender gets".

  SetupAccess    — the SETUP ACCESS (the SAME shared type the attacker uses, from attacker/env_spec.py):
                    how the trusted defender *plugin* reaches a host to set itself up / install
                    bespoke sensors (ssh key + routing). Produced by the environment and used at setup
                    time by the plugin. It carries the key because that's what SETUP needs — the split
                    is setup vs runtime, not a secret the defender must never see.

They're separate because they're used at different times, not because the run spec is secret: it carries
nothing that would matter if it leaked anyway (see docs/security-model.md).

Both are provider-agnostic DTOs the environment produces (MHBench via environment/deployer.py).
DefenderEnvSpec also carries `topology_spec` (a path); the defender runners build Perry's network
from the MHBench JSON at that path.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DefenderHost(BaseModel):
    """Identity of a host in the defended estate, at the defender's knowledge level (part of the run spec)."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None   # e.g. "webserver", "database" (derived from the host name)


class DefenderBox(BaseModel):
    """The always-provisioned box the defender RUNS on, in an isolated ("super-secret") subnet: it can
    reach the victims + the telemetry relay but is hidden from the attacker. Part of the run spec (the
    defender knows its own box); the harness reaches it at setup time via a SetupAccess entry of the same name.

    REQUIREMENT (design, not a self-reported field): the environment MUST give this box internet EGRESS
    (outbound-only, for the LLM API) and NO ingress from the internet. See docs/security-model.md
    (management-plane isolation); the arena may verify it at runtime later (not a flag a plugin can set)."""
    name: str = "defender_box"
    ip: Optional[str] = None       # the box's in-env address
    subnet: Optional[str] = None   # the isolated subnet it lives on


class DefenderEnvSpec(BaseModel):
    """The run spec: objective + host inventory + the defender's own box; no creds/routing."""
    objective: str = "none"
    hosts: list[DefenderHost] = Field(default_factory=list)
    box: Optional[DefenderBox] = None    # the always-provisioned defender box (env guarantees one)
    topology_spec: Optional[str] = None  # path the defender runners read to build Perry's network
