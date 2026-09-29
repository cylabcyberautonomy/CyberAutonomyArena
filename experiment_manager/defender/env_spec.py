"""Defender-facing environment types — symmetric with attacker/env_spec.py.

  DefenderEnvSpec — AGENT-FACING. What the defender's brain legitimately knows about the estate it
                    defends: the objective/scenario and the hosts at its knowledge level
                    ({name, ip, role} — a real org knows its own inventory). NO credentials, NO
                    routing. (Later stages add the common-telemetry source channels + the defender
                    box's own identity.)

  SetupAccess    — HARNESS-ONLY (the SAME shared type the attacker uses, from attacker/env_spec.py):
                    how the trusted defender *plugin* reaches a host to set itself up / install
                    bespoke sensors (ssh key + routing). Produced by the environment, never given to
                    the defender's brain.

Both are provider-agnostic DTOs the ENVIRONMENT produces (MHBench today via environment/deployer.py).
Stage 2a: DefenderEnvSpec also carries `topology_spec` (a path) so the existing defender runners,
which build Perry's network from the MHBench JSON, keep working until they are migrated.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DefenderHost(BaseModel):
    """A host in the defended estate, at the defender's knowledge level."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None   # e.g. "webserver", "database" (derived from the host name)


class DefenderEnvSpec(BaseModel):
    """Agent-facing. objective + host inventory; no creds/routing."""
    objective: str = "none"
    hosts: list[DefenderHost] = Field(default_factory=list)
    topology_spec: Optional[str] = None  # Stage-2a back-compat: path the existing runners still read
