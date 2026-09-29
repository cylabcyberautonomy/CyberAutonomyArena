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


class DefenderBox(BaseModel):
    """The always-provisioned box the defender RUNS on, in an isolated ("super-secret") subnet: it can
    reach the victims + the telemetry relay but is hidden from the attacker. Agent-facing identity only
    (the defender knows its own box); the harness reaches it via a SetupAccess entry of the same name.

    REQUIREMENT (design, not a self-reported field): the environment MUST give this box internet EGRESS
    (outbound-only, for the LLM API) and NO ingress from the internet. Tracked in
    ARENA_PLUGIN_REQUIREMENTS.md; the arena may verify it at runtime later (not a flag a plugin can set)."""
    name: str = "defender_box"
    ip: Optional[str] = None       # the box's in-env address
    subnet: Optional[str] = None   # the isolated subnet it lives on


class DefenderEnvSpec(BaseModel):
    """Agent-facing. objective + host inventory + the defender's own box; no creds/routing."""
    objective: str = "none"
    hosts: list[DefenderHost] = Field(default_factory=list)
    box: Optional[DefenderBox] = None    # the always-provisioned defender box (env guarantees one)
    topology_spec: Optional[str] = None  # Stage-2a back-compat: path the existing runners still read
