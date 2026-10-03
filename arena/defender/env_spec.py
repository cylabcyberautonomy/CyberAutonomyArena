"""Defender-facing environment types — mirrors attacker/env_spec.py.

Two deliberately separate objects:

  DefenderEnvSpec — the RUN SPEC: the runtime information the defender acts on. It carries the
                    objective and the host inventory at the defender's knowledge level (name/ip/role —
                    a real org knows its own estate), the subnet structure (so a decoy defender can place
                    a decoy without parsing a backend topology), and the defender's own box. NO
                    credentials, NO routing — the defender's brain doesn't need them at runtime. This is
                    what build_config() consumes and what conceptually "the defender gets".

  SetupAccess    — the SETUP ACCESS (the SAME shared type the attacker uses, from attacker/env_spec.py):
                    how the trusted defender *plugin* reaches a host to set itself up / install
                    bespoke sensors (ssh key + routing). Produced by the environment and used at setup
                    time by the plugin. It carries the key because that's what SETUP needs — the split
                    is setup vs runtime, not a secret the defender must never see.

They're separate because they're used at different times, not because the run spec is secret: it carries
nothing that would matter if it leaked anyway (see docs/security-model.md).

Both are provider-agnostic DTOs the environment produces (MHBench via environment/deployer.py). The spec
is fully self-describing: the ENVIRONMENT resolves the backend network / security-group NAMES into
`subnets` so the defender never parses a backend topology (the old topology.py shim is gone). A decoy
defender builds Perry's Network straight from `subnets` (see defender/plugins/perry_network.py).
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class DefenderHost(BaseModel):
    """Identity of a host in the defended estate, at the defender's knowledge level (part of the run spec)."""
    name: str
    ip: Optional[str] = None
    role: Optional[str] = None   # e.g. "webserver", "database" (derived from the host name)
    users: list[str] = Field(default_factory=list)  # login accounts the host has (honey-cred placement)
    telemetry: bool = False      # the env ships this host's sysflow/falco to the defender box


class DefenderSubnet(BaseModel):
    """A subnet of the defended estate as the ENVIRONMENT exposes it (part of the run spec).

    Backend-neutral to the defender: the environment has already resolved the cloud network /
    security-group NAMES (e.g. MHBench's "<project>-<subnet>" / "<project>-<subnet>_sg"), so a decoy
    defender places a decoy by naming `network`/`sec_group` without knowing the backend convention.
    The `attacker`/`entry` flags let a strategy avoid the red team's own segment and put honey
    credentials on the attacker's path, in any topology, without matching hardcoded subnet names."""
    name: str                            # logical subnet name (e.g. "webserver_subnet")
    network: Optional[str] = None        # backend network to attach a new host to (env-resolved)
    sec_group: Optional[str] = None      # the subnet's security group (env-resolved)
    hosts: list[DefenderHost] = Field(default_factory=list)
    attacker: bool = False               # the red team's own segment (never place a decoy here)
    entry: bool = False                  # adjacent to the attacker subnet (honey-cred on the path)


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
    """The run spec: objective + host inventory + subnet structure + the defender's own box; no creds/routing."""
    objective: str = "none"
    hosts: list[DefenderHost] = Field(default_factory=list)   # flat victim inventory (no attacker/box)
    subnets: list[DefenderSubnet] = Field(default_factory=list)  # full structure incl. the attacker segment
    network_name: Optional[str] = None   # the backend network name (Perry Network.name)
    management_sg: Optional[str] = None   # the shared management security group (env-resolved)
    box: Optional[DefenderBox] = None    # the always-provisioned defender box (env guarantees one)
