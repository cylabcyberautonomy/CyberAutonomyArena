"""Traffic-facing environment types — mirrors attacker/env_spec.py and defender/env_spec.py.

Two deliberately separate objects (same split as the other systems):

  TrafficEnvSpec — the RUN SPEC: the runtime information the traffic system acts on. It carries the
                   profile/objective of the benign activity and the inventory of VICTIM hosts the
                   generator should run its personas on (name/ip/user — the hosts a defender is scored
                   on, which is exactly where benign noise belongs). NO credentials, NO routing — the
                   generator's config doesn't need them at runtime. This is what build_config() consumes.

  SetupAccess   — the SETUP ACCESS (the SAME shared type the attacker/defender use, from
                  attacker/env_spec.py): how the trusted traffic *plugin*/runner reaches each victim to
                  install and start the generator (scoped key + bastion routing). Produced by the
                  environment, used at setup/run time; it carries the key because that is what setup needs.

Both are provider-agnostic DTOs the ENVIRONMENT produces (MHBench via environment/plugins/mhbench/
deployer.py). The traffic plugin never parses a backend topology or reads a management key — it consumes
these, exactly like the migrated attacker/defender do.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class TrafficHost(BaseModel):
    """A victim host the traffic generator runs a persona on (part of the run spec).

    The traffic system runs benign user activity ON the defended estate — the same victim inventory the
    defender is scored over (NOT the attacker foothold, NOT the defender's own box). `user` is the login
    account the generator runs as on that host."""
    name: str
    ip: Optional[str] = None
    user: str = "root"
    role: Optional[str] = None   # e.g. "webserver"/"database" (derived from the host name; lets a persona vary by role)


class TrafficEnvSpec(BaseModel):
    """The run spec: the benign-activity objective/profile + the victim inventory to generate it on; no
    creds/routing. Self-describing, so a traffic plugin reads its targets from here instead of parsing a
    backend topology."""
    objective: str = "none"
    hosts: list[TrafficHost] = Field(default_factory=list)
