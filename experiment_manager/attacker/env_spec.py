"""AttackerEnvSpec — the attacker-facing view of a deployed environment.

This is the "attacker environment spec" the arena diagram feeds into the attacker system: ONLY
the entry point + objective an attacker legitimately gets, never the full topology. The attacker
plugins consume this instead of the raw MHBench `DeployedEnvironment` (topology JSON path, env
name), which is how they were coupled to MHBench.

Stage A (now): the current MHBench path fills this via `from_deployed()` — a thin adapter over
`DeployedEnvironment`. Stage B: once the environment is a real plugin it emits `AttackerEnvSpec`
directly and the adapter goes away. Either way the attacker only ever sees this object.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from ..environment import DeployedEnvironment


class AttackerEnvSpec(BaseModel):
    # What the strategy/LLM keys off (Incalmo's "environment" field). Was DeployedEnvironment.spec.
    objective: str = "none"
    # The in-environment attacker (Kali) box's internal IP — the attacker's entry point.
    # Was DeployedEnvironment.ip. CAI ships this to the runner as kali_ip.
    entry_ip: Optional[str] = None
    # How the attacker reaches its box to prepare it (Stage A fills these for the self-prep work
    # in the next stage; build_config today only needs objective + entry_ip).
    bastion_ip: Optional[str] = None
    ssh_key: Optional[str] = None
    entry_user: str = "root"

    @classmethod
    def from_deployed(
        cls,
        environment: Optional[DeployedEnvironment],
        *,
        bastion_ip: Optional[str] = None,
        ssh_key: Optional[str] = None,
        entry_user: str = "root",
    ) -> "AttackerEnvSpec":
        """Adapter: build the attacker-facing spec from MHBench's DeployedEnvironment."""
        if environment is None:
            return cls(bastion_ip=bastion_ip, ssh_key=ssh_key, entry_user=entry_user)
        return cls(
            objective=environment.spec or "none",
            entry_ip=str(environment.ip) if environment.ip else None,
            bastion_ip=bastion_ip,
            ssh_key=ssh_key,
            entry_user=entry_user,
        )
