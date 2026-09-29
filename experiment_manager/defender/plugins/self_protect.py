"""Defender self-protection: never let a response block the defender's OWN infrastructure.

A whole-IP block (e.g. FalcoLLMC2Block) could otherwise sever the defender's own telemetry if the
attacker's C2 happens to share the defender's ES/management IP (the legacy shared-IP testbed setup).
This is a DEFENDER-LOCAL invariant: it needs no knowledge of where the attacker's C2 is (that would
be adversary info) — the defender simply refuses to block IPs it knows are its own. So it holds
regardless of the attacker's C2 placement, which is why it replaces the old MHB_C2_ON_KALI gate that
coupled the defender to an attacker config flag.

Kept dependency-free (no openstack/elasticsearch/Perry imports) so it is unit-testable on its own.
"""
from __future__ import annotations

from typing import Callable, Iterable, Optional


class SelfProtectingOrchestrator:
    """Wraps a Perry orchestrator and drops any BlockIP aimed at a protected (own-infra) IP.
    Everything else passes straight through to the wrapped orchestrator."""

    def __init__(self, inner, protected_ips: Iterable[str], on_skip: Optional[Callable[[str], None]] = None):
        self._inner = inner
        self._protected = {ip for ip in protected_ips if ip}
        self._on_skip = on_skip

    @property
    def protected_ips(self) -> set:
        return set(self._protected)

    def run(self, actions):
        safe = []
        for a in actions:
            ip = getattr(a, "ip_to_block", None)
            if ip is not None and ip in self._protected:
                if self._on_skip is not None:
                    self._on_skip(ip)
                continue
            safe.append(a)
        return self._inner.run(safe) if safe else None

    def __getattr__(self, name):
        # Delegate everything else (deploy_decoy, restore, etc.) to the real orchestrator.
        return getattr(self._inner, name)
