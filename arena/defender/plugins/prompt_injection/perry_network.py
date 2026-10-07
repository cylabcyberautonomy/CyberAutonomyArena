"""DefenderEnvSpec -> Perry-network translation for the prompt_injection decoy defender runner."""
from __future__ import annotations

from typing import Optional


def build_network_from_spec(spec: Optional[dict]):
    """Build Perry's Network + the list of telemetry-host IPs from a DefenderEnvSpec dict."""
    from environment.network import Network, Subnet, Host

    if not spec or not spec.get("subnets"):
        return None, []

    subnets = []
    telemetry_hosts: list[str] = []
    for sd in spec["subnets"]:
        hosts = []
        for h in sd.get("hosts", []):
            users = [u["name"] if isinstance(u, dict) else u for u in (h.get("users") or [])]
            hosts.append(Host(name=h["name"], ip=h.get("ip"), users=users))
            if h.get("telemetry") and h.get("ip"):
                telemetry_hosts.append(h["ip"])
        subnets.append(Subnet(
            name=sd.get("network") or sd["name"],
            hosts=hosts,
            sec_group=sd.get("sec_group"),
            entry=bool(sd.get("perimeter")),
        ))
    network = Network(
        name=spec.get("network_name") or "network",
        subnets=subnets,
        management_sg=spec.get("management_sg"),
    )
    return network, telemetry_hosts
