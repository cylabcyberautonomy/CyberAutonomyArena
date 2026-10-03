"""DefenderEnvSpec -> Perry-network translation for the decoy defender runners (deception,
prompt_injection).

Environment-agnostic by construction: it consumes the ENVIRONMENT-produced DefenderEnvSpec (the run
spec the arena injects into the runner config as `defender_env_spec`), never a backend topology. The
environment has already resolved the backend network / security-group NAMES into the spec's subnets, so
nothing here knows MHBench's (or any backend's) naming convention. This replaces the old topology.py
shim, which reached into MHBench's topology JSON directly and was the last env-coupling in the defender.

Shared by the two standalone runner SCRIPTS (deception, prompt_injection), which can't inherit a base —
so this is a module, per the plugin self-containment rule (CLAUDE.md: runner-script-shared code is a
module, everything else is per-plugin or on the base). llm_soc builds its own Network inline from the
same spec (its needs are simpler — host IPs + the defendable set), so it doesn't import this.

Perry's Network/Subnet/Host are plain classes (not pydantic models), so they're built by hand.
"""
from __future__ import annotations

from typing import Optional


def build_network_from_spec(spec: Optional[dict]):
    """Build Perry's Network + the list of telemetry-host IPs from a DefenderEnvSpec dict.

    Returns (network, telemetry_hosts). network is None when the spec carries no subnets (no environment
    was provisioned), mirroring the old "no topology -> no network" behaviour. telemetry_hosts are the
    IPs the environment flags as running sysflow/falco (env ships them to the box); a runner uses them
    only to log "box mode" — it never repoints sensors (the env relay owns shipping).

    `environment.network` is imported lazily (not at module scope): the plugins package imports every
    module it finds at manager startup so DefenderPlugin subclasses self-register, but `environment` only
    exists on the runner subprocess's sys.path (deception_dir), never the manager's — a module-scope
    import here would crash the manager on boot with ModuleNotFoundError."""
    from environment.network import Network, Subnet, Host

    if not spec or not spec.get("subnets"):
        return None, []

    subnets = []
    telemetry_hosts: list[str] = []
    for sd in spec["subnets"]:
        hosts = []
        for h in sd.get("hosts", []):
            hosts.append(Host(name=h["name"], ip=h.get("ip"), users=h.get("users") or []))
            if h.get("telemetry") and h.get("ip"):
                telemetry_hosts.append(h["ip"])
        subnets.append(Subnet(
            # The REAL backend network name the env resolved (DeployDecoy attaches a decoy to it by name);
            # fall back to the logical name if the env didn't resolve one.
            name=sd.get("network") or sd["name"],
            hosts=hosts,
            sec_group=sd.get("sec_group"),
            # Perry's `entry` = the subnet honey-creds are baited on. Map it from the env's `perimeter`
            # marker (the internet-facing/DMZ tier) — a legitimate estate property, NOT attacker adjacency.
            # `attacker` stays at its default False: the attacker's own segment isn't in the spec at all,
            # so get_random_subnet can never place a decoy there without needing a flag.
            entry=bool(sd.get("perimeter")),
        ))
    network = Network(
        name=spec.get("network_name") or "network",
        subnets=subnets,
        management_sg=spec.get("management_sg"),
    )
    return network, telemetry_hosts
