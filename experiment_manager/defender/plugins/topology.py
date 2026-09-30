"""Shared MHBench-topology -> Perry-network translation for the defender runners.

Each defender plugin (deception / llm_soc / prompt_injection) spawns its own standalone runner
script; all three import this one translation so decoy placement, host user lists, the Neutron
network-name prefix, and the attacker-subnet flag stay consistent across plugins.

Perry's Network/Subnet/Host are plain classes (not pydantic models), so they're built by hand from
MHBench's topology JSON.
"""
from __future__ import annotations

# NOTE: `environment.network` is imported lazily inside build_network(), not at
# module scope. This module lives in the plugins package, whose __init__.py
# imports every module it finds so the DefenderPlugin subclasses self-register -
# so the experiment manager imports this file at startup. But `environment` is
# a Defense-MHBench-compatible package that only exists on the *runner*
# subprocess's sys.path (deception_dir), never the manager's, so a module-scope
# import here crashed the whole manager on boot with
# "ModuleNotFoundError: No module named 'environment'".


def host_users(vm_type: str) -> list[str]:
    """Login accounts a host of this MHBench vm_type actually has.

    Perry's Host defaults to an empty user list and MHBench's topology JSON
    doesn't carry accounts, so hosts would otherwise be built with `users == []`.
    AddHoneyCredentials plants its credential trail by iterating
    `credential_host.users` (an ssh key in that user's ~/.ssh plus a matching
    ~/.ssh/config entry pointing at the decoy) - over an empty list that loop
    does nothing, so decoys got their honey accounts but nothing in the
    environment ever pointed at them. Names come from what MHBench bakes:
    ubuntu on every cloud image, plus tomcat on webservers (created by
    setup_struts.yml, and the account a Struts RCE lands in - see
    equifax_small_instrumented.json's own setup_ssh_keys play, which uses
    exactly tomcat on webserver0 and ubuntu on the databases). The attacker box
    deliberately gets none: planting credentials there hands them to the
    attacker rather than baiting a lateral move."""
    if vm_type.startswith("kali"):
        return []
    if vm_type.startswith("webserver"):
        return ["ubuntu", "tomcat"]
    return ["ubuntu"]


def build_network(network_data: dict, experiment_name: str, subnet_connections=None):
    """Build Perry's Network from MHBench's topology JSON for one experiment.

    subnet_connections (the topology's top-level list) lets the entry segment be
    identified - the subnet directly connected to the attacker's own - so
    deception can place a honey credential on the attacker's path in any topology,
    not just ones with a "webserver" subnet.
    """
    from environment.network import Network, Subnet, Host

    # The attacker's first hop: subnets adjacent to the attacker subnet. Raw
    # (un-prefixed) names, since subnet_connections uses them.
    attacker_raw = next(
        (sd["name"] for sd in network_data["subnets"]
         if any(h.get("vm_type", "").startswith("kali") for h in sd["hosts"])),
        None,
    )
    entry_raw = set()
    for conn in (subnet_connections or []):
        endpoints = {conn.get("from_subnet"), conn.get("to_subnet")}
        if attacker_raw in endpoints:
            entry_raw |= endpoints - {attacker_raw, None}

    subnets = [
        Subnet(
            # Must match the real Neutron network name MHBench provisions
            # ("<experiment_name>-<subnet_name>", see NetworkDeployer._n in
            # MHBench's src/deployment/network_deployer.py) - DeployDecoy looks
            # up this exact name via find_network() to attach decoy hosts.
            name=f"{experiment_name}-{subnet_data['name']}",
            hosts=[
                Host(
                    name=h["name"],
                    ip=h["ip_address"],
                    users=host_users(h.get("vm_type", "")),
                )
                for h in subnet_data["hosts"]
            ],
            # `sec_group` isn't in the topology JSON (it's assigned at deploy
            # time); MHBench names it "<experiment_name>-<subnet_name>_sg" (see
            # NetworkTopology.sg_name / NetworkDeployer._n).
            sec_group=f"{experiment_name}-{subnet_data['name']}_sg",
            # The red team's own segment. Flagged so Network.get_random_subnet()
            # never places a decoy next to the attacker (identified by vm_type,
            # not by a hardcoded CIDR the way RestoreServer does it).
            attacker=any(
                h.get("vm_type", "").startswith("kali") for h in subnet_data["hosts"]
            ),
            # The attacker's entry segment (adjacent to its own subnet). Lets
            # deception place a honey credential on the path in any topology.
            entry=subnet_data["name"] in entry_raw,
        )
        for subnet_data in network_data["subnets"]
    ]
    return Network(
        name=network_data["name"],
        subnets=subnets,
        # Every host MHBench deploys gets this security group for bastion
        # reachability (see host_deployer.py / network_deployer.py's
        # self._n("management_sg")).
        management_sg=f"{experiment_name}-management_sg",
    )


def defendable_host_ips(network_data: dict) -> list[str]:
    """IPs of every host the defender legitimately owns - i.e. everything except
    the red team's own machines.

    Deliberately NOT telemetry_host_ips(): that filters on the "*_instrumented"
    vm_types, which is right for *reconfiguring* an agent MHBench already baked
    in, but wrong for *installing* one. On a non-instrumented topology every
    real host is "*_running" and would be filtered out, leaving the defender
    installing Falco on nothing at all.

    The exclusion matters beyond tidiness: the attacker box is not part of the
    defended network, so a defender could never have an agent on it. Installing
    one hands the defense information it has no right to, and in practice
    drowns out everything else - measured on one run, kali produced 75 Falco
    alerts to webserver1's 13, and being the noisiest host it was the first and
    only one to approach the suspicion threshold. It is also the single most
    expensive host to install on (the only one with no baked Falco, so the only
    one that needs the full apt path, which is where the lock races happen).

    Same rule build_network() uses for its attacker-subnet flag, rather than a
    second, subtly different definition of "the attacker".
    """
    return [
        h["ip_address"]
        for subnet_data in network_data["subnets"]
        for h in subnet_data["hosts"]
        if not h.get("vm_type", "").startswith("kali")
    ]


def telemetry_host_ips(network_data: dict) -> list[str]:
    """IPs of hosts that actually run sysflow.

    MHBench's online registry attaches the start_sysflow /
    start_defender_services playbooks to exactly the "*_instrumented" vm_types
    (see MHBench/src/registry/online_registry.yaml). The Kali attacker
    (kali_running) has no telemetry stack at all, so it's excluded -
    reconfiguring it would just fail the playbook."""
    return [
        h["ip_address"]
        for subnet_data in network_data["subnets"]
        for h in subnet_data["hosts"]
        if h.get("vm_type", "").endswith("_instrumented")
    ]
