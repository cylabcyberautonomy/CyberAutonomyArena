from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_flavor_cache: dict[str, tuple[int, int]] = {}


async def _get_flavor_vcpus_ram(flavor: str) -> tuple[int, int]:
    if flavor in _flavor_cache:
        return _flavor_cache[flavor]
    proc = await asyncio.create_subprocess_exec(
        "openstack", "flavor", "show", flavor, "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    result = (int(data["vcpus"]), int(data["ram"]))
    _flavor_cache[flavor] = result
    return result


def _read_mgmt_flavor(mhbench_dir: Path) -> str:
    config_path = mhbench_dir / "config" / "config.yaml"
    cfg = yaml.safe_load(config_path.read_text())
    return cfg["management"]["flavor"]


async def count_vm_specs(topology_path: Path, mhbench_dir: Path) -> list[tuple[int, int]]:
    """Return (vcpus, ram_mb) for each VM in the topology, including the management host."""
    topology = json.loads(topology_path.read_text())
    flavors: list[str] = [_read_mgmt_flavor(mhbench_dir)]
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                flavor = host.get("flavor")
                if flavor:
                    flavors.append(flavor)

    specs = await asyncio.gather(*[_get_flavor_vcpus_ram(f) for f in flavors])
    return list(specs)


@dataclass
class _HypervisorState:
    name: str
    free_vcpus: int
    free_ram_mb: int


async def _query_hypervisor_states() -> list[_HypervisorState]:
    proc = await asyncio.create_subprocess_exec(
        "openstack", "hypervisor", "list", "--long", "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    result = []
    for h in json.loads(stdout.decode()):
        if h.get("State") == "up" and h.get("Status") == "enabled":
            result.append(_HypervisorState(
                name=h["Hypervisor Hostname"],
                free_vcpus=int(h["vCPUs"]) - int(h["vCPUs Used"]),
                free_ram_mb=int(h["Memory MB"]) - int(h["Memory MB Used"]),
            ))
    return result


def _simulate_placement(
    hypervisors: list[_HypervisorState],
    vm_specs: list[tuple[int, int]],
) -> list[int] | None:
    """
    Greedy placement mirroring Nova's RAM weigher: each VM goes to the host
    with the most free RAM that can fit it. Returns per-VM hypervisor indices,
    or None if any VM cannot be placed.
    """
    free = [(h.free_vcpus, h.free_ram_mb) for h in hypervisors]
    assignment: list[int] = []
    for vcpus, ram in vm_specs:
        best = max(
            ((i, fv, fr) for i, (fv, fr) in enumerate(free) if fv >= vcpus and fr >= ram),
            key=lambda x: x[2],
            default=None,
        )
        if best is None:
            return None
        i, fv, fr = best
        free[i] = (fv - vcpus, fr - ram)
        assignment.append(i)
    return assignment


class CapacityTracker:
    """Tracks per-hypervisor cluster capacity.

    Simulates Nova's greedy RAM-weigher placement to decide whether an
    experiment's VMs can be scheduled before allowing deployment to proceed.
    Re-queries OpenStack after each teardown to stay in sync with actual state.
    """

    def __init__(self) -> None:
        self._hypervisors: list[_HypervisorState] = []
        self._condition = asyncio.Condition()

    async def initialize(self) -> None:
        self._hypervisors = await _query_hypervisor_states()
        logger.info(
            "Cluster capacity at startup: %d hypervisors, %d vCPUs / %d MB RAM free",
            len(self._hypervisors),
            sum(h.free_vcpus for h in self._hypervisors),
            sum(h.free_ram_mb for h in self._hypervisors),
        )

    async def reserve(self, vm_specs: list[tuple[int, int]], experiment_name: str) -> tuple[int, int]:
        """Block until all VMs can be placed; return (total_vcpus, total_ram_mb) reserved."""
        total_vcpus = sum(v for v, _ in vm_specs)
        total_ram = sum(r for _, r in vm_specs)
        async with self._condition:
            while True:
                assignment = _simulate_placement(self._hypervisors, vm_specs)
                if assignment is not None:
                    for idx, (vcpus, ram) in zip(assignment, vm_specs):
                        self._hypervisors[idx].free_vcpus -= vcpus
                        self._hypervisors[idx].free_ram_mb -= ram
                    logger.info(
                        "[%s] Capacity reserved: %d vCPUs / %d MB RAM across %d VMs",
                        experiment_name, total_vcpus, total_ram, len(vm_specs),
                    )
                    return total_vcpus, total_ram
                logger.info(
                    "[%s] Waiting for capacity: need to place %d VMs (%d vCPUs / %d MB RAM total)",
                    experiment_name, len(vm_specs), total_vcpus, total_ram,
                )
                await self._condition.wait()

    def release(self, experiment_name: str) -> None:
        """Re-query actual hypervisor state from OpenStack and wake waiting experiments."""
        async def _release() -> None:
            async with self._condition:
                self._hypervisors = await _query_hypervisor_states()
                logger.info(
                    "[%s] Capacity released; cluster now: %d vCPUs / %d MB RAM free",
                    experiment_name,
                    sum(h.free_vcpus for h in self._hypervisors),
                    sum(h.free_ram_mb for h in self._hypervisors),
                )
                self._condition.notify_all()

        asyncio.ensure_future(_release())
