from __future__ import annotations

import asyncio
import json
import logging
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


async def _query_cluster_capacity() -> tuple[int, int]:
    """Return (free_vcpus, free_ram_mb) for the whole cluster."""
    proc = await asyncio.create_subprocess_exec(
        "openstack", "hypervisor", "stats", "show", "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    free_vcpus = int(data["vcpus"]) - int(data["vcpus_used"])
    free_ram_mb = int(data["free_ram_mb"])
    return free_vcpus, free_ram_mb


class CapacityTracker:
    """Tracks cluster-wide free vCPUs and RAM.

    Checks aggregate capacity before allowing deployment to proceed.
    Re-queries OpenStack after each teardown to stay in sync with actual state.
    """

    def __init__(self) -> None:
        self._free_vcpus: int = 0
        self._free_ram_mb: int = 0
        self._condition = asyncio.Condition()

    async def initialize(self) -> None:
        self._free_vcpus, self._free_ram_mb = await _query_cluster_capacity()
        logger.info(
            "Cluster capacity at startup: %d vCPUs / %d MB RAM free",
            self._free_vcpus, self._free_ram_mb,
        )

    async def reserve(self, vm_specs: list[tuple[int, int]], experiment_name: str) -> tuple[int, int]:
        """Block until the cluster has enough aggregate capacity; return (total_vcpus, total_ram_mb) reserved."""
        total_vcpus = sum(v for v, _ in vm_specs)
        total_ram = sum(r for _, r in vm_specs)
        async with self._condition:
            while True:
                if self._free_vcpus >= total_vcpus and self._free_ram_mb >= total_ram:
                    self._free_vcpus -= total_vcpus
                    self._free_ram_mb -= total_ram
                    logger.info(
                        "[%s] Capacity reserved: %d vCPUs / %d MB RAM across %d VMs",
                        experiment_name, total_vcpus, total_ram, len(vm_specs),
                    )
                    return total_vcpus, total_ram
                logger.info(
                    "[%s] Waiting for capacity: need %d vCPUs / %d MB RAM, cluster has %d vCPUs / %d MB RAM free",
                    experiment_name, total_vcpus, total_ram, self._free_vcpus, self._free_ram_mb,
                )
                await self._condition.wait()

    def release(self, experiment_name: str) -> None:
        """Re-query actual cluster capacity from OpenStack and wake waiting experiments."""
        async def _release() -> None:
            async with self._condition:
                self._free_vcpus, self._free_ram_mb = await _query_cluster_capacity()
                logger.info(
                    "[%s] Capacity released; cluster now: %d vCPUs / %d MB RAM free",
                    experiment_name, self._free_vcpus, self._free_ram_mb,
                )
                self._condition.notify_all()

        asyncio.ensure_future(_release())
