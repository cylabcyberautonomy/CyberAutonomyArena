from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_flavor_cache: dict[str, tuple[int, int, int]] = {}

# Keep this much cluster disk free at all times. Nova schedules per-node, so packing aggregate disk to ~100%
# leaves each node too full to fit the next VM even when aggregate looks fine → "No valid host". This buffer
# (~1+ star_pe copy) keeps per-node headroom.
_DISK_HEADROOM_GB = 800


async def _get_flavor_specs(flavor: str) -> tuple[int, int, int]:
    if flavor in _flavor_cache:
        return _flavor_cache[flavor]
    proc = await asyncio.create_subprocess_exec(
        "openstack", "flavor", "show", flavor, "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    # disk (GB) is the one that matters most: nova reserves the full flavor disk, and an env with many small
    # hosts (each e.g. 20GB) exhausts cluster disk long before vCPU/RAM — that's what caused "No valid host".
    result = (int(data["vcpus"]), int(data["ram"]), int(data["disk"]))
    _flavor_cache[flavor] = result
    return result


def _read_mgmt_flavor(mhbench_dir: Path) -> str:
    config_path = mhbench_dir / "config" / "config.yaml"
    cfg = yaml.safe_load(config_path.read_text())
    return cfg["management"]["flavor"]


async def count_vm_specs(topology_path: Path, mhbench_dir: Path) -> list[tuple[int, int, int]]:
    """Return (vcpus, ram_mb, disk_gb) for each VM in the topology, including the management host."""
    topology = json.loads(topology_path.read_text())
    flavors: list[str] = [_read_mgmt_flavor(mhbench_dir)]
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                flavor = host.get("flavor")
                if flavor:
                    flavors.append(flavor)

    specs = await asyncio.gather(*[_get_flavor_specs(f) for f in flavors])
    return list(specs)


async def _query_cluster_capacity() -> tuple[int, int, int]:
    """Return (free_vcpus, free_ram_mb, free_disk_gb) for the whole cluster."""
    proc = await asyncio.create_subprocess_exec(
        "openstack", "hypervisor", "stats", "show", "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    free_vcpus = int(data["vcpus"]) - int(data["vcpus_used"])
    free_ram_mb = int(data["free_ram_mb"])
    free_disk_gb = int(data["local_gb"]) - int(data["local_gb_used"])
    return free_vcpus, free_ram_mb, free_disk_gb


class CapacityTracker:
    """Tracks cluster-wide free vCPUs and RAM.

    Checks aggregate capacity before allowing deployment to proceed.
    Re-queries OpenStack after each teardown to stay in sync with actual state.
    """

    def __init__(self) -> None:
        self._free_vcpus: int = 0
        self._free_ram_mb: int = 0
        self._free_disk_gb: int = 0
        self._condition = asyncio.Condition()

    async def initialize(self) -> None:
        self._free_vcpus, self._free_ram_mb, self._free_disk_gb = await _query_cluster_capacity()
        logger.info(
            "Cluster capacity at startup: %d vCPUs / %d MB RAM / %d GB disk free",
            self._free_vcpus, self._free_ram_mb, self._free_disk_gb,
        )

    async def reserve(self, vm_specs: list[tuple[int, int, int]], experiment_name: str) -> tuple[int, int]:
        """Block until the cluster has enough aggregate vCPU, RAM AND disk (disk is usually the binding one
        for host-heavy envs — nova reserves each flavor's full disk). Returns (total_vcpus, total_ram_mb)."""
        total_vcpus = sum(v for v, _, _ in vm_specs)
        total_ram = sum(r for _, r, _ in vm_specs)
        total_disk = sum(dk for _, _, dk in vm_specs)
        async with self._condition:
            while True:
                if (self._free_vcpus >= total_vcpus and self._free_ram_mb >= total_ram
                        and self._free_disk_gb - total_disk >= _DISK_HEADROOM_GB):
                    self._free_vcpus -= total_vcpus
                    self._free_ram_mb -= total_ram
                    self._free_disk_gb -= total_disk
                    logger.info(
                        "[%s] Capacity reserved: %d vCPUs / %d MB RAM / %d GB disk across %d VMs",
                        experiment_name, total_vcpus, total_ram, total_disk, len(vm_specs),
                    )
                    return total_vcpus, total_ram
                logger.info(
                    "[%s] Waiting for capacity: need %d vCPU / %d MB / %d GB disk; free %d / %d / %d",
                    experiment_name, total_vcpus, total_ram, total_disk,
                    self._free_vcpus, self._free_ram_mb, self._free_disk_gb,
                )
                await self._condition.wait()

    def release(self, experiment_name: str) -> None:
        """Re-query actual cluster capacity from OpenStack and wake waiting experiments."""
        async def _release() -> None:
            async with self._condition:
                self._free_vcpus, self._free_ram_mb, self._free_disk_gb = await _query_cluster_capacity()
                logger.info(
                    "[%s] Capacity released; cluster now: %d vCPUs / %d MB RAM / %d GB disk free",
                    experiment_name, self._free_vcpus, self._free_ram_mb, self._free_disk_gb,
                )
                self._condition.notify_all()

        asyncio.ensure_future(_release())
