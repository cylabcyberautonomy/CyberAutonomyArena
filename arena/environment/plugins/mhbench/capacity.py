"""MHBench topology sizing — turn a topology JSON into per-VM (vcpus, ram_mb, disk_gb) specs."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_flavor_cache: dict[str, tuple[int, int, int]] = {}


async def _get_flavor_specs(flavor: str) -> tuple[int, int, int]:
    if flavor in _flavor_cache:
        return _flavor_cache[flavor]
    try:
        proc = await asyncio.create_subprocess_exec(
            "openstack", "flavor", "show", flavor, "-f", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        data = json.loads(stdout.decode())
        result = (int(data["vcpus"]), int(data["ram"]), int(data["disk"]))
    except Exception:
        logger.debug("flavor specs for %r unavailable (no OpenStack); using placeholder", flavor)
        result = (2, 4096, 20)
    _flavor_cache[flavor] = result
    return result


def _read_mgmt_flavor(mhbench_dir: Path) -> str:
    config_path = mhbench_dir / "config" / "config.yaml"
    cfg = yaml.safe_load(config_path.read_text())
    return cfg["management"]["flavor"]


async def count_vm_specs(topology_path: Path, mhbench_dir: Path,
                         flavor_cpu_cost: dict[str, int] | None = None) -> list[tuple[int, int, int]]:
    """Return (vcpus, ram_mb, disk_gb) for each VM in the topology, including the management host."""
    topology = json.loads(topology_path.read_text())
    flavors: list[str] = [_read_mgmt_flavor(mhbench_dir)]
    for network in topology.get("networks", []):
        for subnet in network.get("subnets", []):
            for host in subnet.get("hosts", []):
                flavor = host.get("flavor")
                if flavor:
                    flavors.append(flavor)

    specs = list(await asyncio.gather(*[_get_flavor_specs(f) for f in flavors]))
    if flavor_cpu_cost:
        specs = [
            (int(flavor_cpu_cost.get(flavor, vcpus)), ram, disk)
            for flavor, (vcpus, ram, disk) in zip(flavors, specs)
        ]
    return specs
