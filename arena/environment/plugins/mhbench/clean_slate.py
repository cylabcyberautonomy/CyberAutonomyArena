"""Backend reset ("clean slate") for the MHBench environment — ENV-LAYER OWNED.

Moved out of arena/main.py so the arena core never touches the backend directly. The arena calls every
registered EnvironmentPlugin's `clean_slate(cfg)` classmethod at startup (plugin-agnostically, the same way
it calls each attacker's `sweep_stale_state`); the MHBench plugin routes that here.

OpenStack: wipe all servers/FIPs/routers/ports/subnets/networks/SGs (except external networks + the default
SG), via the `openstack` CLI (which reads OS_CLOUD). GCP: no-op — a GCP-backed manager must NOT run the
OpenStack wipe (it would nuke the shared OpenStack cloud + the other manager's in-flight work); GCP leftovers
are reaped per-experiment via MHBench (config.gcp.yaml). OS_CLOUD is set HERE (from the env-backend config),
so the arena no longer owns it; set once at startup, it is inherited by every later openstack CLI / MHBench
subprocess in this process.
"""
from __future__ import annotations

import asyncio
import logging
import os

from ...config import env_backend

logger = logging.getLogger(__name__)

_NUKE_BATCH = 20  # delete servers this many at a time — a whole-cluster batch overwhelmed nova/neutron


def ensure_os_cloud(cfg) -> None:
    """Set OS_CLOUD from the env-backend config, so the openstack CLI + MHBench subprocesses target the
    right cloud. Owned by the env layer (the arena no longer sets it)."""
    os.environ["OS_CLOUD"] = env_backend(cfg).os_cloud


async def clean_slate(cfg) -> None:
    """Reset the deployment backend this manager targets. OpenStack -> full wipe; GCP -> no-op."""
    ensure_os_cloud(cfg)
    backend = env_backend(cfg).cloud_backend
    if backend == "openstack":
        await openstack_clean_slate()
    else:
        logger.info("clean_slate: backend=%s — skipping the OpenStack wipe (GCP is reaped per-experiment)", backend)


async def openstack_clean_slate() -> None:
    """Tear down all OpenStack resources except external networks and their subnets."""

    async def _run(*args: str) -> str:
        proc = await asyncio.create_subprocess_exec(
            "openstack", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()

    async def _exec(*args: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "openstack", *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0

    logger.info("Collecting external network IDs...")
    ext_raw = await _run("network", "list", "--external", "-f", "value", "-c", "ID")
    external_net_ids = set(ext_raw.splitlines()) if ext_raw else set()
    if external_net_ids:
        logger.info("External networks (will be preserved): %s", external_net_ids)

    logger.info("=== Deleting servers ===")
    sids = [s for s in (await _run("server", "list", "--all-projects", "-f", "value", "-c", "ID")).splitlines() if s]
    if sids:
        # Delete in chunks of _NUKE_BATCH, each `server delete ... --wait` blocking until that chunk is gone
        # before the next starts — so nova/neutron tear down at most _NUKE_BATCH VMs at once. A single
        # whole-cluster batch overwhelmed them (VIF-unplug + volume-detach storm). The CLI attempts every ID
        # in the chunk and reports failures at the end, so a straggler doesn't abort the rest of its chunk.
        logger.info("Deleting %d servers in batches of %d", len(sids), _NUKE_BATCH)
        for i in range(0, len(sids), _NUKE_BATCH):
            batch = sids[i:i + _NUKE_BATCH]
            logger.info("Deleting servers %d–%d of %d", i + 1, i + len(batch), len(sids))
            if not await _exec("server", "delete", *batch, "--wait"):
                logger.warning("Batch server delete reported a failure (some servers may remain)")

    logger.info("=== Releasing floating IPs ===")
    fids = [f for f in (await _run("floating", "ip", "list", "-f", "value", "-c", "ID")).splitlines() if f]
    if fids:
        logger.info("Deleting %d floating IPs in one batch", len(fids))
        if not await _exec("floating", "ip", "delete", *fids):
            logger.warning("Batch floating IP delete reported a failure")

    logger.info("=== Cleaning up routers ===")
    for rid in (await _run("router", "list", "-f", "value", "-c", "ID")).splitlines():
        if not rid:
            continue
        gw = await _run("router", "show", rid, "-f", "value", "-c", "external_gateway_info")
        if gw and gw != "None":
            logger.info("Unsetting gateway on router %s", rid)
            if not await _exec("router", "unset", "--external-gateway", rid):
                logger.warning("Failed to unset gateway on router %s", rid)
        for port_id in (await _run("port", "list", "--router", rid, "-f", "value", "-c", "ID")).splitlines():
            if not port_id:
                continue
            logger.info("Removing port %s from router %s", port_id, rid)
            if not await _exec("router", "remove", "port", rid, port_id):
                logger.warning("Failed to remove port %s from router %s", port_id, rid)
        logger.info("Deleting router %s", rid)
        if not await _exec("router", "delete", rid):
            logger.warning("Failed to delete router %s", rid)

    logger.info("=== Deleting orphaned internal ports ===")
    port_raw = await _run("port", "list", "-f", "value", "-c", "ID", "-c", "network_id", "-c", "device_owner")
    orphan_pids = []
    for line in port_raw.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        pid, net_id = parts[0], parts[1]
        device_owner = parts[2] if len(parts) > 2 else ""
        if net_id in external_net_ids:
            continue
        if device_owner in {
            "network:dhcp",
            "network:router_interface",
            "network:router_interface_distributed",
            "network:router_gateway",
            "network:ha_router_replicated_interface",
        }:
            continue
        orphan_pids.append(pid)
    if orphan_pids:
        logger.info("Deleting %d orphaned ports in one batch", len(orphan_pids))
        if not await _exec("port", "delete", *orphan_pids):
            logger.warning("Batch port delete reported a failure")

    logger.info("=== Deleting internal subnets ===")
    subnet_raw = await _run("subnet", "list", "-f", "value", "-c", "ID", "-c", "Name")
    for line in subnet_raw.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        sid = parts[0]
        sname = parts[1] if len(parts) > 1 else ""
        if "external" in sname.lower():
            logger.warning("Skipping external subnet: %s (%s)", sname, sid)
            continue
        logger.info("Deleting subnet %s (%s)", sname, sid)
        if not await _exec("subnet", "delete", sid):
            logger.warning("Failed to delete subnet %s", sid)

    logger.info("=== Deleting internal networks ===")
    for nid in (await _run("network", "list", "-f", "value", "-c", "ID")).splitlines():
        if not nid:
            continue
        if nid in external_net_ids:
            logger.warning("Skipping external network %s", nid)
            continue
        logger.info("Deleting network %s", nid)
        if not await _exec("network", "delete", nid):
            logger.warning("Failed to delete network %s", nid)

    logger.info("=== Deleting security groups ===")
    sg_raw = await _run("security group", "list", "-f", "value", "-c", "ID", "-c", "Name")
    for line in sg_raw.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        sgid = parts[0]
        sgname = parts[1] if len(parts) > 1 else ""
        if sgname.strip().lower() == "default":
            continue
        logger.info("Deleting security group %s (%s)", sgname, sgid)
        if not await _exec("security group", "delete", sgid):
            logger.warning("Failed to delete security group %s", sgid)

    logger.info("=== OpenStack teardown complete ===")
