"""Admission control for the arena — backend-neutral VM-count/CPU admission gate."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Iterable, NamedTuple

logger = logging.getLogger(__name__)

_DISK_HEADROOM_GB = 800


async def _query_cluster_totals() -> tuple[int, int, int]:
    """Return the cluster's TOTAL (vcpus, ram_mb, disk_gb), read once at startup."""
    proc = await asyncio.create_subprocess_exec(
        "openstack", "hypervisor", "stats", "show", "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    return int(data["vcpus"]), int(data["memory_mb"]), int(data["local_gb"])


_RECHECK_SECONDS = 30.0


class Reservation(NamedTuple):
    """What reserve() admitted for one experiment. Only n_vms gates admission."""
    vcpus: int
    ram_mb: int
    disk_gb: int
    n_vms: int


def _holds_vms(e) -> bool:
    """Whether an experiment currently occupies VMs (reserved but teardown not finished)."""
    return (getattr(e, "vms_reserved", None) is not None
            and getattr(e, "teardown_finished_at", None) is None)


class CapacityTracker:
    """Admission control for experiments, gated on the VM-count cap and (GCP) a CPU budget."""

    def __init__(self, max_active_vms: int | None = None,
                 active_source: Callable[[], Iterable[Any]] | None = None,
                 max_active_cpus: int | None = None) -> None:
        self._max_active_vms: int | None = max_active_vms
        self._max_active_cpus: int | None = max_active_cpus
        self._active_source: Callable[[], Iterable[Any]] = active_source or (lambda: ())
        self._totals: tuple[int, int, int] | None = None
        self._condition = asyncio.Condition()
        self._waiting: dict[str, tuple] = {}
        self._wait_seq: int = 0

    def _holders(self) -> list:
        return [e for e in self._active_source() if _holds_vms(e)]

    @property
    def active_vms(self) -> int:
        """VMs currently held across all experiments."""
        return sum(int(e.vms_reserved) for e in self._holders())

    def _reserved_totals(self) -> tuple[int, int, int]:
        """Harness-reserved (vcpus, ram_mb, disk_gb) across everything currently holding VMs."""
        held = self._holders()
        return (
            sum(int(getattr(e, "vcpus_reserved", 0) or 0) for e in held),
            sum(int(getattr(e, "ram_mb_reserved", 0) or 0) for e in held),
            sum(int(getattr(e, "disk_gb_reserved", 0) or 0) for e in held),
        )

    def _cap_str(self) -> str:
        return f"/{self._max_active_vms}" if self._max_active_vms is not None else ""

    async def initialize(self) -> None:
        try:
            self._totals = await _query_cluster_totals()
        except Exception:
            logger.exception("Could not read cluster totals from nova at startup; the "
                             "over-commit warning is disabled (admission is unaffected)")
            return
        vcpus, ram_mb, disk_gb = self._totals
        logger.info(
            "Cluster totals at startup: %d vCPUs / %d MB RAM / %d GB disk; VM cap %s; active VMs %d",
            vcpus, ram_mb, disk_gb, self._max_active_vms if self._max_active_vms is not None else "none",
            self.active_vms,
        )

    def _warn_if_overcommitted(self, experiment_name: str, res: Reservation) -> None:
        """Log (never block) if this admission pushes harness reservations past the cluster totals."""
        if self._totals is None:
            return
        t_vcpus, t_ram, t_disk = self._totals
        r_vcpus, r_ram, r_disk = self._reserved_totals()
        over = []
        if r_vcpus > t_vcpus:
            over.append(f"vCPUs {r_vcpus}/{t_vcpus}")
        if r_ram > t_ram:
            over.append(f"RAM {r_ram}/{t_ram} MB")
        if r_disk > t_disk - _DISK_HEADROOM_GB:
            over.append(f"disk {r_disk}/{t_disk} GB (headroom {_DISK_HEADROOM_GB})")
        if over:
            logger.warning(
                "[%s] Admitted, but harness-reserved capacity now exceeds the cluster: %s. "
                "max_active_vms%s is too high for the flavors in play - expect nova "
                "'No valid host' failures. Lower the cap.",
                experiment_name, "; ".join(over), self._cap_str(),
            )

    def _fits(self, n_vms: int, total_vcpus: int, active: int, active_cpus: int) -> bool:
        """Whether a demand of (n_vms, total_vcpus) can be admitted against the active totals."""
        vm_ok = (self._max_active_vms is None
                 or active + n_vms <= self._max_active_vms
                 or active == 0)
        cpu_ok = (self._max_active_cpus is None
                  or active_cpus + total_vcpus <= self._max_active_cpus)
        return vm_ok and cpu_ok

    async def reprioritize(self, experiment_name: str, priority: int) -> bool:
        """Change a still-QUEUED experiment's scheduling priority. Return True if it was waiting."""
        async with self._condition:
            w = self._waiting.get(experiment_name)
            if w is None:
                return False
            self._waiting[experiment_name] = (-priority, w[1], w[2], w[3])
            self._condition.notify_all()
            return True

    async def reserve(self, vm_specs: list[tuple[int, int, int]], experiment_name: str,
                      on_admit: Callable[[Reservation], None] | None = None,
                      priority: int = 0) -> Reservation:
        """Block until the VM-count cap and (GCP) CPU budget allow this experiment, then admit it."""
        total_vcpus = sum(v for v, _, _ in vm_specs)
        total_ram = sum(r for _, r, _ in vm_specs)
        total_disk = sum(dk for _, _, dk in vm_specs)
        n_vms = len(vm_specs)
        async with self._condition:
            self._wait_seq += 1
            self._waiting[experiment_name] = (-priority, self._wait_seq, n_vms, total_vcpus)
            try:
              while True:
                active = self.active_vms
                active_cpus = self._reserved_totals()[0]
                vm_ok = (self._max_active_vms is None
                         or active + n_vms <= self._max_active_vms
                         or active == 0)
                cpu_ok = (self._max_active_cpus is None
                          or active_cpus + total_vcpus <= self._max_active_cpus)
                my_rank = self._waiting[experiment_name][:2]
                outranked = any(
                    (w[0], w[1]) < my_rank and self._fits(w[2], w[3], active, active_cpus)
                    for nm, w in self._waiting.items() if nm != experiment_name
                )
                if vm_ok and cpu_ok and not outranked:
                    reservation = Reservation(total_vcpus, total_ram, total_disk, n_vms)
                    if on_admit is not None:
                        on_admit(reservation)
                    self._condition.notify_all()
                    logger.info(
                        "[%s] Admitted: %d topology VMs (%d vCPUs / %d MB RAM / %d GB disk); "
                        "active VMs now %d%s%s",
                        experiment_name, n_vms,
                        total_vcpus, total_ram, total_disk, self.active_vms, self._cap_str(),
                        (f"; active vCPUs now {self._reserved_totals()[0]}/{self._max_active_cpus}"
                         if self._max_active_cpus is not None else ""),
                    )
                    self._warn_if_overcommitted(experiment_name, reservation)
                    return reservation
                logger.info(
                    "[%s] Waiting for capacity: need %d VMs / %d vCPUs, active %d VMs%s / %d vCPUs%s",
                    experiment_name, n_vms, total_vcpus, active, self._cap_str(), active_cpus,
                    (f"/{self._max_active_cpus}" if self._max_active_cpus is not None else ""),
                )
                try:
                    await asyncio.wait_for(self._condition.wait(), timeout=_RECHECK_SECONDS)
                except asyncio.TimeoutError:
                    pass
            finally:
                self._waiting.pop(experiment_name, None)

    def release(self, experiment_name: str) -> None:
        """Wake the waiters to re-derive the count after a teardown or DELETE. This call is idempotent."""
        async def _release() -> None:
            async with self._condition:
                logger.info("[%s] Released; active VMs now %d%s",
                            experiment_name, self.active_vms, self._cap_str())
                self._condition.notify_all()

        asyncio.ensure_future(_release())
