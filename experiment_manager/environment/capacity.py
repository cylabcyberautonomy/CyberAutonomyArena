from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Callable, Iterable, NamedTuple

import yaml

logger = logging.getLogger(__name__)

_flavor_cache: dict[str, tuple[int, int, int]] = {}

# Disk headroom assumed in the over-commit WARNING (not a gate): nova schedules per-node, so packing
# aggregate disk to ~100% leaves each node too full to fit the next VM even when aggregate looks fine
# → "No valid host". The warning fires when harness-reserved disk exceeds total minus this.
_DISK_HEADROOM_GB = 800



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
        # disk (GB) is the one that matters most: nova reserves the full flavor disk, and an env with many small
        # hosts (each e.g. 20GB) exhausts cluster disk long before vCPU/RAM — that's what caused "No valid host".
        result = (int(data["vcpus"]), int(data["ram"]), int(data["disk"]))
    except Exception:
        # No OpenStack CLI / not an OpenStack backend (e.g. the GCP manager). Only the VM COUNT
        # gates admission — the per-VM vcpu/ram/disk feed the over-commit WARNING only — so a
        # placeholder keeps counting correct without depending on OpenStack.
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
    """Return (vcpus, ram_mb, disk_gb) for each VM in the topology, including the management host.

    flavor_cpu_cost (GCP only): map of MHBench flavor -> GCP CPUS_ALL_REGIONS cost. When given, the
    vcpu field of each spec is taken from this map (falling back to the placeholder count for a flavor
    not listed), so the vCPU reservation reflects the real GCP quota cost instead of the (2,4096,20)
    placeholder that _get_flavor_specs returns when there's no OpenStack. RAM/disk are left as-is.
    Omit it (or pass None/empty) on OpenStack for unchanged behavior."""
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


async def _query_cluster_totals() -> tuple[int, int, int]:
    """Return the cluster's TOTAL (vcpus, ram_mb, disk_gb). Read exactly once, at startup, for
    the over-commit warning - never on the admission path."""
    proc = await asyncio.create_subprocess_exec(
        "openstack", "hypervisor", "stats", "show", "-f", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data = json.loads(stdout.decode())
    return int(data["vcpus"]), int(data["memory_mb"]), int(data["local_gb"])


# A waiter re-evaluates at least this often even if no release() ever notifies it. The
# re-evaluation is a sum over the in-memory registry - no I/O, no nova - so this costs nothing;
# it just guarantees a lost notification can delay admission but never wedge it.
_RECHECK_SECONDS = 30.0


class Reservation(NamedTuple):
    """What reserve() admitted for one experiment. The caller records it ON THE EXPERIMENT
    (via reserve()'s on_admit, under the tracker's lock) so that the registry - not this
    object and not any ledger inside the tracker - is the single source of truth. vcpus /
    ram_mb / disk_gb are recorded for the over-commit warning and the run record; only
    n_vms gates admission."""
    vcpus: int
    ram_mb: int
    disk_gb: int
    n_vms: int


def _holds_vms(e) -> bool:
    """THE rule for whether an experiment currently occupies VMs. It is evaluated against
    live experiment state on every check, not against a paired reserve/release ledger, so
    no code path (finish, failure, retry, timeout, cancel, provider refusal) can leak a
    count or double-count one:

      * it holds VMs from the instant reserve() admits it (vms_reserved is set under the
        tracker's lock, before any other reserve() can be evaluated)
      * until its teardown has actually COMPLETED (teardown_finished_at set).

    Status is deliberately not consulted. An ERROR whose teardown failed still has VMs on
    the cluster and keeps holding them; a FINISHED / TIMEDOUT / BLOCKED / ERROR one whose
    teardown succeeded released them the moment it finished. A QUEUED experiment has no
    reservation yet, so it never holds. A retry clears vms_reserved (and
    teardown_finished_at) before re-reserving, so the failed attempt's VMs never count
    alongside the new attempt's. An experiment removed from the registry (DELETE) stops
    holding once it is gone."""
    return (getattr(e, "vms_reserved", None) is not None
            and getattr(e, "teardown_finished_at", None) is None)


class CapacityTracker:
    """Admission control for experiments: ONE rule, the VM-count cap (max_active_vms).

    The count is derived on EVERY check from the experiments themselves via `active_source`
    (the registry's load()): the sum of vms_reserved over those for which _holds_vms() is
    true. There is no internal ledger to keep in step with call sites and no nova query on
    the admission path - the registry IS the ledger, and _holds_vms() is the only thing
    that decides.

    Nova is read exactly once, at startup, for the cluster's TOTAL vCPU/RAM/disk. Those are
    used only to log a warning when an admission would push the harness's own reserved
    totals past what the cluster physically has (i.e. the cap is set too high for the
    flavors in play - the "No valid host" failure mode). It is a log line, never a gate:
    the operator sizes max_active_vms; the harness just tells them if it looks wrong.

    Waiters re-evaluate on every release() and, as a free backstop, every _RECHECK_SECONDS.
    """

    def __init__(self, max_active_vms: int | None = None,
                 active_source: Callable[[], Iterable[Any]] | None = None,
                 max_active_cpus: int | None = None) -> None:
        self._max_active_vms: int | None = max_active_vms
        # GCP-only CPU budget (the global CPUS_ALL_REGIONS quota). None = no CPU gate, so on
        # OpenStack admission is decided by the VM-count rule alone, exactly as before.
        self._max_active_cpus: int | None = max_active_cpus
        # Returns every experiment the harness knows about; the tracker filters with
        # _holds_vms(). Defaults to "none" so a tracker with no registry acts uncapped.
        self._active_source: Callable[[], Iterable[Any]] = active_source or (lambda: ())
        # Cluster totals from the one startup read; None if nova was unreachable then, in
        # which case the over-commit warning is simply skipped (admission is unaffected).
        self._totals: tuple[int, int, int] | None = None
        self._condition = asyncio.Condition()
        # Priority-ordered admission. Currently-waiting reservers:
        #   experiment_name -> (neg_priority, seq, n_vms, total_vcpus)
        # A waiter admits only when it fits AND no higher-ranked waiter that ALSO currently fits is
        # queued — so a labeled-priority experiment jumps ahead, while a priority run too big for the
        # free capacity still lets smaller lower-priority runs fill the gap ("whoever fits"). Rank is
        # (neg_priority, seq): lower = served first (neg_priority = -priority; seq = FIFO tiebreak).
        self._waiting: dict[str, tuple] = {}
        self._wait_seq: int = 0

    # ----------------------------------------------------------- state-derived views
    def _holders(self) -> list:
        return [e for e in self._active_source() if _holds_vms(e)]

    @property
    def active_vms(self) -> int:
        """VMs currently held across all experiments - the authoritative count."""
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
        """Log (never block) if, with this admission, the harness's own reservations exceed
        the cluster. Exact rather than a flavor guess: it uses the real flavors of everything
        currently held plus this experiment's."""
        if self._totals is None:
            return
        t_vcpus, t_ram, t_disk = self._totals
        r_vcpus, r_ram, r_disk = self._reserved_totals()   # already includes `res` (on_admit ran)
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
        """Whether a demand of (n_vms, total_vcpus) can be admitted against the current active totals.
        Mirrors the vm_ok/cpu_ok rules in reserve() (incl. the active==0 lone-oversized escape) so the
        priority outranking check uses the exact same admission logic."""
        vm_ok = (self._max_active_vms is None
                 or active + n_vms <= self._max_active_vms
                 or active == 0)
        cpu_ok = (self._max_active_cpus is None
                  or active_cpus + total_vcpus <= self._max_active_cpus)
        return vm_ok and cpu_ok

    async def reprioritize(self, experiment_name: str, priority: int) -> bool:
        """Change a still-QUEUED experiment's scheduling priority on the fly. Returns True if it was
        currently waiting (and got re-ranked + everyone re-woken), False if it isn't waiting anymore
        (already admitted / unknown). Higher priority = sooner."""
        async with self._condition:
            w = self._waiting.get(experiment_name)
            if w is None:
                return False
            self._waiting[experiment_name] = (-priority, w[1], w[2], w[3])  # keep seq/n_vms/vcpus
            self._condition.notify_all()
            return True

    async def reserve(self, vm_specs: list[tuple[int, int, int]], experiment_name: str,
                      on_admit: Callable[[Reservation], None] | None = None,
                      priority: int = 0) -> Reservation:
        """Block until the VM-count cap AND (on GCP) the CPU budget allow this experiment.

        Admission counts ONLY the topology VMs in vm_specs (the environment's real footprint,
        incl. the management host). VMs a plugin may deploy later (e.g. defender decoys) are NOT
        pre-reserved here.

        on_admit(reservation) is invoked INSIDE the lock the moment admission is decided. The
        caller must use it to set vms_reserved / vcpus_reserved / ram_mb_reserved /
        disk_gb_reserved on the experiment, so that the registry already shows this experiment
        as holding VMs before any other reserve() can evaluate the count."""
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
                # VM-count rule: admit if under the cap, OR if nothing else holds VMs - the
                # latter lets a single env larger than the cap still run (alone) instead of
                # deadlocking forever waiting for room that can never free up.
                vm_ok = (self._max_active_vms is None
                         or active + n_vms <= self._max_active_vms
                         or active == 0)
                # CPU budget (GCP): the global CPUS_ALL_REGIONS quota is a HARD ceiling - it
                # cannot be exceeded even by a lone experiment (that just strands mid-provision
                # with QUOTA_EXCEEDED), so there is deliberately no active==0 escape here. An
                # env whose own CPU cost exceeds the budget waits in QUEUED instead. None (the
                # OpenStack default) makes this always true, leaving admission to the VM rule.
                cpu_ok = (self._max_active_cpus is None
                          or active_cpus + total_vcpus <= self._max_active_cpus)
                # Priority gate: yield to any higher-ranked waiter that ALSO fits right now, so
                # labeled-priority experiments are admitted first. A higher-priority run that is
                # too big to fit does NOT block us (it isn't counted as outranking), so smaller
                # lower-priority runs still fill the gap.
                my_rank = self._waiting[experiment_name][:2]
                outranked = any(
                    (w[0], w[1]) < my_rank and self._fits(w[2], w[3], active, active_cpus)
                    for nm, w in self._waiting.items() if nm != experiment_name
                )
                if vm_ok and cpu_ok and not outranked:
                    reservation = Reservation(total_vcpus, total_ram, total_disk, n_vms)
                    if on_admit is not None:
                        on_admit(reservation)
                    self._condition.notify_all()  # let any waiters that yielded to us re-check now
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
                    # Condition.wait() re-acquires the lock in its finally even when cancelled
                    # (the timeout), so we hold the lock again on either exit path.
                    await asyncio.wait_for(self._condition.wait(), timeout=_RECHECK_SECONDS)
                except asyncio.TimeoutError:
                    pass  # backstop: loop and re-derive the count from state (free; no I/O)
            finally:
                # Deregister from the priority queue on EVERY exit (admit, cancel/eviction, error) so a
                # departed waiter never keeps outranking the others. Runs with the condition lock held
                # (the async-with hasn't exited), and before the post-admit notify_all reaches anyone.
                self._waiting.pop(experiment_name, None)

    def release(self, experiment_name: str) -> None:
        """Call after an experiment's teardown has RUN - whether or not it succeeded - and
        after a DELETE removed it from the registry. Whether it still holds VMs is decided
        entirely by its state (_holds_vms), not by this call: this only wakes the waiters so
        they re-derive the count. No nova. Fire-and-forget, idempotent, and safe for an
        experiment that never reserved."""
        async def _release() -> None:
            async with self._condition:
                logger.info("[%s] Released; active VMs now %d%s",
                            experiment_name, self.active_vms, self._cap_str())
                self._condition.notify_all()

        asyncio.ensure_future(_release())
