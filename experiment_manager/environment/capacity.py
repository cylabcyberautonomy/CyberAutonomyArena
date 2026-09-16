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

# Decoys AIAttackerDetection stands up per Falco trigger - see estimate_decoy_vms().
_AI_ATTACKER_DETECTION_DECOY_BURST = 5


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


def _defended_host_count(topology: dict) -> int:
    """Real hosts across the defended (non-attacker) subnets. Mirrors the defender
    repo's Strategy._defended_host_count, which excludes the attacker's own segment.
    The defender determines "attacker" from subnet_connections; here we approximate
    it by subnet name (the attacker segment is conventionally named "*attacker*"),
    which lands within ~1 host of exact — fine for a capacity estimate. Falls back to
    all subnets if none look like the attacker's (matches the repo's `or all` fallback)."""
    subnets = [s for net in topology.get("networks", []) for s in net.get("subnets", [])]
    non_attacker = [s for s in subnets if "attacker" not in (s.get("name", "").lower())] or subnets
    return sum(len(s.get("hosts", [])) for s in non_attacker)


def estimate_decoy_vms(defender, topology_path: Path) -> int:
    """Estimate how many decoy VMs the defender will stand up during arming, so they
    can be included in the VM-count reservation (they are real VMs but are deployed by
    the defender subprocess, outside count_vm_specs). The true count is decided in the
    defender repo: arsenal['DeployDecoy'] if set, else default = round(defended/3)
    (Strategy._default_decoy_count). We mirror that. Only deception/prompt_injection
    deploy decoys via this path; a DoNothing strategy deploys none; llm_soc and others
    deploy none. Honey credentials are NOT VMs, so they are ignored here.

    AIAttackerDetection (prompt_injection's reactive strategy) is the one exception to
    the mirror: it ignores both arsenal['DeployDecoy'] and the default, deploys 0 at arm
    time, and then 5 per Falco trigger (dynamic_prompt_injection.py, `for i in range(5)`),
    once per distinct tripped host. Nothing up-front can predict the trigger count, so we
    reserve one burst - a far better estimate than round(defended/3), which relates to
    nothing that strategy does."""
    if defender is None:
        return 0
    if getattr(defender, "type", None) not in ("prompt_injection", "deception"):
        return 0
    if (getattr(defender, "strategy", "") or "") == "AIAttackerDetection":
        return _AI_ATTACKER_DETECTION_DECOY_BURST
    arsenal = getattr(defender, "arsenal", None) or {}
    if "DeployDecoy" in arsenal:
        try:
            return max(0, int(arsenal["DeployDecoy"]))
        except (TypeError, ValueError):
            pass
    if (getattr(defender, "strategy", "") or "") == "DoNothing":
        return 0
    hosts = _defended_host_count(json.loads(topology_path.read_text()))
    return max(1, round(hosts / 3)) if hosts else 0


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
    holding by virtue of no longer being there."""
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
                 active_source: Callable[[], Iterable[Any]] | None = None) -> None:
        self._max_active_vms: int | None = max_active_vms
        # Returns every experiment the harness knows about; the tracker filters with
        # _holds_vms(). Defaults to "none" so a tracker with no registry acts uncapped.
        self._active_source: Callable[[], Iterable[Any]] = active_source or (lambda: ())
        # Cluster totals from the one startup read; None if nova was unreachable then, in
        # which case the over-commit warning is simply skipped (admission is unaffected).
        self._totals: tuple[int, int, int] | None = None
        self._condition = asyncio.Condition()

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

    async def reserve(self, vm_specs: list[tuple[int, int, int]], experiment_name: str,
                      extra_vms: int = 0,
                      on_admit: Callable[[Reservation], None] | None = None) -> Reservation:
        """Block until the VM-count cap allows this experiment.

        extra_vms: the defender's decoy VMs - real VMs deployed later by the defender
        subprocess, so not in vm_specs, but they count toward the cap.

        on_admit(reservation) is invoked INSIDE the lock the moment admission is decided. The
        caller must use it to set vms_reserved / vcpus_reserved / ram_mb_reserved /
        disk_gb_reserved on the experiment, so that the registry already shows this experiment
        as holding VMs before any other reserve() can evaluate the count."""
        total_vcpus = sum(v for v, _, _ in vm_specs)
        total_ram = sum(r for _, r, _ in vm_specs)
        total_disk = sum(dk for _, _, dk in vm_specs)
        n_vms = len(vm_specs) + max(0, extra_vms)
        async with self._condition:
            while True:
                active = self.active_vms
                # Admit if under the cap, OR if nothing else holds VMs - the latter lets a
                # single env larger than the cap still run (alone) instead of deadlocking
                # forever waiting for room that can never free up.
                if (self._max_active_vms is None
                        or active + n_vms <= self._max_active_vms
                        or active == 0):
                    reservation = Reservation(total_vcpus, total_ram, total_disk, n_vms)
                    if on_admit is not None:
                        on_admit(reservation)
                    logger.info(
                        "[%s] Admitted: %d VMs (%d topology + %d decoy; %d vCPUs / %d MB RAM / %d GB disk); "
                        "active VMs now %d%s",
                        experiment_name, n_vms, len(vm_specs), max(0, extra_vms),
                        total_vcpus, total_ram, total_disk, self.active_vms, self._cap_str(),
                    )
                    self._warn_if_overcommitted(experiment_name, reservation)
                    return reservation
                logger.info(
                    "[%s] Waiting for VM capacity: need %d VMs, active %d%s",
                    experiment_name, n_vms, active, self._cap_str(),
                )
                try:
                    # Condition.wait() re-acquires the lock in its finally even when cancelled
                    # (the timeout), so we hold the lock again on either exit path.
                    await asyncio.wait_for(self._condition.wait(), timeout=_RECHECK_SECONDS)
                except asyncio.TimeoutError:
                    pass  # backstop: loop and re-derive the count from state (free; no I/O)

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
