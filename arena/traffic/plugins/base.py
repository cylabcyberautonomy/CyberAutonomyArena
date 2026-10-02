"""Base class for the *third* plugin class: background-traffic generation.

Mirrors ``AttackerPlugin`` / ``DefenderPlugin`` — a pydantic ``BaseModel`` with a
``_registry`` keyed by ``config_type``, and a lifecycle the harness drives from
``main.py``. Where attacker/defender each own a process on the harness host, a
traffic plugin owns *background user activity on the victim hosts*: it installs a
generator onto every victim, starts it so its noise lands in the attack-phase
telemetry the defender sees, stops it when the attacker exits, and collects its
labeled activity log so benign events stay separable from the attacker's at
scoring time.

Lifecycle (all no-ops by default; the harness calls them only when a traffic
config is present, so a run without one behaves exactly as before):

    setup(experiment, cfg, bastion_ip)          # install generator+persona on victims (heavy; pre-rotation)
    start(experiment, cfg, bastion_ip)          # start it (fast; POST-rotation, so noise is in the attack logs)
    stop(experiment, cfg, bastion_ip)           # stop it (attacker finished)
    collect_logs(experiment, cfg, dest, bastion_ip)  # pull activity log before VMs are destroyed
    teardown(experiment, cfg, bastion_ip)       # best-effort extra cleanup
"""
from __future__ import annotations

from abc import abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...ui_schema import PluginUISchema

if TYPE_CHECKING:
    from ...experiment import Experiment


class TrafficPlugin(BaseModel):
    """Base for background-traffic generators. Subclass with ``config_type="..."``
    to register a selectable plugin (matches the attacker/defender pattern)."""

    _registry: ClassVar[dict[str, type["TrafficPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            TrafficPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    # -- lifecycle (default no-ops; override what you need) -----------------

    async def setup(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str],
    ) -> None:
        """Install the generator + persona onto the victim hosts. Runs BEFORE the
        pre-attack log rotation (like attacker setup) so install noise is rotated
        away, and under the harness's configure gate (heavy bastion ansible).
        Idempotent; raising fails the experiment (a requested traffic layer that
        can't install must not silently produce an un-noised run)."""

    async def start(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str],
    ) -> None:
        """Start the generator on the victim hosts. Runs AFTER rotation so the
        benign activity is captured in the same attack-phase telemetry the
        defender is scored on."""

    async def stop(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str],
    ) -> None:
        """Stop the generator (attacker has finished). Best-effort."""

    async def collect_logs(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        dest: Path,
        bastion_ip: Optional[str],
    ) -> None:
        """Pull the per-host labeled activity log into ``dest`` before the VMs are
        destroyed. Best-effort: losing this log must never block reclaiming VMs."""

    async def teardown(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str],
    ) -> None:
        """Best-effort cleanup of anything MHBench's own teardown won't remove.
        Default no-op — the generator lives on VMs that get destroyed anyway."""
