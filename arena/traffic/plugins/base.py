"""Base class for the *third* plugin class: background-traffic generation.

Full parity with ``DefenderPlugin`` — a pydantic ``BaseModel`` with a ``_registry`` keyed by
``config_type``, a ``build_config()`` → runner contract, a runner subprocess the arena spawns, and the
same readiness-marker handshake the defender uses (so the attacker is gated on background traffic actually
being up, and a flaky generator surfaces as a failed run instead of a silently un-noised one).

Where the defender owns a reactive loop, a traffic plugin owns *background user activity on the victim
hosts*: it INSTALLS a generator onto every victim (``setup()``, heavy — run BEFORE the pre-attack log
rotation so install noise is rotated away), then its RUNNER starts the generator so benign activity lands
in the attack-phase telemetry the defender sees, holds until the attacker finishes, and pulls the labeled
activity log so benign events stay separable from the attacker's at scoring time.

Like the defender, traffic is OPTIONAL and fully decoupled from the backend: the ENVIRONMENT produces a
``TrafficEnvSpec`` (victim inventory) + a scoped ``SetupAccess`` per victim (key + bastion routing), which
the arena hands to ``setup()`` and injects into the runner config. A plugin never reads a management key
or parses a topology — it reaches each victim via ``access.ssh_base()``.

Lifecycle the arena drives (only when a traffic config is present):

    setup(experiment, cfg, spec, access, bastion_ip)   # install generator+persona on victims (pre-rotation, FATAL)
    build_config(experiment_name, environment) -> dict  # the runner contract (arena injects spec/access on top)
    run(config_path, experiment_name, cfg) -> Process   # spawn the runner (post-rotation); it arms + holds
      └─ runner touches ready_marker once generators are up; arena wait_until_ready() gates the attacker
    <arena terminates the process>                       # runner stops generators + pulls logs on SIGTERM
    teardown(experiment, cfg)                            # best-effort extra cleanup (default no-op)
"""
from __future__ import annotations

import asyncio
from abc import abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import output_root
from ...ui_schema import PluginUISchema

if TYPE_CHECKING:
    from ...experiment import Experiment


class TrafficPlugin(BaseModel):
    """Base for background-traffic generators. Subclass with ``config_type="..."`` to register a
    selectable plugin (matches the attacker/defender pattern)."""

    _registry: ClassVar[dict[str, type["TrafficPlugin"]]] = {}

    # Keys this plugin's runner REQUIRES in build_config()'s output — the plugin↔runner contract, declared
    # as data (symmetric with DefenderPlugin). The arena validates build_config()'s output against this
    # (before injecting the arena-provided traffic_env_spec / traffic_setup_access). Empty = no contract.
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # Per-plugin external code path (symmetric with DefenderPlugin): a traffic plugin backed by an external
    # repo names its own config fields here, so the arena can run its runner in that repo's own venv.
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            TrafficPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS).
        Called by the arena right after build_config() — before it injects the arena-provided keys."""
        if not cls.REQUIRED_CONFIG_KEYS:
            return
        if not isinstance(built, dict):
            raise ValueError(f"{cls.__name__}.build_config() returned {type(built).__name__}, not a dict")
        missing = cls.REQUIRED_CONFIG_KEYS - built.keys()
        if missing:
            raise ValueError(
                f"{cls.__name__}.build_config() omitted required key(s) {sorted(missing)} declared in "
                f"REQUIRED_CONFIG_KEYS — its runner reads them. Got keys: {sorted(built)}")

    # -- lifecycle ---------------------------------------------------------
    async def setup(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
        traffic_env_spec=None,
        traffic_access=None,
        bastion_ip: Optional[str] = None,
    ) -> None:
        """Install the generator + persona onto the victim hosts. The arena runs this BEFORE the
        pre-attack log rotation (so install noise is rotated away) and under its configure gate (heavy
        bastion work). FATAL: raising fails the experiment — a requested traffic layer that can't install
        must not silently produce an un-noised run.

        ``traffic_env_spec`` (agent-facing: victim inventory) and ``traffic_access`` (setup-time: scoped
        key + bastion routing per victim, a list[SetupAccess]) are produced by the ENVIRONMENT and passed
        in, so the plugin reaches victims via ``access.ssh_base()`` instead of reading a management key or
        parsing a backend topology. Default no-op."""

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        environment,
    ) -> dict:
        """The runner contract: the dict the plugin's runner reads. The arena injects
        ``traffic_env_spec`` + ``traffic_setup_access`` + ``bastion_ip`` + ``log_dir`` on top (see
        traffic.run_traffic), so declare only the keys build_config() itself always emits."""
        ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        """Spawn the traffic runner subprocess (post-rotation) and return it WITHOUT waiting. The runner
        starts the generators on the victims, touches the readiness marker once they are up (see
        wait_until_ready), then holds until SIGTERM — on which it stops the generators and pulls the
        labeled activity log into log_dir before the VMs are destroyed."""
        ...

    async def teardown(
        self,
        experiment: "Experiment",
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Best-effort cleanup of harness-side resources the generator left that the environment's own
        teardown won't remove. Default no-op — the generator lives on VMs that get destroyed anyway."""

    # -- readiness handshake (symmetric with DefenderPlugin) ---------------
    @staticmethod
    def ready_marker_path(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "traffic" / "traffic_ready"

    @classmethod
    def clear_ready_marker(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Remove a stale marker before starting (overwrite=true reuses the output dir, so a marker left
        by a previous run would otherwise make the gate pass instantly)."""
        cls.ready_marker_path(experiment_name, cfg).unlink(missing_ok=True)

    @classmethod
    async def wait_until_ready(
        cls,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        process: asyncio.subprocess.Process,
        log=None,
    ) -> float:
        """Block until the runner reports the generators are up (writes the marker). Returns seconds
        spent. Raises if the runner dies first (a traffic layer that crashed before generating must fail
        the experiment, not hand the attacker an un-noised run) or if it exceeds the timeout.

        Reuses cfg.defender_ready_timeout_seconds — the same arming-timeout budget as the defender."""
        marker = cls.ready_marker_path(experiment_name, cfg)
        timeout = cfg.defender_ready_timeout_seconds
        deadline = asyncio.get_event_loop().time() + timeout
        started = asyncio.get_event_loop().time()
        while True:
            if marker.exists():
                waited = asyncio.get_event_loop().time() - started
                if log:
                    log(experiment_name, f"Traffic up after {waited:.1f}s")
                return waited
            if process.returncode is not None:
                raise RuntimeError(
                    f"Traffic runner exited (code {process.returncode}) before starting generators — "
                    f"see {marker.parent / 'traffic.log'}")
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(
                    f"Traffic did not start within {timeout}s — see {marker.parent / 'traffic.log'}")
            await asyncio.sleep(2)
