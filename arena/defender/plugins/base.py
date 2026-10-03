import asyncio
import json
import os
import subprocess
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import output_root
from ...environment import DeployedEnvironment
from ...ui_schema import PluginUISchema


class PreparedDefender(BaseModel):
    """Opaque handoff from prepare() to run(), symmetric with the attacker's PreparedAttacker.
    prepare() does a defender's EXTERNAL arming (stand up the box ES, deploy decoys / plant
    honey-creds for a strategy that arms in setup) to completion and returns this; run() then
    just launches the reactive loop.

    `armed_in_setup` is True when the strategy's arming FULLY completed in prepare() (Perry's
    Strategy.ARMS_IN_SETUP — the static/naive deception strategies). It is informational/diagnostic:
    the arena keeps waiting on the readiness marker uniformly (so a crashed run-mode process is still
    surfaced), but for an armed_in_setup run that wait is near-instant — the run-mode start() only begins
    monitoring, the slow deploy already happened in prepare() — so no separate "skip the marker" path is
    needed. It is False for strategies that arm inside the loop (llm_soc, prompt_injection, Reactive*),
    whose full arming the marker covers."""
    armed_in_setup: bool = False

    # Setup-produced state the runner config needs — the data baton, symmetric with PreparedAttacker
    # carrying its C2 URLs. Phase A (box-ES / box-agent standup, run BEFORE build_config) fills these in,
    # and build_config() bakes them into the config it emits — so they are no longer patched into the
    # already-written config. All optional: a defender with no box telemetry (canary) leaves them None.
    es_url: Optional[str] = None          # harness-host -> box ES ssh -L tunnel URL (http://127.0.0.1:<lport>)
    falco_index: Optional[str] = None     # falco index name on the box ES
    sysflow_index: Optional[str] = None   # sysflow index name on the box ES
    box_agent_host: Optional[str] = None  # box-agent endpoint (dynamic defenders only)
    box_agent_port: Optional[int] = None
    box_agent_token: Optional[str] = None


class DefenderPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    # Keys this plugin's runner REQUIRES in build_config()'s output — the plugin↔runner contract, declared
    # as data (symmetric with AttackerPlugin). The arena validates build_config()'s output against this
    # (before it injects the arena-provided keys like defender_env_spec), and the conformance test checks
    # it generically. Empty = no declared contract. Declare only keys build_config() itself always emits —
    # NOT the arena-injected ones (defender_env_spec / defender_setup_access / management_ip / …).
    REQUIRED_CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset()

    # Per-plugin external code path: a defender backed by an external repo (the Defense/Perry defenders)
    # names its own config fields here, so no single field silently backs several plugins. Default None =
    # self-contained defender (canary) or a backend-specific one (velociraptor reads its own velociraptor_dir).
    code_dir_field: ClassVar[Optional[str]] = None
    code_python_field: ClassVar[Optional[str]] = None

    # Whether this defender executes its actions FROM THE DEFENDER BOX (in-env) via the box agent +
    # the env action channel, rather than from the arena host. When True the arena always deploys the box
    # agent and arms the env channel (box execution is the ONLY path — there is no arena-execution
    # orchestrator any more). Checks-only/self-contained defenders (canary, velociraptor) leave it False.
    executes_from_box: ClassVar[bool] = False

    def _code_dir(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_dir(self.code_dir_field)

    def _code_python(self, cfg: ExperimentManagerConfig) -> Path:
        return cfg.plugin_python(self.code_dir_field, self.code_python_field)

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            DefenderPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    @classmethod
    def validate_built_config(cls, built: dict) -> None:
        """Assert build_config()'s output carries every key the runner requires (REQUIRED_CONFIG_KEYS).
        Called by the arena right after build_config() — before it injects the arena-provided keys — so a
        plugin whose config drifts from what its runner reads fails fast with a precise message."""
        if not cls.REQUIRED_CONFIG_KEYS:
            return
        if not isinstance(built, dict):
            raise ValueError(f"{cls.__name__}.build_config() returned {type(built).__name__}, not a dict")
        missing = cls.REQUIRED_CONFIG_KEYS - built.keys()
        if missing:
            raise ValueError(
                f"{cls.__name__}.build_config() omitted required key(s) {sorted(missing)} declared in "
                f"REQUIRED_CONFIG_KEYS — its runner reads them. Got keys: {sorted(built)}")

    def box_ingress(self) -> dict[str, list[int]]:
        """The defender-requested box-ingress this plugin needs the ENVIRONMENT to open, by kind:

            "telemetry": [9200]  -> the env relay routes sensor telemetry to the box ES on these
                                    ports (no new victim-facing firewall port opens).
            "forward":   [8000]  -> a victim->mgmt->box raw-TCP passthrough + a victim->mgmt SG rule
                                    on these ports (server-mediated EDR clients beacon in).

        The harness reads this at defender arm and calls `request-ingress` with exactly these ports,
        so the box's exposed surface matches precisely what the defender uses. A defender that needs
        nothing returns {} (default) and opens ZERO box ports. Config-aware: e.g. a diagnostic-only
        canary that runs no telemetry checks opens nothing."""
        return {}

    def defender_vm_budget(self) -> list[tuple[int, int, int]]:
        """The MAX extra VMs this defender may spin up during the run, as (vcpus, ram_mb, disk_gb)
        specs — the same shape EnvironmentPlugin.capacity() returns, so the arena simply appends them to
        the topology's footprint at admission. The cluster then holds room for `topology + this budget`
        BEFORE the experiment is admitted, so every mid-run add_host draws from an already-reserved pool
        and can never block or oversubscribe; the arena rejects an add that would exceed the ceiling.

        OPT-IN, like box_ingress(): a defender that never changes topology (canary, velociraptor, a
        passive SOC) returns [] (default) and needs no other change — the whole dynamic-host path is
        inert for it (topology + 0 reserved, no env↔defender dynamic contract). Only a defender that
        actually requests hosts (a deception/decoy strategy) overrides this. Pairing a non-empty budget
        with an environment whose supports_dynamic_topology() is False is a contract violation the arena
        catches at deploy time."""
        return []

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
    ) -> None:
        """One-time setup this defender needs before it can run (e.g. ensuring shared
        infrastructure like Elasticsearch is up, installing Falco on the experiment's
        hosts). Runs once, before build_config()/run() - default no-op. Mirrors
        AttackerPlugin.setup(); unlike that one there's no per-defender resource (a C2
        container) to tear down on failure, so this has no transactional cleanup -
        raising here just fails the defender start (see run_defender()'s caller).

        `bastion_ip` is this experiment's own bastion floating IP (from MHBench
        provisioning) - NOT the same as cfg.arena_host_ip (the harness's own fixed
        address, used for Elasticsearch). Any AnsibleRunner use needs THIS one to
        SSH-ProxyCommand into the experiment's internal hosts at all.

        `defender_env_spec` (agent-facing: host inventory + the defender box) and
        `defender_access` (setup-time: scoped key + bastion routing per host, a
        list[SetupAccess]) are produced by the ENVIRONMENT plugin and passed in so a
        defender that needs the box/victims at setup time reads them from here instead
        of reaching into a specific backend's deployer. They are the same values the
        arena injects into build_config()'s output for the runner; default None for
        defenders whose setup() doesn't need them."""

    async def prepare(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> "PreparedDefender":
        """EXTERNAL arming phase — the arena calls this AFTER build_config()/config-write and BEFORE
        run(), and blocks on it. A telemetry/deception defender overrides it to stand up its box ES and
        run its strategy's external arming (deploy decoys / plant honey-creds) to completion, so the
        slow, failure-prone arming finishes — and raises HERE if it fails — before the attacker starts,
        mirroring the attacker's setup()→run() split. It returns a PreparedDefender; run() then only
        launches the reactive loop.

        Default: no-op (an empty baton) for defenders with no external arming (e.g. canary). Whether any
        arming actually happens is the strategy's call (Perry's Strategy.ARMS_IN_SETUP): a strategy that
        arms inside its loop makes this a no-op and keeps using the readiness marker."""
        return PreparedDefender()

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Best-effort cleanup of harness-side resources this defender created that the
        environment's own teardown doesn't already handle. Runs before the environment
        teardown. Default no-op; the caller (main.py) already wraps this in try/except,
        same best-effort treatment as log collection - a defender teardown failure must
        not block reclaiming the environment's VMs.

        NOTE: stray VMs a defender stood up outside the topology (decoys) are NOT the
        defender's problem to reap - deleting a VM is backend-specific, and defenders are
        backend-agnostic. The ENVIRONMENT sweeps those on its own networks as the first
        step of its teardown (see MHBenchEnvironment._teardown_dynamic_hosts)."""

    # ------------------------------------------------------------------
    # Readiness handshake
    #
    # A defender's strategy does all of its placement work in initialize()
    # (decoys, fake data, honey credentials) and only then enters the loop that
    # reacts to telemetry. run() below just SPAWNS that process - it returns as
    # soon as the subprocess exists, long before arming is done. Starting the
    # attacker at that point meant the engagement could be over before the
    # defense existed: measured on a ReactiveLayered run, initialize() took
    # 3m45s while the attacker finished its whole chain in 1m38s, so the
    # reactive poll loop never executed a single iteration. These let the
    # harness block until the runner says it is actually armed.
    # ------------------------------------------------------------------
    @staticmethod
    def ready_marker_path(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_ready"

    @classmethod
    def clear_ready_marker(cls, experiment_name: str, cfg: ExperimentManagerConfig) -> None:
        """Remove a stale marker before starting a defender. Re-running an
        experiment with overwrite=true reuses the same output dir, so a marker
        left by the previous run would otherwise make the gate pass instantly."""
        cls.ready_marker_path(experiment_name, cfg).unlink(missing_ok=True)

    @classmethod
    async def wait_until_ready(
        cls,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        process: asyncio.subprocess.Process,
        log=None,
    ) -> float:
        """Block until the defender's runner reports its strategy is armed.

        Returns seconds spent arming. Raises if the defender process dies first
        (a defender that crashed during initialize() must fail the experiment,
        not quietly hand an undefended environment to the attacker) or if
        arming exceeds cfg.defender_ready_timeout_seconds."""
        marker = cls.ready_marker_path(experiment_name, cfg)
        deadline = asyncio.get_event_loop().time() + cfg.defender_ready_timeout_seconds
        started = asyncio.get_event_loop().time()
        while True:
            if marker.exists():
                waited = asyncio.get_event_loop().time() - started
                if log:
                    log(experiment_name, f"Defender armed after {waited:.1f}s")
                return waited
            if process.returncode is not None:
                raise RuntimeError(
                    f"Defender exited (code {process.returncode}) while arming - "
                    f"see {marker.parent / 'defender.log'}"
                )
            if asyncio.get_event_loop().time() > deadline:
                raise TimeoutError(
                    f"Defender did not finish arming within "
                    f"{cfg.defender_ready_timeout_seconds}s - see {marker.parent / 'defender.log'}"
                )
            await asyncio.sleep(2)

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict: ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process: ...

    @staticmethod
    async def _run_deception_script(
        script_path: Path,
        config_path: Path,
        cfg: ExperimentManagerConfig,
        log_path: Path,
        repo_dir: Path,
        python: Path,
        mode: str = "run",
    ) -> asyncio.subprocess.Process:
        """Spawn the plugin's runner.py in its repo's own venv, with the repo on PYTHONPATH so its
        packages are importable. Shared by every DefenderPlugin subclass backed by the Defense/Perry repo
        (llm_soc/deception/prompt_injection) — each passes its OWN resolved repo_dir + python (per-plugin
        config paths). `mode` is passed as argv[2]: "run" (default) launches the long-running reactive loop
        and hands the live process back WITHOUT waiting; "prepare" runs the strategy's external arming to
        completion and exits (see _run_prepare_and_wait)."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        python = str(python)
        pythonpath_parts = [str(repo_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath = os.pathsep.join(pythonpath_parts)
        return await asyncio.create_subprocess_exec(
            python,
            str(script_path),
            str(config_path),
            mode,
            cwd=str(repo_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    @staticmethod
    def prepared_marker_path(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        """Sidecar the prepare-mode runner writes its PreparedDefender baton to (JSON), read back by
        prepare() in the arena process — the only channel across the prepare→run process boundary."""
        return output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_prepared.json"

    @classmethod
    async def _run_prepare_and_wait(
        cls,
        script_path: Path,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        log_path: Path,
    ) -> "PreparedDefender":
        """Run the plugin's runner.py in "prepare" mode (external arming) to completion, in the deception
        venv, and return its PreparedDefender baton. Unlike run(), this WAITS: the external arming (decoy
        deploy etc.) must finish — and a failure must surface as an exception — before the attacker starts.
        Raises if the prepare process exits non-zero or writes no baton."""
        marker = cls.prepared_marker_path(experiment_name, cfg)
        marker.unlink(missing_ok=True)  # drop any stale baton from a prior run of this name
        repo_dir = cfg.plugin_dir(cls.code_dir_field)
        python = cfg.plugin_python(cls.code_dir_field, cls.code_python_field)
        proc = await cls._run_deception_script(script_path, config_path, cfg, log_path, repo_dir, python, mode="prepare")
        rc = await proc.wait()
        if rc != 0:
            raise RuntimeError(
                f"Defender prepare (external arming) exited {rc} — see {log_path}")
        if not marker.exists():
            raise RuntimeError(
                f"Defender prepare exited 0 but wrote no baton at {marker} — see {log_path}")
        return PreparedDefender.model_validate_json(marker.read_text())
