import asyncio
import json
import os
import subprocess
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...experiment_log import log, output_root
from ...ui_schema import PluginUISchema
from ..lifecycle import DefenderSignal
from ...env_action_server import resolve_socket_path


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

    @staticmethod
    def _env_spec_key(env_spec) -> dict:
        """The agent-facing DefenderEnvSpec (host inventory / subnets / box — NO credentials) as a config
        key. A defender's build_config() does `built.update(self._env_spec_key(env_spec))`: it receives the
        spec as a TYPED arg (symmetric with the attacker's build_config(env_spec, ...)) and emits it itself,
        instead of the arena injecting it after. Credential-bearing SetupAccess is deliberately NOT here —
        it stays arena-injected after build_config so build_config's output remains credential-free (the
        tests/test_plugin_conformance leak guard bans ssh_key / ProxyCommand in build_config output)."""
        return {"defender_env_spec": env_spec.model_dump()} if env_spec is not None else {}

    @staticmethod
    def _baton_keys(prepared: "PreparedDefender") -> dict:
        """The subset of the Phase-A baton that goes into the runner config, skipping None. A telemetry
        defender's build_config() does `built.update(self._baton_keys(prepared))` so es_url / falco_index /
        sysflow_index / box_agent_* are baked in — replacing the old 'prepare patches the written config'."""
        fields = ("es_url", "falco_index", "sysflow_index",
                  "box_agent_host", "box_agent_port", "box_agent_token")
        return {f: getattr(prepared, f) for f in fields if getattr(prepared, f, None) is not None}

    async def provision_box(
        self,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        bastion_ip: Optional[str] = None,
        defender_env_spec=None,
        defender_access=None,
        needs_agent: bool = False,
    ) -> "PreparedDefender":
        """PHASE A — produce the baton BEFORE build_config (symmetric with the attacker's setup()→prepared).
        A telemetry defender overrides this to stand up its per-experiment box ES (+ the box agent when
        needs_agent) and return a PreparedDefender carrying es_url / falco_index / sysflow_index /
        box_agent_* — which build_config() then bakes into the runner config. Taking env_spec/access as
        args (not reading a written config) is what lets it run before build_config. Default: an empty
        baton, for a defender with no box telemetry (canary / velociraptor)."""
        return PreparedDefender()

    @staticmethod
    def _lifecycle(experiment):
        """The DefenderLifecycle the arena attached (mirrors AttackerPlugin._lifecycle); None in tests
        that drive run_setup without one."""
        return getattr(experiment, "_defender_lifecycle", None)

    async def run_setup(self, experiment, cfg: ExperimentManagerConfig) -> "PreparedDefender":
        """The SETUP phase — the defender analog of AttackerPlugin.run_setup: fully ARM the defender, so
        the RUN phase (run_defender) only launches the loop. Emit SETUP_STARTED, then:
          setup() + provision_box()   -> the box ES / box-agent baton (what build_config consumes)
          build_config(env_spec, baton) + inject creds/routing + write the runner config
          prepare()                   -> EXTERNAL arming (decoy / honey-cred deploy) that consumes that config
        Returns the PreparedDefender from prepare(). Symmetric with the attacker, whose run_setup also runs
        build_config + writes the config after setup() (its arming — the C2 — happens in setup() itself).

        For the defender build_config lives HERE, not in run_defender: the written config IS part of arming
        (prepare() reads it, and so does the run loop). The credential-bearing SetupAccess + bastion routing
        are injected into the written config (kept OUT of build_config's own output by the leak guard),
        because the defender's runner acts on victims/the box during the run.

        It does NOT emit READY: a defender is READY only once its RUNNER has armed (the readiness marker,
        gated by wait_until_ready after run()), not when setup finishes. FAILED stays centralized in the
        arena's defender error handler (it covers the whole setup→run block), so this just raises."""
        lc = self._lifecycle(experiment)
        if lc is not None:
            await lc.emit(DefenderSignal.SETUP_STARTED)
        experiment_name = experiment.experiment_name
        env_spec = experiment._defender_env_spec        # agent-facing DefenderEnvSpec (host inventory, NO creds)
        access = experiment._defender_access             # scoped SetupAccess list (key + bastion routing)
        bastion_ip = experiment._bastion_ip             # this experiment's ephemeral bastion floating IP
        # The dynamic topology-mutation window (+ box agent) is armed only for an executes_from_box defender —
        # the arena sets experiment._env_dynamic and opens the window before this runs.
        env_action_socket = resolve_socket_path(cfg) if getattr(experiment, "_env_dynamic", False) else None
        needs_agent = env_action_socket is not None
        # Phase-A baton: box ES + ssh -L tunnel (+ box agent), produced BEFORE build_config.
        await self.setup(experiment_name, cfg, bastion_ip,
                         defender_env_spec=env_spec, defender_access=access)
        prepared = await self.provision_box(
            experiment_name, cfg, bastion_ip,
            defender_env_spec=env_spec, defender_access=access,
            needs_agent=needs_agent,
        )
        # build_config(env_spec, baton) -> write the runner config (the defender's arming config).
        config_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender_config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        built = self.build_config(experiment_name, env_spec, prepared)
        type(self).validate_built_config(built)  # fail fast if the config drifts from the runner contract (pre-injection)
        # INJECT the credential-bearing SetupAccess + routing (kept OUT of build_config's output by the leak
        # guard). Box-only execution: an executes_from_box controller gets ONLY the box entry — it never acts
        # on victims directly, it asks the box agent (which alone holds victim access) and the env.
        _access = list(access or [])
        if getattr(type(self), "executes_from_box", False) and env_spec is not None:
            _box = getattr(env_spec, "box", None)
            _box_ip = getattr(_box, "ip", None) if _box else None
            if _box_ip:
                _access = [a for a in _access if getattr(a, "host", None) == _box_ip]
        built["defender_setup_access"] = [a.model_dump() for a in _access]
        # Inject the running plugin's code dir under the stable runner key "deception_dir" (a self-contained
        # defender declares no code_dir_field and gets nothing). management_ip is the harness's own fixed host
        # (NOT an ES address); bastion_ip is this experiment's ephemeral bastion FIP the runner ProxyCommands
        # through to reach internal hosts.
        if type(self).code_dir_field:
            built["deception_dir"] = str(cfg.plugin_dir(type(self).code_dir_field))
        built["management_ip"] = cfg.arena_host_ip
        built["bastion_ip"] = bastion_ip
        built["log_dir"] = str(output_root(experiment_name, cfg) / experiment_name / "defender")
        # Dynamic topology-mutation channel (UDS, no token — unreachable from in-env); present only for an
        # executes_from_box defender.
        if env_action_socket is not None:
            built["env_action_socket"] = env_action_socket
            built["experiment_name"] = experiment_name  # the orchestrator stamps it into each request payload
        config_path.write_text(json.dumps(built, indent=2))
        log(experiment_name, f"Prepared defender ({self.type}) config: {config_path}")
        # EXTERNAL arming (decoy / honey-cred deploy) that CONSUMES the written config. BLOCKS + raises on
        # failure, before the attacker starts. run() then only launches the reactive loop.
        armed = await self.prepare(config_path, experiment_name, cfg)
        log(experiment_name, f"Defender armed (armed_in_setup={armed.armed_in_setup})")
        return armed

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        env_spec,
        prepared: "PreparedDefender",
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
