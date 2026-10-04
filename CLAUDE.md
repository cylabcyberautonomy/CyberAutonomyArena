# The arena

The arena runs cyber-range **experiments**. An experiment pairs three pluggable systems:

| System          | Role                                                              | Required? |
|-----------------|------------------------------------------------------------------|-----------|
| **environment** | deploys the network the experiment runs on, sizes it, issues scoped access, produces the agent-facing specs | yes |
| **attacker**    | the offensive agent, run from a foothold in that network         | yes |
| **defender**    | the defensive system (detection / deception / active response)   | optional |

The arena (`arena/main.py`) drives each system through a fixed lifecycle and **never reaches
inside a plugin**; no plugin reaches into the arena. Swapping any system is choosing a different plugin —
no arena change. The conceptual reference lives in `docs/` (`architecture.md`, `lifecycle.md`,
`plugins.md`, `security-model.md`); this file is the practical "how to extend" guide.

---

## How every plugin works (shared mechanics)

**Register by subclassing + a `config_type`.** Each plugin subclasses its system's base and passes a
`config_type`, which registers it in that base's `_registry`:

```python
class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    ...
```

The plugins package imports every module under it on startup, so a class self-registers. **To add a
plugin, drop a file in the right `plugins/` directory — there is no central list to edit.**

**Selection in the experiment spec** (shapes differ by system):

```json
{
  "experiment_name": "demo",
  "environment": "environments/instrumented/equifax_small_instrumented.json",
  "attacker_plugin": "incalmo_strategy",
  "attacker_spec": {"strategy": "GraphSearch"},
  "defender":  {"type": "llm_soc", "strategy": "FalcoLLM"}
}
```
- **attacker** — a `(plugin, spec)` pair: `attacker_plugin` + `attacker_spec` (an inline dict **or** a
  path to a JSON/YAML file). This is the only attacker form.
- **environment** — the explicit `{environment_plugin, environment_spec}` (`environment_plugin` names a
  registered plugin, `environment_spec` is a path; no bare-string shorthand).
- **defender** — the embedded `{type, ...}` form.

**Two invariants every plugin must respect** (full rationale in `docs/security-model.md`):
1. **No god key.** The environment issues a scoped credential per system — the attacker key opens its
   foothold only, the defender key its box + victims only. A plugin gets its key from the injected
   `SetupAccess` and must **never** read the broad management key off disk. `tests/test_no_god_key.py`
   enforces this.
2. **Run spec vs setup access.** The environment produces two things per system, split by *when* they're
   used: a **run spec** (objective + identity/inventory — the runtime info the agent acts on, handed to it
   via `build_config`) and a **`SetupAccess`** (scoped key + bastion routing — the setup-time info the
   plugin uses to stand the system up). The split is by purpose, not secrecy: credentials live in
   `SetupAccess` because that's where setup needs them, and a leaked scoped key only opens what that system
   could already reach (invariant 1).

A consequence: a non-environment plugin should be **backend-agnostic** — it consumes the neutral spec +
scoped access, and where it must act on the cloud it expresses intent the environment executes, rather
than parsing a backend's topology or branching on the backend.

**The runner-config contract (attacker + defender).** An attacker/defender plugin's `build_config()`
emits the dict its runner reads. Declare the keys the runner REQUIRES as
`REQUIRED_CONFIG_KEYS = frozenset({...})` on the plugin class (an un-annotated class attribute — the base
types it as a `ClassVar`, so it is not a pydantic field). The arena calls `validate_built_config()` right
after `build_config()` and fails the experiment early with a precise message if a key is missing (instead
of a `KeyError` deep in the run), and `tests/test_plugin_conformance.py` enforces it generically + pins the
per-plugin set in one data table. Declare only keys `build_config()` ALWAYS emits (not per-config-optional
ones, and not the arena-injected defender keys like `defender_env_spec`).

**Plugin self-containment.** Machinery used by *all* plugins of a type goes on the base class; machinery
used by a *subset* is **copied into each** plugin (not put on the base, which would foist it on plugins
that don't use it, and not shared via a cross-plugin helper module). The one exception is code shared by
standalone *runner scripts* (which can't inherit a base) — that stays a module, labelled as such.

**Plugin code paths.** A plugin that shells out to an external codebase (Incalmo, MHBench, the
Defense/Perry defender repo, Velociraptor, Sliver) needs that checkout's path set in
`config.yaml`. There is **one `*_dir` field per plugin** (plus an optional `*_python` override, defaulting
to `<its_dir>/.venv/bin/python`); **set only the paths for the plugins you use** — `mhbench_dir` is the one
always required (the environment backend). A plugin resolves its own path via `cfg.plugin_dir(self.code_dir_field)`
/ `cfg.plugin_python(...)`, where `code_dir_field`/`code_python_field` are ClassVars the plugin declares
(e.g. `llm_soc_dir`, `incalmo_llm_dir`). Redundancy is intentional: plugins sharing a repo (the two incalmo
attackers; the three Defense/Perry defenders) each name it, so no field silently backs several. See the
README's *Config reference* for the full table. (These still live in the top-level arena config; longer term
they belong in each plugin's own config — the way the environment-backend settings now live in the
environment layer: `arena/environment/config.py` owns `EnvBackendConfig`, loaded from config.yaml's
`env_backend:` section, and `ExperimentManagerConfig` no longer carries them.)

**Running the tests** (fast, cloud-free — run before committing):
```
pytest tests/
```
- `tests/test_arena_contract.py` — the 4-system contract (registration, config round-trip,
  `build_config`/`ui_schema` shapes) for the specific named baseline plugins.
- `tests/test_plugin_conformance.py` — registry-driven smoke tests: iterates EVERY registered plugin of
  each type and holds it to the shared base-class contract (instantiable, `ui_schema` well-formed,
  lifecycle methods present + right async-ness, `build_config` serializable + no credential leak). A new
  plugin is checked automatically; a failure names the plugin and lists every problem at once.
- `tests/test_attacker_lifecycle.py` — the attacker setup → ready → running → stopping → stopped handshake.
- `tests/test_defender_lifecycle.py` — the defender handshake + the `wait_until_ready` readiness-marker gate
  (returns on the marker, raises if the runner dies first or arming times out).
- `tests/test_no_god_key.py` — the scoped-key regression guard.

There are no cloud integration tests in pytest. End-to-end testing is opt-in and costs real cloud + LLM
credits — see `tests/README_live_smoke.md` (`run_experiment_smoke.py`, `run_dashboard_smoke.py`, and a
cheap no-cloud adapter probe). Run that before shipping a plugin that touches a real foothold.

## Layout

```
arena/
  main.py       the arena: the experiment lifecycle + admission/queueing
  config.py     ExperimentManagerConfig (paths, limits, backend selection)
  experiment/   the Experiment model + its persisted state
  environment/  environment plugin type (backend-neutral interface); plugins/mhbench/ is the MHBench backend
  attacker/     attacker plugin type + implementations
  defender/     defender plugin type + implementations
```

---

## Adding an ENVIRONMENT plugin

Deploys and tears down the network, sizes it for admission (so experiments can run in parallel), and
**produces everything the attacker and defender need to reach it**. Subclass `EnvironmentPlugin`
(`environment/plugins/base.py`) with a `config_type`.

The environment package ROOT is backend-neutral — it holds only the interface (`plugins/base.py`), the
config/models/lifecycle, the admission gate (`capacity.py:CapacityTracker`), and the `build_environment`
factory. A backend's whole implementation lives inside ITS plugin; MHBench is just one plugin, not the
environment interface.

Existing: `plugins/mhbench/` — the MHBench backend as a PACKAGE: `deployer.py` (provision/configure +
spec/access production), `capacity.py` (`count_vm_specs` topology sizing), `collect.py`/`rotate.py`/
`teardown.py`, and `mhbench.py` (the `EnvironmentPlugin` that delegates to them). Deploys a multi-host
MHBench topology (e.g. the Equifax-breach scenarios) on OpenStack (default) or GCP; issues the per-system
scoped keys during `configure` and produces the agent-facing specs + `SetupAccess`. The environment root
is backend-neutral: a second backend implements the same `EnvironmentPlugin` interface as its own plugin,
with no change to the arena.

**Lifecycle the arena drives:**
```python
async def capacity(self, experiment, cfg) -> list[tuple[int, int, int]]:   # (vcpus, ram_mb, disk_gb) per VM
async def provision(self, experiment, c2c_url, cfg, lc=None) -> tuple[DeployedEnvironment, mgmt_ip]:
    """Spin the network up. Emit DEPLOYING -> DEPLOYED (or FAILED) on `lc`."""
async def configure(self, experiment, mgmt_ip, c2c_url, cfg, lc=None) -> None:
    """Configure hosts. Emit CONFIGURING -> CONFIGURED. Issue the per-system scoped keys here."""
async def collect(self, experiment, cfg) -> None:          # pull host logs before teardown
async def teardown(self, experiment, cfg, lc=None) -> None: # tear the network down (reap stray VMs first)
```

**Spec production — you are the producer.** Keep the two audiences strictly separate:
```python
# RUN SPEC (objective + identity — the runtime info the agent acts on):
def attacker_spec(self, deployed, cfg) -> AttackerEnvSpec
def defender_spec(self, deployed, cfg) -> DefenderEnvSpec    # host inventory {name, ip, role}
# SETUP ACCESS (scoped key + bastion routing — used at setup time):
def attacker_setup_access(self, deployed, mgmt_ip, cfg) -> list[AttackerSetupAccess]
def defender_setup_access(self, deployed, mgmt_ip, cfg) -> list[DefenderSetupAccess]
```
**Symmetric specs.** `attacker/env_spec.py` and `defender/env_spec.py` MIRROR each other: the same parallel
type tree with identical fields — `AttackerUser`/`DefenderUser`, `AttackerHost`/`DefenderHost`,
`AttackerSubnet`/`DefenderSubnet`, `AttackerBox`/`DefenderBox`, `AttackerEnvSpec`/`DefenderEnvSpec`,
`AttackerSetupAccess`/`DefenderSetupAccess`. The ONLY difference is which fields the producer *populates*
(the info a system is entitled to know): the attacker gets just `objective` + its `box` (the foothold); the
defender gets `objective` + `box` (the defender box) + the estate (`hosts`/`subnets`). `AttackerEnvSpec`
also derives a `footholds` list (its `box` + any host it holds creds on) — see the two files' docstrings.

**Scoped credentials — the core security contract.** Issue a separate key per system, each scoped to only
that system's hosts; a leaked attacker key must open the foothold and nothing else:
```python
def attacker_credential(self, deployed, cfg) -> str   # foothold only
def defender_credential(self, deployed, cfg) -> str   # defender box + victims only
# the broad management/provisioning key stays internal to the deploy path — no accessor, never in a spec.
```
Stamp the scoped key + bastion routing into each `SetupAccess` you return (see `_bastion_proxy_args` and
how `mhbench.py` sets `ssh_key` + `ssh_common_args`).

**Infra guarantees every environment provides:**
```python
def defender_box(self, deployed, cfg) -> DefenderBox:
    """A bare, isolated box the defender runs on (own subnet), hidden from the attacker.
    The environment provides ONLY the bare box; the defender stands up its own ES/tooling."""
async def program_ingress(self, experiment, mgmt_ip, cfg, ingress) -> None:
    """Open EXACTLY the box ports the defender requested (from its box_ingress()); {} opens nothing.
    This also points the telemetry relay at the box (victim -> relay -> box:port)."""
def resolve_spec(self, cfg) -> str:
    """The resolved, canonical id of the environment to deploy (MHBench: the absolute topology path);
    the arena stamps it into DeployedEnvironment.topology_spec. Defaults to the raw environment_spec."""
def provides_defender_box(self, deployed, cfg) -> bool:
    """Whether a REAL defender box exists — the arena gates the env<->defender contract on this (a
    configured defender requires a box). Defaults to `defender_box(...) is not None`; MHBench overrides
    it to report the real isolated box only (not the mgmt-host fallback)."""
```
`program_ingress` defaults to a no-op, so a backend without a relay is still valid. The defender declares
the box port via `box_ingress()` and `program_ingress()` both opens it and routes the relay there — one
path (there is no separate `telemetry_ingest`/`program_telemetry`/`telemetry_relay_ip`).

---

## Adding an ATTACKER plugin

Runs an offensive agent from the foothold the environment provides. Subclass `AttackerPlugin`
(`attacker/plugins/base.py`) with a `config_type`.

Existing:
- `plugins/incalmo_strategy/` — Incalmo C2 attacker (sandcat agents beacon in from the victims) driven by a
  **fixed strategy** (`GraphSearch`, `Darkside`, …).
- `plugins/incalmo_llm/` — the same Incalmo C2 attacker driven by a **free-form LLM planning loop**
  (`planning_llm` + `abstraction`). These are two **separate, self-contained plugins** (one per folder): each
  carries its OWN copy of the Incalmo C2 lifecycle (`c2.py` / `foothold.py` / `aux/`), the same way the three
  Defense/Perry defenders each copy `box_es_install.sh`. Both point at the same Incalmo repo via their own
  code-path field (`incalmo_strategy_dir` / `incalmo_llm_dir`).
- `plugins/terminus/` — Terminus-2, Terminal-Bench 2.0's reference shell agent: an LLM driving a real
  shell in a read-terminal → think → type-command loop on the foothold.
- `plugins/cai/` — the CAI (Cybersecurity AI) framework's offensive agent, run on the foothold as a shell
  agent.
- `plugins/sliver/` — `sliver_llm`: the Sliver counterpart of `c2_llm` (bare LLM + `run_command` over a
  [Sliver](https://github.com/BishopFox/sliver) C2). Its own C2 lifecycle (`sliver_c2.py`); NOT
  live-validated.

**The interface:**
```python
class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    model: str = "..."          # pydantic config fields

    @classmethod
    def ui_schema(cls) -> PluginUISchema: ...

    def build_config(self, experiment_name, env_spec, c2c_url) -> dict:
        """Run config the agent reads. env_spec is the AttackerEnvSpec run spec (objective +
        foothold identity, no keys) — safe to serialize and hand the agent."""

    async def setup(self, experiment, cfg, mgmt_ip, access=None) -> PreparedAttacker:
        """Prepare the foothold. `access` is the SetupAccess list (setup-time key + routing). Reach the foothold with
        self.primary_access(access).ssh_base(). Return PreparedAttacker()."""

    async def start(self, prepared, config_path, experiment_name, cfg, c2c_url, agent_c2c_url=None, access=None):
        """Launch the attack process and return it without waiting. Return as soon as it's up — the base
        emits RUNNING after start(), STOPPING/STOPPED around stop(). Readiness is established in setup()."""

    async def stop(self, experiment, cfg, access=None) -> None: ...
    async def collect_logs(self, experiment, cfg, dest, access=None) -> None: ...   # optional
```

**Reaching the foothold.** In `setup()` turn the primary access into an ssh prefix; in
`start()`/`stop()`/`collect_logs()` the primary `SetupAccess` is handed to you directly (you never
persist/load it — the base's `run_*` wrappers do):
```python
base = self.primary_access(access).ssh_base()   # setup(): access is the SetupAccess list
base = access.ssh_base()                         # start()/stop()/collect_logs(): access is the one entry
```
`ssh_base()` returns a ready `ssh` prefix (scoped key + bastion ProxyCommand). Reach the foothold ONLY
through the `access` you're handed.

**Running a C2.** Do it in your own `setup()`: bring the C2 up, prep the foothold, block until an agent
beacons in before returning. There is no shared C2 base class — copy `plugins/incalmo_strategy/`'s shape (it
keeps `launch_c2c`/`wait_c2c_ready`/`wait_c2c_agent`/`stop_c2c` on itself, plus a `sweep_stale_state()` hook
to reap orphaned C2 tunnels on clean-slate). Set `requires_docker = True` only if the C2 runs as a Docker
container on the harness host (it gates an early preflight).

**Lifecycle.** The arena drives setup → ready → running → stopping → stopped and waits on each; you don't
emit these. Implement `setup`/`start`/`stop`; the base wraps them in `run_setup`/`run_start`/`run_stop`.
`start()` must return quickly with the launched process.

---

## Adding a DEFENDER plugin

Runs a defensive system: detection, deception, or active response. Optionally instruments the environment
in `setup()`, then ingests telemetry and executes actions during the run. Subclass `DefenderPlugin`
(`defender/plugins/base.py`) with a `config_type`.

Existing:
- `plugins/llm_soc/` — an LLM SOC that ingests env telemetry (Falco/Sysflow) from its per-experiment box
  ES and dispatches LLM agents to act (restore a host, block a C2 IP) in response.
- `plugins/canary/` — a lightweight checks-only defender for integration testing (no decoys, no LLM).
- `plugins/deception/` — a decoy/honeypot defender: deploys decoy VMs and plants honey-credentials
  (static + reactive strategies), reacting to box-ES telemetry. **In a separate repo that is not yet
  open-sourced.** Its decoy *deployment* path has known arena issues (see `DEPLOY_DECOY_ISSUE.md`) and
  ultimately wants a first-class "ask the environment for a decoy" capability rather than reaching into
  the cloud directly.
- `plugins/prompt_injection/` — AI-attacker-detection: deploys decoy hosts whose names are
  prompt-injection payloads aimed at an LLM attacker. Same not-yet-open-sourced status and same
  decoy-deployment caveats as `deception`.

**The interface:**
```python
class MyDefender(DefenderPlugin, config_type="my_defender"):
    type: Literal["my_defender"]
    strategy: str = "..."

    @classmethod
    def ui_schema(cls) -> PluginUISchema: ...

    def build_config(self, experiment_name, environment) -> dict:
        """Run config the runner reads. The arena injects `defender_env_spec` (agent-facing host
        inventory) and `defender_setup_access` (the setup-time scoped key + routing per victim + the box)."""

    async def run(self, config_path, experiment_name, cfg) -> asyncio.subprocess.Process:
        """Spawn the defender runner (the reactive loop) and return the process. External arming already
        ran in prepare(); a loop-armed strategy still writes the readiness marker once armed (see below)."""

    # optional:
    async def prepare(self, config_path, experiment_name, cfg) -> PreparedDefender:
        """EXTERNAL arming — run BEFORE run() and blocked on: stand up the box ES, and deploy decoys /
        plant honey-creds for a strategy that arms in setup. Return a PreparedDefender. Default: no-op."""
    def box_ingress(self) -> dict[str, list[int]]: ...   # ports the env should open to the box
    async def setup(self, experiment_name, environment, cfg, mgmt_ip=None) -> None: ...
    async def teardown(self, experiment_name, environment, cfg) -> None: ...
```

**Arming: prepare() then the marker.** A defender's arming splits in two, mirroring the attacker's
setup()→start():
- **EXTERNAL arming** (deploy decoy VMs, plant honey-creds/fake data) runs in **`prepare()`**, which the
  arena drives after `build_config()` and **before** `run()`, and **blocks on**. It runs to completion and
  returns a `PreparedDefender`; a failure raises there and fails the experiment, so the slow decoy deploy
  finishes before the attacker starts instead of racing it inside the loop. (On the Perry side this is
  `Strategy.ARMS_IN_SETUP` + `Defender.prepare()`.)
- **In-loop arming** (subscribing to telemetry; strategies that deploy reactively or whose placement can't
  leave the loop process — llm_soc, prompt_injection, Reactive*) stays in the run loop. For those, `run()`
  spawns the runner and the runner **must touch the readiness marker once actually armed**:
  ```python
  DefenderPlugin.ready_marker_path(experiment_name, cfg)   # touch from inside the runner once armed
  ```
  The arena blocks on `wait_until_ready` before letting the attacker in. If the runner crashes before
  writing it, the experiment fails — an undefended run must never be reported as defended.

**Reaching victims + the box.** The arena injects `defender_setup_access` (a `SetupAccess` list, scoped
key + routing per host) into your config; the runner reads its hosts and access from there — never resolve
a key or parse the topology yourself.

**Box ES (telemetry).** A telemetry-consuming defender stands up a per-experiment Elasticsearch on the
env-provided box and tunnels to it. The machinery (`prepare_box_es` + the tunnel helpers +
`box_es_install.sh`) is **copied into each telemetry defender** (`llm_soc`/`deception`/`prompt_injection`)
— it is per-plugin, not a base method, so `canary`/other defenders don't inherit it. Call it in
`prepare()` (before the external arming that reads the box ES); it injects `es_url` into the config the
runner reads.

**Box ingress — request exactly what you use:**
```python
def box_ingress(self):
    return {"telemetry": [9200],   # env relay routes sensor telemetry to box:9200
            "forward":   [8000]}   # victim -> mgmt -> box passthrough (server-mediated EDR clients)
```
A defender that needs nothing returns `{}` and opens nothing.
