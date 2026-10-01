# The arena (experiment_manager)

The arena runs cyber-range **experiments**. An experiment pairs four pluggable systems:

| System          | Role                                                              | Required? |
|-----------------|------------------------------------------------------------------|-----------|
| **environment** | deploys the network the experiment runs on, sizes it, issues scoped access, produces the agent-facing specs | yes |
| **attacker**    | the offensive agent, run from a foothold in that network         | yes |
| **defender**    | the defensive system (detection / deception / active response)   | optional |
| **traffic**     | benign background activity on the victim hosts                   | optional |

The arena (`experiment_manager/main.py`) drives each system through a fixed lifecycle and **never reaches
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
- **environment** — the explicit `{environment_plugin, environment_spec}` (a bare path string coerces to
  the `mhbench` plugin).
- **defender** / **traffic** — the embedded `{type, ...}` form.

**Two invariants every plugin must respect** (full rationale in `docs/security-model.md`):
1. **No god key.** The environment issues a scoped credential per system — the attacker key opens its
   foothold only, the defender key its box + victims only. A plugin gets its key from the injected
   `SetupAccess` and must **never** read the broad management key off disk. `tests/test_no_god_key.py`
   enforces this.
2. **Adversary-safe vs harness-only.** The environment produces an **agent-facing spec** (objective +
   identity/inventory — safe to hand the model) and a **harness-only `SetupAccess`** (scoped key + bastion
   routing — stays in trusted plugin code, never given to an agent).

A consequence: a non-environment plugin should be **backend-agnostic** — it consumes the neutral spec +
scoped access, and where it must act on the cloud it expresses intent the environment executes, rather
than parsing a backend's topology or branching on the backend.

**Plugin self-containment.** Machinery used by *all* plugins of a type goes on the base class; machinery
used by a *subset* is **copied into each** plugin (not put on the base, which would foist it on plugins
that don't use it, and not shared via a cross-plugin helper module). The one exception is code shared by
standalone *runner scripts* (which can't inherit a base) — that stays a module, labelled as such.

**Running the tests** (fast, cloud-free — run before committing):
```
pytest tests/
```
- `tests/test_arena_contract.py` — the 4-system contract (registration, config round-trip,
  `build_config`/`ui_schema` shapes).
- `tests/test_attacker_lifecycle.py` — the setup → ready → running → stopping → stopped handshake.
- `tests/test_no_god_key.py` — the scoped-key regression guard.

There are no cloud integration tests in pytest. End-to-end testing is opt-in and costs real cloud + LLM
credits — see `tests/README_live_smoke.md` (`run_experiment_smoke.py`, `run_dashboard_smoke.py`, and a
cheap no-cloud adapter probe). Run that before shipping a plugin that touches a real foothold.

## Layout

```
experiment_manager/
  main.py       the arena: the experiment lifecycle + admission/queueing
  config.py     ExperimentManagerConfig (paths, limits, backend selection)
  experiment/   the Experiment model + its persisted state
  environment/  environment plugin type (backend-neutral interface); plugins/mhbench/ is the MHBench backend
  attacker/     attacker plugin type + implementations
  defender/     defender plugin type + implementations
  traffic/      traffic plugin type + caldera_human
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
# ADVERSARY-SAFE (objective + identity, intended for the agent):
def attacker_spec(self, deployed, cfg) -> AttackerEnvSpec
def defender_spec(self, deployed, cfg) -> DefenderEnvSpec    # host inventory {name, ip, role}
# HARNESS-ONLY (scoped key + bastion routing):
def attacker_setup_access(self, deployed, mgmt_ip, cfg) -> list[SetupAccess]
def defender_setup_access(self, deployed, mgmt_ip, cfg) -> list[SetupAccess]
```

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
- `plugins/incalmo/` — C2-based attackers (sandcat agents beacon in from the victims). Three
  `config_type`s share its C2 lifecycle (`_IncalmoAttacker`): `incalmo_strategy` (fixed strategies —
  GraphSearch, …), `incalmo_llm` (Incalmo's free-form LLM planning loop), and `c2_llm` (a BARE LLM given
  the raw C2 — a minimal run-command loop, no Incalmo framework; the C2 analog of the shell agents).
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
        """Run config the agent reads. env_spec is the ADVERSARY-SAFE AttackerEnvSpec (objective +
        foothold identity, no keys) — safe to serialize and hand the agent."""

    async def setup(self, experiment, cfg, mgmt_ip, access=None) -> PreparedAttacker:
        """Prepare the foothold. `access` is the harness-only SetupAccess list. Reach the foothold with
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
beacons in before returning. There is no shared C2 base class — copy `plugins/incalmo/`'s shape (it keeps
`launch_c2c`/`wait_c2c_ready`/`wait_c2c_agent`/`stop_c2c` on itself). Set `requires_docker = True` only if
the C2 runs as a Docker container on the harness host (it gates an early preflight).

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
        inventory) and `defender_setup_access` (harness-only scoped key + routing per victim + the box)."""

    async def run(self, config_path, experiment_name, cfg) -> asyncio.subprocess.Process:
        """Spawn the defender runner and return the process. It MUST write the readiness marker once
        armed (see below)."""

    # optional:
    def box_ingress(self) -> dict[str, list[int]]: ...   # ports the env should open to the box
    async def setup(self, experiment_name, environment, cfg, mgmt_ip=None) -> None: ...
    async def teardown(self, experiment_name, environment, cfg) -> None: ...
```

**The readiness marker — required.** `run()` only spawns the runner; arming (decoys, fake data, detection
loop init) then takes minutes. The arena blocks on `wait_until_ready` before letting the attacker in, so
the runner must touch the marker once actually armed:
```python
DefenderPlugin.ready_marker_path(experiment_name, cfg)   # touch from inside the runner once armed
```
If the runner crashes before writing it, the experiment fails — an undefended run must never be reported
as defended.

**Reaching victims + the box.** The arena injects `defender_setup_access` (a `SetupAccess` list, scoped
key + routing per host) into your config; the runner reads its hosts and access from there — never resolve
a key or parse the topology yourself.

**Box ES (telemetry).** A telemetry-consuming defender stands up a per-experiment Elasticsearch on the
env-provided box and tunnels to it. The machinery (`prepare_box_es` + the tunnel helpers +
`box_es_install.sh`) is **copied into each telemetry defender** (`llm_soc`/`deception`/`prompt_injection`)
— it is per-plugin, not a base method, so `canary`/other defenders don't inherit it. Call it in `run()`;
it injects `es_url` into the config the runner reads.

**Box ingress — request exactly what you use:**
```python
def box_ingress(self):
    return {"telemetry": [9200],   # env relay routes sensor telemetry to box:9200
            "forward":   [8000]}   # victim -> mgmt -> box passthrough (server-mediated EDR clients)
```
A defender that needs nothing returns `{}` and opens nothing.

---

## Adding a TRAFFIC plugin

Generates benign background activity on the victim hosts so the attacker's actions aren't the only thing
in the telemetry. Subclass `TrafficPlugin` (`traffic/plugins/base.py`) with a `config_type`;
`plugins/caldera_human/` is the working reference to copy. The full extension guide is pending while the
interface settles — follow the same registration + selection pattern as the other systems.
