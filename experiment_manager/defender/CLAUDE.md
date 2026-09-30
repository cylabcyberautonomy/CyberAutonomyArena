# Adding a defender plugin

A defender plugin runs a defensive system against the attack: detection, deception, active response.
It **arms** (places decoys, plants honey data, starts its detection loop), then reacts while the
attacker runs. Subclass `DefenderPlugin` (`plugins/base.py`) with a `config_type`, drop the file under
`plugins/<name>/`, and it self-registers.

Existing plugins to copy from:
- `plugins/llm_soc/` — an LLM SOC reading telemetry (Falco/sysflow) from the defender box's ES.
- `plugins/deception/`, `plugins/prompt_injection/` — decoy/honey-credential strategies.
- `plugins/canary/` — a lightweight checks-only defender (a good minimal template).

## The interface

```python
class MyDefender(DefenderPlugin, config_type="my_defender"):
    type: Literal["my_defender"]
    strategy: str = "..."       # plugin-specific config fields (pydantic)

    @classmethod
    def ui_schema(cls) -> PluginUISchema: ...

    def build_config(self, experiment_name, environment) -> dict:
        """The run config the runner process reads. The arena then injects `defender_env_spec`
        (agent-facing: host inventory at the defender's knowledge level) and `defender_setup_access`
        (harness-only: scoped key + bastion routing per victim + the box) into this dict."""

    async def run(self, config_path, experiment_name, cfg) -> asyncio.subprocess.Process:
        """Spawn the defender runner and return the process. It must write the readiness marker
        (ready_marker_path) once armed — see below."""

    # optional:
    def box_ingress(self) -> dict[str, list[int]]: ...   # ports the env should open to the box
    async def setup(self, experiment_name, environment, cfg, mgmt_ip=None) -> None: ...
    async def teardown(self, experiment_name, environment, cfg) -> None: ...
```

## The readiness handshake — required

`run()` only *spawns* the runner; arming (decoys, fake data, detection loop init) takes minutes. The
arena blocks on `wait_until_ready` before letting the attacker in, so **the runner must create the
marker file when it is actually armed**:

```python
DefenderPlugin.ready_marker_path(experiment_name, cfg)   # touch this from inside the runner
```

Without it, the attacker could finish before the defense exists. A runner that crashes before the
marker fails the experiment (correct — an undefended run must not be reported as defended).

## Reaching victims + the defender box — the golden rule

The arena injects `defender_setup_access` (a `list[SetupAccess]`, scoped key + bastion routing) into
your config. The runner reads hosts + access from there — **never** resolve an MHBench key or parse
the topology for credentials yourself (`tests/test_no_god_key.py` enforces this). The base class
`prepare_box_es(...)` stands up per-experiment Elasticsearch on the env-provided defender box and
tunnels to it — reuse it rather than pointing at a shared ES.

## Box ingress — request exactly what you use

The environment gives the defender a **bare, isolated box** and opens **zero** ports to it by default.
Declare what you need from `box_ingress()`:

```python
def box_ingress(self):
    return {"telemetry": [9200],   # env relay routes sensor telemetry to box:9200
            "forward":   [8000]}   # victim -> mgmt -> box passthrough (server-mediated EDR clients)
```

The harness opens exactly these at arm. A defender that needs nothing returns `{}` and opens nothing.

## Register + verify

Add a contract test in `tests/test_arena_contract.py` (registry + `build_config`), then `pytest tests/`.
