# Adding a defender plugin

A defender plugin runs a defensive system against the attack: detection, deception, or active
response. It first instruments the environment in a setup stage, and
then can ingest telemetry and actively execute actions on the environment during the running stage.

To create a defender, create a Python file in `plugins/`. Initialize a class that is subclassed under
`DefenderPlugin` (`plugins/base.py`) with a `config_type`.

Existing plugins:
- `plugins/incalmo/` — a C2-based agent (runs a C2 container, agents beacon in). <I actually want to create a real C2 based agent, and have incalmo be like... the incalmo work>
- `plugins/terminus/` - shell-based agent <insert description of terminus2 here>
- `plugins/cai/` — shell-based agent <insert relevant description of CAI agent here>

Existing:
- `plugins/llm_soc/` — an LLM SOC that ingests telemetry instrumented on the environment (Falco/Sysflow). Can dispatch agents to execute actions in response to that telemetry.
- `plugins/deception/` - <insert description of the deception plugin here, also I haven't open sourced this repo so let's make a note that needs to be open sourced, and also like it doesn't really work in this model because it requires deploying decoys which is something it needs to request of the environment service though we could add that in right?>
- `plugins/prompt_injection/` - <insert description of the prompt injection plugin here, also haven't open sourced this repository for the same reasons as the above>
- `plugins/canary/` — a lightweight checks-only defender for integration testing.

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

## The readiness marker — required

`run()` only spawns the runner. Arming (decoys, fake data, detection loop init) then takes minutes.
The arena blocks on `wait_until_ready` before it lets the attacker in. So the runner must create the
marker file once it is actually armed:

```python
DefenderPlugin.ready_marker_path(experiment_name, cfg)   # touch this from inside the runner
```

Without the marker, the attacker could finish before the defense exists. If the runner crashes before
it writes the marker, the experiment fails — an undefended run must not be reported as defended.

## Reaching victims and the defender box

The arena injects `defender_setup_access` into your config — a list of `SetupAccess`, each with a
scoped key and bastion routing. The runner reads its hosts and access from there. Do not resolve an
MHBench key or parse the topology for credentials yourself; `tests/test_no_god_key.py` enforces this.

To read telemetry, reuse the base class method `prepare_box_es(...)`. It stands up a per-experiment
Elasticsearch on the env-provided defender box and opens a tunnel to it for setup access.

## Box ingress — request exactly what you use

The environment gives the defender a bare, isolated box, and opens zero ports to it by default. To
open a port, return it from `box_ingress()`:

```python
def box_ingress(self):
    return {"telemetry": [9200],   # env relay routes sensor telemetry to box:9200
            "forward":   [8000]}   # victim -> mgmt -> box passthrough (server-mediated EDR clients)
```

The harness opens exactly these at arm. A defender that needs nothing returns `{}` and opens nothing.

## Selecting this plugin

Pick the plugin in the experiment spec with the embedded form:

```json
"defender": {"type": "my_defender", "strategy": "..."}
```

`config_type` is what `type` matches on. The defender has no separate plugin+spec-file form — that
shape exists only for the environment and the attacker.

## Register and verify

Add a contract test in `tests/test_arena_contract.py`. Assert the class is in the registry and that
`build_config` carries what the runner reads. Then run `pytest tests/`.
