# Adding an attacker plugin

An attacker plugin runs an offensive agent from an attacker foothold the environment provides.

To create an attacker, create a Python file in `plugins/`. Initialize a class that is subclassed under
`AttackerPlugin` (`plugins/base.py`) with a `config_type`. 

Existing plugins:
- `plugins/incalmo/` — the Incalmo integration: an LLM attacker that runs a C2 (sandcat agents beacon
  in from the victims) and drives it either through fixed strategies (GraphSearch, ...) or a free-form
  LLM planning loop. Subclasses `C2AttackerPlugin`.
- `plugins/terminus/` — Terminus-2, Terminal-Bench 2.0's reference shell agent (from the `harbor`
  framework): an LLM that drives a real shell in a read-terminal → think → type-command loop, run on
  the foothold.
- `plugins/cai/` — the CAI (Cybersecurity AI) framework's offensive agent, installed and run on the
  foothold as a shell agent.

## The interface

```python
class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    model: str = "..."          # plugin-specific config fields (pydantic)

    @classmethod
    def ui_schema(cls) -> PluginUISchema: ...        # dashboard form (see ui_schema.py)

    def build_config(self, experiment_name, env_spec, c2c_url) -> dict:
        """The run config the agent process reads. env_spec is the ADVERSARY-SAFE AttackerEnvSpec
        (objective + foothold identity — no keys). Safe to serialize and hand to the agent."""

    async def setup(self, experiment, cfg, mgmt_ip, access=None) -> PreparedAttacker:
        """Prepare the foothold. `access` is a list of harness-only SetupAccess (scoped key + bastion
        routing). Reach the foothold with self.primary_access(access).ssh_base(). Return
        PreparedAttacker()."""

    async def start(self, prepared, config_path, experiment_name, cfg, c2c_url, agent_c2c_url=None, access=None):
        """Launch the attack process and return it, without waiting for it to finish. You do not emit
        lifecycle signals here: the base emits RUNNING right after start() returns, STOPPING/STOPPED
        around stop(). So return as soon as the process is up."""

    async def stop(self, experiment, cfg, access=None) -> None: ...          # kill the process(es)

    async def collect_logs(self, experiment, cfg, dest, access=None) -> None: ...   # optional
```

## Running a C2

If your attacker needs a command-and-control server, subclass `C2AttackerPlugin` (in `plugins/base.py`)
instead of `AttackerPlugin`. It adds the C2 hooks — `launch_c2c`, `wait_c2c_ready`, `wait_c2c_agent`,
`stop_c2c` — and a `setup()` that brings the C2 up, preps the foothold, and waits for an agent to beacon
in. Set `requires_docker = True` on your subclass only if the C2 runs as a Docker container on the
harness host. Shell and LLM agents that need no C2 subclass `AttackerPlugin` directly and write their
own `setup()`. See `plugins/incalmo/` for the C2 case.

## Reaching the foothold

The arena passes `setup()` a list of `SetupAccess` objects. Each one holds a scoped key and the
routing to reach one foothold. In `setup()`, take the primary one and turn it into an `ssh` prefix:

```python
base = self.primary_access(access).ssh_base()   # in setup(): access is the SetupAccess list
```

In `start()`, `stop()`, and `collect_logs()`, the primary `SetupAccess` is handed to you as `access`
directly — you never persist or load it:

```python
base = access.ssh_base()                         # in start()/stop()/collect_logs()
```

`run_setup()` persists the access, and the `run_start` / `run_stop` / `run_collect_logs` wrappers load
it and pass it in. `ssh_base()` returns a ready-to-run `ssh` prefix (the scoped key plus the bastion
ProxyCommand).

Do not read a key off disk — reach the foothold only through the `access` you're handed.
`tests/test_no_god_key.py` enforces this.

## Lifecycle

The arena drives the agent through setup → ready → running → stopping → stopped, and waits for each
step. You do not emit these yourself. Implement `setup`, `start`, and `stop`; the base class wraps them
in `run_setup` / `run_start` / `run_stop`, which emit the signals. `start()` must return quickly with
the launched process — readiness is established in `setup()`, not `start()`.

## Register and verify

Add a contract test next to the others in `tests/test_arena_contract.py`. Assert the class is in the
registry and that `build_config` carries what the runner reads. Then run `pytest tests/`.

`pytest tests/` is fast and cloud-free. It covers three things:
- `test_arena_contract.py` — the four-system contract: registration, config round-trip,
  `build_config` / `ui_schema` shapes.
- `test_attacker_lifecycle.py` — the setup → ready → running → stopping → stopped handshake.
- `test_no_god_key.py` — the scoped-key regression guard.

There are no cloud integration tests in pytest. End-to-end testing is opt-in and costs real cloud and
LLM credits — see `tests/README_live_smoke.md`, which drives a full run against a live manager
(`run_experiment_smoke.py`), a dashboard smoke (`run_dashboard_smoke.py`), and a cheap no-cloud adapter
probe (`probe_terminus_adapter.py`). Run that before shipping a plugin that touches a real foothold.
