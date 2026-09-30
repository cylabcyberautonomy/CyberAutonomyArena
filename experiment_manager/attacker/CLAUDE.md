# Adding an attacker plugin

An attacker plugin runs an offensive agent from an attacker foothold the environment provides. The
agent runs as a process, and its exit code is the verdict.

To create an attacker, create a Python file in `plugins/`. Initialize a class that is subclassed under
`AttackerPlugin` (`plugins/base.py`) with a `config_type`. The plugins package imports every file
under it on startup, so the class registers itself. There is no list to edit.

Existing plugins to copy from:
- `plugins/incalmo/` — a C2-based agent (runs a C2 container, agents beacon in). The complex case.
- `plugins/terminus/`, `plugins/cai/` — pure shell agents (no C2): install a tool on the foothold,
  push a runner, launch it. **Start here for a new shell/LLM agent.**

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
        """Prepare the foothold. `access` is the harness-only SetupAccess (scoped key + bastion
        routing) — persist it with self.persist_primary_access(...) so start()/stop() can recover it.
        Return PreparedAttacker() (with C2 urls if you run one)."""

    async def start(self, prepared, config_path, experiment_name, cfg, c2c_url, agent_c2c_url=None):
        """Launch the attack process and return it. Exit code = verdict."""

    async def stop(self, experiment, cfg) -> None: ...          # kill the process(es)
    async def collect_logs(self, experiment, cfg, dest) -> None: ...   # optional
```

The `launch_c2c`, `wait_c2c_ready`, `wait_c2c_agent`, and `stop_c2c` methods are only for C2-based
attackers. A shell agent leaves them at their no-op defaults. Set `requires_docker = True` (a ClassVar)
only if `setup()` needs a local Docker daemon for a C2 container. Leave it off if Docker runs on the
foothold instead.

## Reaching the foothold

The arena passes `setup()` a list of `SetupAccess` objects. Each one holds a scoped key and the
routing to reach one foothold. Use them to reach the foothold:

```python
base = self.persist_primary_access(experiment_name, cfg, access).ssh_base()  # in setup()
# later, in start()/stop() (which only get experiment_name):
base = self.load_primary_access(experiment_name, cfg).ssh_base()
```

`ssh_base()` returns a ready-to-run `ssh` prefix (the scoped key plus the bastion ProxyCommand).

Do not read a key off disk. Reading a key path (`cfg.*.ssh_key_path`, `~/.ssh/id_ed25519`) re-arms the
god key, and `tests/test_no_god_key.py` will fail. Keys live only in SetupAccess, which stays in
trusted plugin code. The `env_spec` you get in `build_config` is adversary-safe and carries none.

## Lifecycle

The arena drives the agent through setup → ready → running → stopping → stopped, and waits for each
step. You do not emit these yourself. Implement `setup`, `start`, and `stop`; the base class wraps them
in `run_setup` / `run_start` / `run_stop`, which emit the signals. `start()` must return quickly with
the launched process — readiness is established in `setup()`, not `start()`.

## Register and verify

Add a contract test next to the others in `tests/test_arena_contract.py`. Assert the class is in the
registry and that `build_config` carries what the runner reads. Then run `pytest tests/`.
