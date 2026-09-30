# Adding an attacker plugin

An attacker plugin runs an offensive agent from a **foothold** the environment provides, and its
process **exit code is the verdict**. Subclass `AttackerPlugin` (`plugins/base.py`) with a
`config_type`, drop the file under `plugins/<name>/`, and it self-registers.

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

`launch_c2c` / `wait_c2c_ready` / `wait_c2c_agent` / `stop_c2c` are only for C2-based attackers; a
shell agent leaves them at their no-op defaults. Set `requires_docker = True` (ClassVar) only if
`setup()` needs a **local** Docker daemon (a C2 container) — not if Docker runs on the foothold.

## Reaching the foothold — the golden rule

The arena passes `setup()` a `list[SetupAccess]` (the scoped, env-issued credential + routing). Use it:

```python
base = self.persist_primary_access(experiment_name, cfg, access).ssh_base()  # in setup()
# later, in start()/stop() (which only get experiment_name):
base = self.load_primary_access(experiment_name, cfg).ssh_base()
```

`ssh_base()` is a ready-to-run `ssh` prefix (scoped key + bastion ProxyCommand). **Never** read a key
path off disk (`cfg.*.ssh_key_path`, `~/.ssh/id_ed25519`) — that re-arms the god key and
`tests/test_no_god_key.py` will fail. `build_config`'s `env_spec` is adversary-safe by design; keys
live only in SetupAccess, which stays in trusted plugin code.

## Lifecycle handshake

The arena drives setup → ready → running → stopping → stopped and waits for each signal. You get this
for free: implement `setup`/`start`/`stop`; the base's `run_setup`/`run_start`/`run_stop` emit the
signals around them. `start()` must return promptly with the launched process (readiness is
established in `setup()`).

## Register + verify

Add a contract test beside the others in `tests/test_arena_contract.py` (assert it's in the registry
and `build_config` carries what the runner reads), then `pytest tests/`.
