# Adding an environment plugin

An environment plugin deploys and tears down the network an experiment runs on. It also sizes that
network for submission (to allow for parallel experimentation), and produces everything the attacker and defender need to reach it.

To create an environment, create a Python file in `plugins/`. Initialize a class that is subclassed
under `EnvironmentPlugin` (`plugins/base.py`) with a `config_type`. 


Existing plugins:
- `plugins/mhbench.py` - <put a better description of MHBench here other than wraps the existing deployer>.

## Lifecycle the arena drives

```python
async def capacity(self, experiment, cfg) -> list[tuple[int, int, int]]:
    """(vcpus, ram_mb, disk_gb) per VM, for the admission/capacity tracker."""

async def provision(self, experiment, c2c_url, cfg, lc=None) -> tuple[DeployedEnvironment, mgmt_ip]:
    """Spin the network up. Emit DEPLOYING -> DEPLOYED (or FAILED) on `lc`."""

async def configure(self, experiment, mgmt_ip, c2c_url, cfg, lc=None) -> None:
    """Configure hosts. Emit CONFIGURING -> CONFIGURED. Issue the per-system scoped keys here."""

async def collect(self, experiment, cfg) -> None:   # pull host logs before teardown
async def teardown(self, experiment, cfg, lc=None) -> None:   # tear the network down
```

## Spec production — you are the producer

The arena asks the environment for each system's specs. Keep the two kinds strictly separate:

```python
# ADVERSARY-SAFE (objective + identity, intended to hand the agent):
def attacker_spec(self, deployed, cfg): ...      -> AttackerEnvSpec
def defender_spec(self, deployed, cfg): ...      -> DefenderEnvSpec

# HARNESS-ONLY (scoped key + bastion routing):
def attacker_setup_access(self, deployed, mgmt_ip, cfg): ...   -> list[SetupAccess]
def defender_setup_access(self, deployed, mgmt_ip, cfg): ...   -> list[SetupAccess]
```

## Scoped credentials — the core security contract

The environment must issue a separate key per system. Each key is scoped to only that system's hosts.
A leaked attacker key must open the foothold and nothing else.

```python
def attacker_credential(self, deployed, cfg) -> str:   # foothold only
def defender_credential(self, deployed, cfg) -> str:   # defender box + victims only
# the broad management/provisioning key stays internal to the plugin's deploy path — no accessor,
# and it is never placed in any SetupAccess.
```

Stamp the scoped key + bastion routing into each `SetupAccess` you return (see `_bastion_proxy_args`
and how `mhbench.py` sets `ssh_key` + `ssh_common_args`). `tests/test_no_god_key.py` guards the
consuming side.

## Infra guarantees every environment provides

```python
def defender_box(self, deployed, cfg) -> DefenderBox:
    """A bare, isolated box the defender runs on (own subnet), hidden from the attacker.
    The environment provides ONLY the bare box; the defender stands up its own ES/tooling."""

async def program_ingress(self, experiment, mgmt_ip, cfg, ingress) -> None:
    """Open EXACTLY the box ports the defender requested (from its box_ingress()); {} opens nothing.
    This is also what points the telemetry relay at the box (victim -> relay -> box:port)."""
```

`program_ingress` defaults to a no-op, so a backend without a relay/forwarder is still valid. The defender
declares the box port it needs via `box_ingress()`, and `program_ingress()` both opens it and routes the
relay there — one path. (There is no `telemetry_ingest`/`program_telemetry`/`telemetry_relay_ip`: in box
mode the environment's relay provisioning points victim sensors at the relay, so the defender never needs
a relay address.)

## Selection

The environment is selected with the explicit `{plugin, spec}` shape. `environment_spec` is the
topology path:

```json
{"environment_plugin": "mhbench",
 "environment_spec": "environments/instrumented/equifax_small_instrumented.json"}
```

A bare path string coerces to `{environment_plugin: mhbench, environment_spec: <path>}`.

The attacker uses the same `plugin` + `spec` idea (`attacker_plugin` + `attacker_spec`, where the spec
is an inline dict or a path) — see `attacker/CLAUDE.md`. The defender and traffic are selected by the
embedded `{type, ...}` form.

## Register and verify

Add a contract test in `tests/test_arena_contract.py`. Assert the class is in the registry and that
`ui_schema` is well-formed. Then run `pytest tests/`.
