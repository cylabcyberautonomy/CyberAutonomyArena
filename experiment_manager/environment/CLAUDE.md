# Adding an environment plugin

An environment plugin deploys and tears down the network an experiment runs on, sizes it for
admission, and **produces everything the attacker and defender need to reach it**. Subclass
`EnvironmentPlugin` (`plugins/base.py`) with a `config_type`, drop the file under `plugins/<name>/`,
and it self-registers.

The reference implementation is `plugins/mhbench.py` (wraps the external MHBench deployer). A second
backend (e.g. Ludus) implements the same interface.

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
# ADVERSARY-SAFE (objective + identity, safe to hand the agent):
def attacker_spec(self, deployed, cfg): ...      -> AttackerEnvSpec
def defender_spec(self, deployed, cfg): ...      -> DefenderEnvSpec

# HARNESS-ONLY (scoped key + bastion routing; NEVER given to an agent):
def attacker_setup_access(self, deployed, mgmt_ip, cfg): ...   -> list[SetupAccess]
def defender_setup_access(self, deployed, mgmt_ip, cfg): ...   -> list[SetupAccess]
```

## Scoped credentials — the core security contract

The environment must issue a **separate key per system**, each scoped to only that system's hosts.
A leaked attacker key must open the foothold **and nothing else** — east-west `ssh root@victim` is not
something the attacker may get for free.

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

def telemetry_ingest(self, deployed, cfg) -> TelemetryIngest:
    """The fixed relay endpoint sensors bake to (constant per backend so it can be baked in)."""

async def program_telemetry(self, deployed, cfg, routes) -> None:   # deliver streams to consumers
async def program_ingress(self, experiment, mgmt_ip, cfg, ingress) -> None:
    """Open EXACTLY the box ports the defender requested (from its box_ingress()); {} opens nothing."""
```

`program_telemetry` / `program_ingress` default to no-ops, so a backend without a relay is still valid.

## Selection

The environment uses the explicit shape (not the embedded `type` selector the other systems use):

```json
{"environment_plugin": "mhbench",
 "environment_spec": "environments/instrumented/equifax_small_instrumented.json"}
```

A bare path string coerces to `{environment_plugin: mhbench, environment_spec: <path>}`.

## Register + verify

Add a contract test in `tests/test_arena_contract.py` (registry + `ui_schema`), then `pytest tests/`.
