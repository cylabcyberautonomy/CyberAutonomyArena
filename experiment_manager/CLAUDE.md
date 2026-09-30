# experiment_manager — the arena

The arena runs cyber-range **experiments**. An experiment pairs four pluggable systems:

| System         | Role                                                           | Required? |
|----------------|----------------------------------------------------------------|-----------|
| **environment**| deploys the network the experiment runs on, sizes it, issues scoped access | yes |
| **attacker**   | the offensive agent, run from a foothold in that network       | yes |
| **defender**   | the defensive system (detection / deception / active response) | optional |
| **traffic**    | benign background activity on the victim hosts                 | optional |

The arena (`main.py`) drives each system through a fixed lifecycle and never reaches inside a plugin.
Swapping any system is choosing a different plugin — no arena change.

## How a plugin is selected and registered

Each plugin subclasses its system's base class and passes a `config_type`:

```python
class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    ...
```

The `config_type` registers the class in `AttackerPlugin._registry` (the same holds for Defender,
Environment, and Traffic). The plugins package imports every module under it on startup, so the class
registers itself. To add a plugin, drop a file in the right `plugins/` directory. There is no central
list to edit.

A user selects each system in the experiment spec:

```json
{
  "experiment_name": "demo",
  "environment": "environments/instrumented/equifax_small_instrumented.json",
  "attacker_plugin": "incalmo_strategy",
  "attacker_spec": {"strategy": "GraphSearch"},
  "defender":  {"type": "llm_soc", "strategy": "FalcoLLM"}
}
```

The shapes differ by system:
- **attacker** — a `(plugin, spec)` pair: `attacker_plugin` names the plugin, `attacker_spec` holds its
  fields as an inline dict or a path to a JSON/YAML file. This is the only attacker form.
- **environment** — the explicit `{environment_plugin, environment_spec}` shape (a bare path string
  coerces to the mhbench plugin).
- **defender** and **traffic** — the embedded `{type, ...}` form.

## Layout

```
experiment_manager/
  main.py            the arena: the experiment lifecycle + admission/queueing
  config.py          ExperimentManagerConfig (paths, limits, backend selection)
  experiment/        the Experiment model + its persisted state
  environment/       environment plugin type + the MHBench implementation   (see environment/CLAUDE.md)
  attacker/          attacker plugin type + implementations                  (see attacker/CLAUDE.md)
  defender/          defender plugin type + implementations                  (see defender/CLAUDE.md)
  traffic/           traffic plugin type (implementation pending)
```

## Two invariants every plugin must respect

1. No god key. The environment issues a scoped credential per system. The attacker key opens its
   foothold only; the defender key opens its box and victims only. A plugin gets that key from the
   injected `SetupAccess`. It must never read the broad management key off disk.
   `tests/test_no_god_key.py` enforces this.
2. Adversary-safe vs harness-only. The environment produces two things per system. The agent-facing
   spec holds the objective and identity, and is safe to hand the model. The harness-only `SetupAccess`
   holds the keys and bastion routing, and stays in trusted plugin code — it is never given to the agent.

## Running the tests

`tests/test_arena_contract.py` is the fast, cloud-free contract guard (plugin registration,
config round-trip, build_config shape). Run the whole suite before committing:

```
pytest tests/
```
