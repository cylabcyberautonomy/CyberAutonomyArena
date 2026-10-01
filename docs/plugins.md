# Adding a plugin

Every swappable system is a plugin. This page is the cross-cutting mechanics shared by all four types;
the per-type specifics live in the `CLAUDE.md` of each package:

- `experiment_manager/environment/CLAUDE.md`
- `experiment_manager/attacker/CLAUDE.md`
- `experiment_manager/defender/CLAUDE.md`
- (traffic: implementation pending)

## The shape of a plugin

Create a Python file in the system's `plugins/` directory and define a class that subclasses the system's
base and passes a `config_type`:

```python
class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    # ... pydantic config fields ...
```

The `config_type` registers the class in that base's `_registry`. The plugins package imports every module
under it on startup, so simply dropping the file in makes the plugin discoverable — **there is no central
list to edit**.

## How each type is selected

| System       | Selection shape in the experiment spec |
|--------------|----------------------------------------|
| environment  | `{"environment_plugin": "...", "environment_spec": "..."}` (a bare path string coerces to `mhbench`) |
| attacker     | `"attacker_plugin": "..."` + `"attacker_spec": <inline dict \| path to a JSON/YAML file>` |
| defender     | `"defender": {"type": "...", ...}` |
| traffic      | `"traffic": {"type": "...", ...}` |

The attacker's pair form is deliberate: the plugin and its spec are separate, and the spec may be inline
for quick runs or a file for anything substantial. The environment uses an explicit `{plugin, spec}`;
defender and traffic use the embedded `{type, ...}`.

## The two invariants every plugin must respect

These are the load-bearing rules (full rationale in [security-model.md](security-model.md)):

1. **No god key.** The environment issues a *scoped* credential per system (attacker key → its foothold
   only; defender key → its box + victims only). A plugin gets its key from the injected `SetupAccess`
   and must **never** read the broad management key off disk. `tests/test_no_god_key.py` enforces this.
2. **Adversary-safe vs harness-only.** The environment produces an agent-facing spec (objective +
   identity/inventory — safe to hand the model) and a harness-only `SetupAccess` (keys + routing — stays
   in trusted plugin code). Anything with a credential or a route is setup-facing and never reaches the
   agent.

A consequence worth internalizing: a non-environment plugin should be **backend-agnostic**. It consumes
the neutral spec + scoped access and, where it needs to act on the cloud (restore a host, open a port),
expresses intent that the environment executes — it does not branch on the backend or parse a specific
topology format.

## Plugin-design conventions

- **Each plugin is self-contained.** Shared machinery used by *all* plugins of a type goes on the base
  class; machinery used by a *subset* is **copied into each** plugin rather than put on the base (which
  would foist it on plugins that don't use it) or shared via a cross-plugin helper module. The one
  unavoidable exception is code shared by standalone *runner scripts* (which can't inherit a base) — that
  stays a module and is labelled as such.
- **Declare only what you use.** A defender opens exactly the box ports it needs via `box_ingress()`
  (`{}` opens nothing); an environment opens exactly those.

## Register and verify

Add a case to `tests/test_arena_contract.py` — the fast, cloud-free contract guard. Assert the class is in
its registry, its `ui_schema()` is well-formed, and (for defender/attacker) that `build_config`/the spec
carries what the runner reads. Then run the whole suite:

```
pytest tests/
```

`tests/test_arena_contract.py` is the cheap guard for the 4-system contract; `tests/test_no_god_key.py`
is the scoped-credential tripwire. Both must stay green.
