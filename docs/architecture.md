# Architecture

The arena runs cyber-range **experiments**: an offensive agent attacks a victim network, optionally
against a defensive system, with optional benign background traffic. It is built so that each of those
roles is a **swappable plugin** behind a fixed contract — you change the matchup by choosing different
plugins, never by changing the arena.

## The four systems

An experiment pairs four pluggable systems. Two are required, two optional:

| System          | Role                                                              | Required? |
|-----------------|------------------------------------------------------------------|-----------|
| **environment** | deploys the network the experiment runs on, sizes it for admission, issues scoped access, produces the agent-facing specs | yes |
| **attacker**    | the offensive agent, run from a foothold the environment provides | yes |
| **defender**    | the defensive system — detection, deception, and/or active response | optional |
| **traffic**     | benign background activity on the victim hosts                    | optional |

Each is a plugin: a class that subclasses its system's base (`EnvironmentPlugin` / `AttackerPlugin` /
`DefenderPlugin` / `TrafficPlugin`) and registers itself with a `config_type`. See the repo-root
`CLAUDE.md` (one section per system) for how to write one.

## The arena vs. the plugins

`arena/main.py` is **the arena**. It owns the experiment lifecycle, admission/queueing, and
the status stream — and it drives each system *only* through its base-class interface. It never reaches
inside a plugin, and no plugin reaches into the arena. That boundary is the whole design: the arena is
backend-agnostic, and a plugin is free to be as backend-specific as it needs, as long as it honours the
contract.

A concrete illustration: the environment may *know* it's running on OpenStack vs GCP and act on that; the
**defender may not** — it receives a neutral host inventory + scoped access and expresses *intent*
("restore host X", "block IP Y"), and the environment executes it in its own terms.

## How a matchup is specified

A matchup is a spec naming one plugin per system. The selection *shapes* differ by system (see the
repo-root `CLAUDE.md` for the exact form):

- **environment** — `{environment_plugin, environment_spec}` (a bare topology path coerces to the mhbench
  plugin).
- **attacker** — a `(plugin, spec)` pair: `attacker_plugin` + `attacker_spec` (an inline dict *or* a path
  to a JSON/YAML file). This is the only attacker form.
- **defender** / **traffic** — the embedded `{type, ...}` form.

```json
{
  "experiment_name": "demo",
  "environment": "environments/instrumented/equifax_small_instrumented.json",
  "attacker_plugin": "incalmo_strategy",
  "attacker_spec": {"strategy": "GraphSearch"},
  "defender": {"type": "llm_soc", "strategy": "FalcoLLM"}
}
```

## The environment is the producer

The environment is the source of truth for everything the other systems need to reach the network. For
each system it produces **two** things, split by audience — a distinction enforced throughout:

- an **agent-facing spec** (objective + identity/inventory), safe to hand the model; and
- a **harness-only `SetupAccess`** (scoped key + bastion routing), used only by trusted plugin setup
  code and never given to an agent.

This is what lets the attacker and defender be written against neutral specs instead of parsing a
particular backend's topology.

## Lifecycle, in one line

`capacity → provision → configure → (defender arm) → attacker run → collect → teardown`, with a
readiness handshake gating the attacker on the defender being armed. See
[lifecycle.md](lifecycle.md) for the full flow and the handshake, [plugins.md](plugins.md) for how to add
a plugin of each type, and [security-model.md](security-model.md) for the no-god-key and
agent-safe-vs-harness-only invariants that the whole design rests on.

## Backends

The environment plugin owns the cloud backend. `mhbench` is the environment plugin; it deploys an
MHBench topology and supports OpenStack (default) and GCP. The environment package root holds only the
backend-neutral interface + the arena-facing machinery, so a second backend is added as its own
`EnvironmentPlugin` under `plugins/` — with no change to the arena or the interface.
