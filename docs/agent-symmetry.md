# Attacker / Defender base symmetry

**Goal.** Make `arena/attacker/plugins/base.py` and `arena/defender/plugins/base.py` read as **mirror
twins** — the same method set, the same parameters, the same bodies wherever behavior is the same —
the way `attacker/env_spec.py` and `defender/env_spec.py` already mirror each other. **Not** a shared
superclass (the two stay self-contained, per the repo's plugin self-containment rule); the duplication
is intentional and the point is that the files look identical side by side, so the *real* differences
are the only things that stand out.

## Why they diverge today (all one root cause)

The attacker and defender are both **agents the arena launches into the environment**. They differ in
the knowledge the environment grants them (attacker: its foothold only; defender: the estate) and in
their objective. Everything else that currently differs in the two base classes traces to **one**
decision: *where the agent's long-running process runs and who launches/waits on it.*

| Concern | Attacker today | Defender today | Essential? |
|---|---|---|---|
| Long-running in-process state | the **C2 daemon** | the telemetry subscription + reactive loop | no — both have it |
| Who launches it | `setup()` launches the C2, blocks until ready (`wait_c2c_ready`/`wait_c2c_agent`) | the arena spawns `run()` fire-and-forget | no — mechanism |
| Readiness | synchronous in `setup()` (poll the C2 for a beacon) | async marker file, polled by `wait_until_ready` | no — same "poll until armed" |
| Where the process runs | on its **foothold** (launched over SSH) | on the **harness host**, reaching in | no — a locus choice |
| Credentials | setup-time key, **persisted** + reloaded for `start`/`stop`/`collect` | **injected into the runner config** (it reaches in during the run) | no — follows the locus |
| Stop / collect | plugin `stop()`/`collect_logs()` (may kill remote procs) | inlined arena helper `_stop_defender_process` | no — follows the locus |
| **Control-plane actions** | none — the attacker only acts *inside* the network it compromised | restore (rebuild), BlockIP (SG), deploy-decoy (new VM) = **cloud control plane** | **YES** |

Only the last row is an essential, threat-model-level difference: a defender legitimately commands the
infrastructure, an adversary must not. Everything above it is a consequence of the defender running as
an arena-spawned process on the harness instead of as a setup-launched agent on a foothold like the
attacker.

## Target end state

Both bases expose the **same surface**, in the same order, with identical shared bodies:

```
# ClassVars (mirrored)
_registry  REQUIRED_CONFIG_KEYS  code_dir_field/code_python_field
__init_subclass__                                   # identical (cls._registry)

# ===== PLUGIN SURFACE =====
build_config(experiment_name, env_spec, prepared)   # identical signature
ui_schema()                                         # identical
setup(experiment, cfg, bastion_ip, access) -> Prepared     # launches the agent's long-running process
                                                           #   on its foothold/box, blocks until ready
start(prepared, config_path, experiment_name, cfg, access) -> Process   # launches the run/act client
stop(experiment, cfg, access)                       # default: SIGTERM the local pid (identical body)
collect_logs(experiment, cfg, dest, access)         # pull agent-side logs
teardown(experiment_name, cfg)                      # release host-side resources (C2 / box)
sweep_stale_state(cfg)                              # reap orphaned global state on clean-slate
example_prepared()                                  # filled baton for offline build_config tests
_code_dir / _code_python                            # identical
primary_access(access)                              # the agent's primary foothold/box entry

# ===== FRAMEWORK (do NOT override) =====
validate_built_config(built)                        # identical
_access_path / _persist_access / _load_access        # identical (both persist their primary access)
_lifecycle(experiment)                              # near-identical (one literal differs: the lifecycle attr)
run_setup / run_start / run_stop / run_collect_logs  # identical shapes; emit this agent's signals
```

The **only** members that stay defender-specific are its *capabilities* — the things the environment
grants it that an attacker never gets:

- `box_ingress()` / `defender_vm_budget()` — infra the env opens/reserves for it.
- **control-plane access** — a scoped, token'd channel to ask the environment for restore / BlockIP /
  decoy. (The attacker has no such channel.) See the security note below.

These live behind clearly-labelled "DEFENDER CAPABILITY" banners so the twin structure is unbroken.

## Slices

1. **Base skeleton (safe, no behavior change). — DONE (97 tests green).** Made the already-shared members
   byte-identical: `__init_subclass__` via `cls._registry`, and `_lifecycle` kept as a near-identical
   staticmethod differing only by the one literal (the lifecycle attr — the real difference, shown in
   place; the `_lifecycle_attr` classvar idea was dropped as indirection that only relocated the
   difference). `validate_built_config` / `_code_dir` / `_code_python` were already identical. Arena-facing
   signatures unchanged ⇒ no `main.py` change.
2. **Symmetric lifecycle surface. — STOP-PATH + run_start DONE (99 tests green).**
   - Done: defender now has `start` (default → `run()`), `stop` (default SIGTERM `experiment.defender_pid`,
     a new field mirroring the attacker's `pid`), `run_start` (mirrors `run_attacker`’s wrapper), and
     `run_stop` (emits STOPPING/STOPPED around `stop()`, guarded against a prior FAILED). `run_defender`
     is now a thin mirror of `run_attacker` (both call `plugin.run_start`). `main.py`’s free-function
     `_stop_defender_process` now just drives `defender.run_stop` + reaps the process. Behavior preserved;
     defender still on harness.
   - Remaining: `collect_logs`/`run_collect_logs` mirrors (no caller until box logs exist — slice 3);
     `sweep_stale_state`/`example_prepared` surface mirrors; aligning `setup`/`run_setup` to the attacker's
     `(experiment, cfg, bastion_ip, access)` convention — this one is folded into slice 3, since `setup()`
     changes substantially when it starts launching the box process.
3. **Defender on the box. — SCAFFOLDED (opt-in `runs_on_box`, default False; 103 tests green).**
   `setup()`/`run_start` launch the defender process **on the box** over SSH and block until it reports
   ready — the readiness marker becomes the in-`setup()` poll (the defender's `wait_c2c_agent`). Telemetry
   becomes box-local; victim actions use the box's scoped key threaded at launch (not injected into the
   config); `prepare()`/`wait_until_ready` collapse into `setup()`.
   - Scaffolded (inert until a plugin sets `runs_on_box=True`): the `runs_on_box` capability flag; `start()`
     routes to `_launch_on_box` when set; scoped-access recovery (`primary_access` + `_persist_access`/
     `_load_access`, persisting the *list* — box + victims) threaded through `run_start`/`run_stop`/
     `run_collect_logs`; `run_setup` persists the access when `runs_on_box`; `collect_logs`/`run_collect_logs`
     mirrors added. Tests cover the routing, the default-unchanged path, the access round-trip, and the stub.
   - Stubs to fill in with live validation: `_launch_on_box` (ship + SSH-launch the runner on the box, like
     the attacker's C2 bring-up) and `_wait_box_ready` (poll the box for armed — the mirror of
     `wait_c2c_agent`). Also the `setup`/`run_setup` signature alignment deferred from slice 2, and dropping
     the config cred-injection for `runs_on_box` defenders (TODO marked at the injection site).
   - **Nuance (honest):** the Incalmo attacker's *planner* actually runs on the harness and reaches victims
     via its C2 — so the credential symmetry is really "scoped access **threaded at launch** vs **injected
     into a persistent config**," which this scaffold delivers; the box is where in-env execution, box-local
     telemetry, and control-plane isolation (slice 4) naturally live.
4. **Control-plane as a capability.** A box-resident defender that needs restore/BlockIP/decoy reaches
   the environment over a **token'd TCP** channel (the box-agent pattern), not the harness UDS.

   > **Security boundary.** `env_action_server.py` is a UDS *on purpose*: "the transport IS the boundary,
   > so there is deliberately NO token … a move to TCP would require restoring a token." Moving the
   > defender in-env means restoring that token and exposing the channel to the (isolated,
   > attacker-invisible) box subnet only. This slice needs live validation and a security review.
   > Reusable prior art: branch `feature/env-defender-interface` (UDS+token dynamic env channel).

Slices 1–2 are behavior-preserving and land first. 3–4 touch the security boundary and the cloud, and
need live validation (OpenStack; GCP has the known Falco/driver limits).
