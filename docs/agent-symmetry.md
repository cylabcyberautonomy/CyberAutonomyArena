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

## Parity map — the ACCURATE state (attacker base ~300 lines, defender ~545)

They are NOT "pretty much identical" and shouldn't be — the defender legitimately does more. Honest accounting:

**Byte-identical (shared machinery):** `__init_subclass__`, `_code_dir`, `_code_python`, `validate_built_config`,
the classvars (`_registry`/`REQUIRED_CONFIG_KEYS`/`code_dir_field`/`code_python_field`/`_ACCESS_FILE`);
`_lifecycle` differs by one string literal only; `build_config`/`ui_schema` same shape.

**Parallel (same name + role, structurally twin, only small/essential deltas):** `start`, `stop` (both
SIGTERM a pid — `experiment.pid` vs `experiment.defender_pid`), `teardown`, `collect_logs`/`run_collect_logs`,
`example_prepared`, `run_stop` (both now FAILED-guarded; differ only by signal enum + the defender's
runs_on_box access-load), `primary_access`/`_persist_access`/`_load_access` (attacker persists ONE foothold,
defender the LIST — box+victims), `run_start` (attacker emits RUNNING; defender doesn't — it's READY only
once armed).

**Truly irreducible defender-only (do NOT force identical):** `box_ingress`, `defender_vm_budget`, the
capability flags (`executes_from_box`/`runs_on_box`), and the box/C2-equivalent machinery
(`_launch_on_box`/`_wait_box_ready` ↔ the attacker's own C2 lifecycle). These have no attacker analog.

**Convergeable (design-artifact, not essential) — the parity-convergence slice:** earlier filed as
"essential," but on review these are just current data-flow and SHOULD converge:
- **access as a LIST on both — DONE** (attacker `_persist_access`/`_load_access` persist/load the list; run_*
  hand plugins their primary foothold, so existing plugins are unchanged; multi-foothold env supported).
- **opaque baton — DONE** (teammate, `53b1ef4`): `PreparedDefender` is now an empty marker exactly like
  `PreparedAttacker`; each telemetry defender carries its own subclass (`PreparedLLMSOC`/…) and bakes its
  fields in its OWN `build_config`; the base `run_setup` field-forwarding loop is gone. Attacker already
  matched (empty `PreparedAttacker` + C2 subclasses), so no attacker change.
- **fold `provision_box` → `setup()` — DONE** (teammate, `53b1ef4`): `provision_box()` is gone; defender
  `setup()` now stands up infra + returns the baton, and `run_setup` is a single `prepared = await setup()`
  → `build_config` → write → `prepare()`. Mirrors the attacker's `setup() -> Prepared` + `run_setup` shape.
- **fold `prepare()` → `setup()` — OPEN (decision pending).** `prepare()` is the external-arming step
  (deploy decoys / plant honey-creds). The teammate argues it's a defender-only capability with no attacker
  twin (leave it labeled, like `box_ingress`); I think there IS a partial twin (the attacker deploys its
  foothold agent + waits in `setup()`), so folding would be real convergence (`run_setup` becomes
  shape-identical) — but it costs a Defense-repo runner change (arming must read the spec/baton, not the
  written config) + a full live revalidation of all 5 defenders, for the last increment of symmetry. User
  to decide whether the symmetry is worth that cost.
- **`sweep_stale_state` on the defender** — add once box defenders can orphan state (uv-venvs/tunnels).

**Box-deferred:** the `setup()` *signature* still differs (defender `(experiment_name, cfg, bastion_ip,
defender_env_spec, defender_access, needs_agent)` vs attacker `(experiment, cfg, bastion_ip, access)`) —
aligning it touches every defender plugin, same cross-repo cost bucket as the `prepare()` fold; the
cred-injection in `run_setup` collapses with the box model (`runs_on_box` threads access instead).

So: slice 1 unified the shared machinery; slice 2 + the parity pass made the lifecycle surface parallel
(+ `run_stop` guard, `example_prepared` mirror, list-access); the baton + `provision_box`→`setup` fold are
now DONE (teammate). Remaining: the `prepare()` fold (user decision) + `setup()` signature alignment (cross-
repo). After those the defender stays modestly larger only for the truly-irreducible set above — correct.

## Full conversion (convert every defender to run on the box) — per-component live work

Investigating the real conversion surfaced that it spans **three** components, and several seams are
determined by live facts (box→victim routing, the box-facing mgmt address, what the bare box has
installed) that can't be derived offline. What's landed vs what's left:

**Landed (offline, tested):**
- arena base twins (slices 1–2), the `runs_on_box` scaffold (slice 3), and the token'd TCP channel
  keystone (slice 4): `serve_env_actions_tcp` + `handle_env_action(token, trusted_transport)` +
  `new_env_action_token()`. 110 tests green.

**arena repo — remaining (needs cloud):**
- `main.py`: when arming a `runs_on_box` defender, `new_env_action_token()` → `exp._env_action_token`,
  start `serve_env_actions_tcp` bound to the box-facing mgmt address for the serving window, and thread
  the token + TCP URL to the box runner (in the config it ships). For `runs_on_box`, set the config's
  `log_dir` to a box-side path and SKIP the cred-injection (TODO already marked in `run_setup`).
- `DefenderPlugin._launch_on_box` (live mechanics): scp the runner + config to the box and run it over
  `ssh -tt` (foreground, so the local pid proxies the remote — `stop()`'s local SIGTERM propagates);
  `_wait_box_ready` polls the box marker over ssh (the mirror of `wait_c2c_agent`), then bridges the
  local readiness marker so `main.py`'s `wait_until_ready` is untouched. Command construction is pure and
  can be unit-tested; the scp/ssh round-trips need a live box.

**MHBench env plugin — victim routing RESOLVED (no change needed); box-facing address still open:**
- `defender_setup_access` stamps **harness→bastion** ProxyCommand routing, and that **already works from
  the box** — EMPIRICALLY CONFIRMED by the canary-on-box live run (ssh 7/7 + resolve 7/7 reaching all
  original victims *from the box* via the existing ProxyCommand). So **no box-relative-routing change is
  needed**; a direct-hop (decoys are already direct) would be a mere optimization. This was the big open
  question for this side — now closed.
- Still open (and only for the active-response/control-plane path): expose the mgmt host's **box-facing
  address** so `main.py` can bind `serve_env_actions_tcp` to it — but per the reverse-tunnel decision
  (option 2, ssh -R), the harness *initiates* the tunnel, so this may not need a bound box-facing address
  at all. Settle it at the tunnel pairing.

**Defense repo — remaining (branch off its `arena-integration`; needs cloud):**
- `RemoteEnvOrchestrator`: POST env actions to the **TCP URL + `X-Arena-Token`** (from the shipped
  config) instead of the UDS, when box-resident.
- The deception / prompt_injection / velociraptor runners must run **on the box** (their deps present or
  vendored; telemetry box-local; victim actions via the box's scoped key). velociraptor's active response
  is via its own server, so it may not need the TCP channel at all — confirm live.

**Validation order (live, OpenStack, `equifax_small`):** `canary` first — **DONE, LIVE-VALIDATED**
(canary `runs_on_box=True`, GraphSearch attacker → Finished; `_launch_on_box` ship+ssh-tt launch,
credential-threading, `_wait_box_ready` marker-bridge, and `-tt` teardown all worked; box→victim routing
confirmed as above; telemetry gap reproduced identically = pre-existing, orthogonal). On
`feature/defender-box-uv-engine` (off `9ae812f`, +2 commits, 114 tests). Next: an active-response defender
(`llm_soc`, needs the Perry uv path + the reverse-tunnel) to exercise the TCP token channel; then the
Defense-repo defenders. The TCP boundary move still gets a security review before it is trusted.

## Corrections from the live decoy-deploy work (teammate, arena-integration)

Three facts from a peer live-debugging prompt_injection/deception that reshape the box plan:

1. **Cloud ops cannot move to the box → the model is HYBRID, which VALIDATES slice 4.** Even with the
   engine fully on the box, `AddHost`/`RebuildHost` have no cloud creds / god-key there, so they MUST keep
   routing to the arena env-action channel (that path is validated — FalcoLLM's RebuildHost works). So a
   box-resident defender does *host/victim actions natively on the box* but *cloud ops via the env channel*
   — which is exactly what slice 4's token'd TCP channel is for. The keystone is the right shape; it is not
   optional for active-response defenders, it is the only way their cloud ops work from the box.

2. **The box is Python 3.8; Perry needs 3.10+ → the full engine needs its own runtime on the box.** This is
   why the current box agent is *thin*. `_launch_on_box` has modes by runtime need: a stdlib-only runner
   (canary) runs directly under the box's `python3`; a Perry-based engine (llm_soc/deception/prompt_injection)
   needs a newer interpreter. BOTH attacker archetypes show how to get one onto an in-env box, so copy
   whichever fits:
     - **Docker image** (Incalmo `c2.py`): build on the harness, install docker live via apt, ship with
       `docker save | ssh 'docker load'`, run the container on the box.
     - **Self-installed `uv` venv** (Terminus `terminus.py`): `uv`-install a fresh interpreter + the engine
       into a venv on the box over SSH (needs the box's PyPI/astral egress, which it has) — **no Docker**.
   NOTE (correction): Incalmo is NOT "harness-only" — its C2 server runs ON the foothold (container);
   only its planner stays on the harness, over an `ssh -L` tunnel. Terminus runs fully on the foothold
   (brain + shell, via a uv venv). So both archetypes put code in-env; they differ in how much (Incalmo =
   infra on-box + brain on-harness = mirrors `executes_from_box`; Terminus = whole agent on-box = mirrors
   `runs_on_box`). The earlier "scp the runner" sketch only holds for the stdlib canary.

3. **Build on the env-side decoy-key fix (`e2046c2` on arena-integration), don't re-implement.** A mid-run
   `add_host` decoy carries only the broad mgmt key; the box uses the SCOPED defender key, so the env now
   injects the scoped pubkey into each decoy's `authorized_keys` (with a ~2min retry for fresh sshd). Also:
   add-host'd decoys are **directly reachable from the box** (`decoy:22` open; `new_host_setup_access` is a
   direct hop, not a bastion ProxyCommand) — so the box→decoy path is direct. (The original victims' access
   still carries the harness→bastion ProxyCommand; confirm whether in-env hosts are likewise directly
   reachable from the box when converting — the decoy evidence suggests they may be.)

   The thin box agent only wires BlockIP + ConfigureDecoy; AddFakeData/AddHoneyCredentials/StartHoneyService
   are unwired stubs — the full-engine-on-box path (this work) replaces that, so those don't need wiring
   into the thin agent.
