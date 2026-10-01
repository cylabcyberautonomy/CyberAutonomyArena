# Sliver C2 backend — design

Status: **design only, not implemented.** Grounds a second C2-based attacker that drives
[Sliver](https://github.com/BishopFox/sliver) instead of Incalmo's sandcat/Caldera C2, so the benchmark
can compare one LLM loop across two real C2 frameworks. It mirrors the existing Incalmo integration and
the arena contract — only the C2 *implementation* changes, not the lifecycle or the LLM loop.

## Why not reuse `_IncalmoAttacker`

`c2_llm` subclasses `_IncalmoAttacker` because it reuses Incalmo's exact C2 (same `c2.py`, same sandcat
implant, same HTTP API). Sliver has its own server, implant, and operator API, so it needs a **parallel
lifecycle** (`sliver_c2.py`), its own plugin, and its own runner. Everything *above* the C2 — the arena
contract, the opaque baton, the shape of the LLM loop — is shared by pattern, not by inheritance.

## Component placement

| Component | What it is | Where it runs |
|---|---|---|
| `sliver-server` daemon | the C2 server + operator gRPC API (default :31337) | the foothold |
| C2 listener (mTLS) | where implants beacon/session in (e.g. :8443) | the foothold |
| implant | Sliver-generated binary; sessions back to the listener | foothold (initial), then victims |
| operator client (`sliver-py`) | what the runner drives the C2 through | the runner, on the harness host |

Server on the **foothold** (recommended) keeps all attacker infra on one in-env IP a defender can block
— the same rationale as the current "C2 on the foothold" model. (Harness-host is the alternative.)

## Lifecycle: `sliver_c2.py` (same interface shape as `c2.py`)

`setup_c2(experiment_name, cfg, foothold_access, mgmt_ip) -> (sentinel, operator_cfg, listener_addr)`,
all over the foothold `SetupAccess` (scoped key + bastion routing — no management key off disk):

1. **Install** `sliver-server` on the foothold itself — `sliver_c2` downloads the release binary and
   sets it up (self-contained, exactly like `c2.py` apt-installs Docker). No baked dependency: a clean
   foothold image is enough. (Idempotent: skip the download if it's already present from a prior run.)
2. **Start** the `sliver-server` daemon (operator gRPC up on the foothold).
3. **Tunnel**: open an `ssh -L` from the harness to the foothold's gRPC port, on a dynamically chosen
   local port — the exact pattern (and the one-integer setup→start handoff) from `c2.py`.
4. **Operator config**: `sliver-server operator --name op --lhost <foothold> --save <path>`; pull the
   `.cfg` back to the harness. It carries the client mTLS certs — **harness-only**, like `SetupAccess`,
   never handed to the agent.
5. Via `sliver-py` (through the tunnel): **start an mTLS listener** on the foothold and **generate a
   session-mode implant** targeting it.
6. **Deliver + run** the implant on the foothold; **wait** for its session to register (readiness gate).
7. Return the sentinel (`sliver-c2:<exp>`), the operator-config path (+ tunnel local URL) for the runner,
   and the listener address (victim-facing) for lateral delivery.

`teardown_c2(experiment_name)`: kill the tunnel, stop the daemon/listener on the foothold, drop state —
**keyed by experiment_name** (statefile), identical to `c2.py`. No `c2c_container_id`.

## Plugin: `SliverLLMAttacker(AttackerPlugin, config_type="sliver_llm")`

Its *own* C2 lifecycle (not `_IncalmoAttacker`'s), but the same arena contract:

- `setup()`: preflight → `sliver_c2.setup_c2` → wait for session → return an opaque
  `SliverPreparedC2(PreparedAttacker)` carrying `operator_cfg` + `listener_addr` (the baton).
- `build_config(experiment_name, env_spec, prepared)`: `{operator_cfg, listener_addr, model, api_base,
  max_turns, objective}` — read off its *own* baton; the arena never inspects it.
- `run(prepared, config_path, experiment_name, cfg)`: launch `sliver_llm_runner.py` under a venv that has
  `sliver-py` + `openai`.
- `stop_c2c(experiment_name)` → `sliver_c2.teardown_c2`. `requires_docker = False` (Sliver is a single
  binary — the setup-concurrency gate keys on this, so Sliver setups run ungated unless we opt in).

## Runner: `sliver_llm_runner.py`

The same LLM loop as `c2_llm_runner.py` — only the C2 **client** swaps:

| Primitive | `c2_llm` (Incalmo HTTP) | `sliver_llm` (sliver-py) |
|---|---|---|
| connect | base URL | `SliverClientConfig.parse_config_file(cfg)` → `SliverClient.connect()` |
| list agents | `GET /agents` | `client.sessions()` (+ `beacons()`) |
| run command | `POST /send_command` | `interact_session(id).execute(cmd, args)` |

One tool exposed to the model — `run_command(session_id, command)` — plus `finish`. **Session mode**
(interactive) over beacons, so each LLM turn gets a prompt result instead of waiting for a check-in.

## Networking (two paths — mirrors the Incalmo work)

- **implant → listener**: victims session to the foothold's listener port. Needs the env's deploy-time
  firewall to admit the victim subnets to the foothold on that port — the same parity the env agent added
  for Incalmo's `:8888`, just Sliver's port. **Coordinate the port with the env agent.**
- **operator gRPC → runner**: the harness reaches the server over the `ssh -L` tunnel through the bastion
  (foothold has no floating IP) — the `c2.py` dynamic-local-port pattern.
- **mTLS** throughout; the operator config holds the client certs and stays harness-only.

## Decisions

- **Provisioning — self-contained.** `sliver_c2` installs `sliver-server` on the foothold at setup
  (downloads the release binary); no baked image dependency. See lifecycle step 1.
- **Server location — foothold.** All attacker infra on one in-env IP a defender can block.
- **Implant mode — sessions** (interactive, low-latency per LLM turn). Beacons (async check-in,
  stealthier) are a later toggle for studying stealth against a live-connection-watching defender.
- **Lateral movement (v1) — the LLM does it via `run_command`:** exploit the next host, fetch the
  implant from the foothold, run it → a new session. Keeps it a *bare* LLM+C2 (one primitive, like the
  shell agents). Wiring Sliver's native lateral tooling as dedicated tools is a later, less-bare option.
- **Runner venv — dedicated.** A `sliver_python`/`sliver_dir` venv on the harness host with `sliver-py`
  + `openai`, isolated from Incalmo's deps. A preflight builds it if missing (mirrors Incalmo's venv
  check + `deception_python`). Config-pointed, like `incalmo_python`.

## Build phases (once approved + Sliver available)

1. `sliver_c2.py` setup/teardown — the infra; the biggest piece; needs live validation.
2. `SliverLLMAttacker` plugin — small; unit-testable via the contract test.
3. `sliver_llm_runner.py` — the sliver-py loop; needs live validation.
4. Listener-port firewall — coordinate with the env agent.
5. Live smoke — a `gcp_beacon`-style run with `sliver_llm`.

## Fit with the arena contract

- Opaque baton: `SliverPreparedC2(PreparedAttacker)` carries operator-config + listener; `build_config`
  reads its own baton; the arena stays oblivious (the refactor already removed all C2-casing).
- Teardown by `experiment_name`; no persisted C2 handle.
- No god key: foothold reached via `SetupAccess`; operator config harness-only.
