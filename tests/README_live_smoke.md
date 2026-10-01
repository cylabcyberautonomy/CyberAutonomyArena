# Live smoke test (opt-in, real cloud + LLM credits)

The fast contract test (`test_arena_contract.py`) proves the four systems still fit together
without deploying anything. This is the occasional full end-to-end check: it actually deploys a
range, runs the attacker, runs a defender, and asserts real outcomes. Run it deliberately, not
in CI.

## The baseline combo

| System | Choice | Why |
| --- | --- | --- |
| environment | `equifax_small` | fast; same `.10` DB key-holder structure as medium/large |
| attacker | `incalmo_strategy` / `GraphSearch` | deterministic strategy, no attacker-LLM refusal risk |
| defender | `llm_soc` / `FalcoLLM` | reads telemetry, deploys **no** decoys (decoy defenders are tightly coupled to MHBench) |

Note: `equifax_small` is not instrumented. FalcoLLM needs Falco telemetry, so for the defender
half either use `equifax_small_instrumented`, or rely on the llm_soc runner's own `InstallFalco`
step. For a pure attacker-reaches-DB check, the environment choice above is enough.

## Connectivity-only run (cheap, no LLM)

Before spending credits on FalcoLLM, prove the defender-side plumbing works with the **canary
defender** (`defender: canary`) — a diagnostic that SSHes to every victim through the bastion,
checks model-name vs OS-hostname resolution, confirms this run's `falco-<exp>`/`sysflow-<exp>`
indices exist, and reads `/etc/shadow` on a victim to confirm the event reaches the telemetry
store. It deploys no decoys and calls no LLM. Its report lands at
`output/<exp>/defender/connectivity_report.json`.

```bash
python3 tests/run_experiment_smoke.py --defender canary --environment environments/instrumented/equifax_small_instrumented.json --yes
```

If the canary passes, a real telemetry defender can connect on that environment.

## ⚠ Before you run

- A manager's **startup clean-slate wipes the OpenStack cloud (all projects)**. Do NOT start a
  second OpenStack manager against the shared cluster to run this — it will delete the live
  batch's VMs. Either use the already-running manager, or run on a cloud/tenant nobody else is
  using.
- This spends real LLM credits (the FalcoLLM defender) and real cluster time (~an hour).

## Run it against an already-running manager

Use the script — it submits, polls to a terminal state, and checks the pass criteria below:

```bash
python3 tests/run_experiment_smoke.py --yes                    # named combo, teardown on
python3 tests/run_experiment_smoke.py --defender none --keep --yes   # attacker-only, leave range up
python3 tests/run_experiment_smoke.py --delete-only --name smoke_arena_contract  # clean up
```

Key flags: `--url` (default `http://localhost:8000`), `--environment`, `--attacker` (Incalmo
strategy), `--defender` (llm_soc strategy or `none`), `--traffic` (persona or `none`), `--keep`,
`--overwrite`, `--timeout`, `--output-root`. `--yes` skips the confirmation prompt.

Or by hand:

The attacker is a `(plugin, spec)` pair: `attacker_plugin` selects the plugin and `attacker_spec`
holds its bespoke fields, either inline as a dict or as a path to a JSON/YAML file.

```bash
# write the attacker spec to a file, then reference it by path
echo '{"strategy": "GraphSearch"}' > /tmp/atk_spec.json

curl -sS -X POST http://localhost:8000/experiments \
  -H 'content-type: application/json' \
  -d '{
        "experiment_name": "smoke_arena_contract",
        "environment": "environments/instrumented/equifax_small_instrumented.json",
        "attacker_plugin": "incalmo_strategy",
        "attacker_spec": "/tmp/atk_spec.json",
        "defender":  {"type": "llm_soc", "strategy": "FalcoLLM"},
        "teardown": true,
        "priority": 1000
      }'
curl -sS http://localhost:8000/experiments/smoke_arena_contract | python3 -m json.tool
```

## Pass criteria

1. Status reaches `Finished` (not `Error` / `TimedOut` / `Blocked`).
2. Attacker reached the DB tier: the attacker output records lateral movement past webserver0
   and at least one exfiltrated data file — this is the regression the blacklist fix protects
   (a blacklisted `.10` webserver0 gives 0 files).
3. Defender armed: `output/<exp>/defender/defender_ready` was created and the defender log shows
   telemetry being read (FalcoLLM issuing at least one LLM call, or an explicit "no alerts"
   heartbeat).
4. Logs collected before teardown: `output/<exp>/environment/<host>/` holds each victim's
   `audit.log` / `syslog`.

## After a refactor

Run `test_arena_contract.py` first (fast). Only when it is green, run this once to confirm the
live path still works end to end.
