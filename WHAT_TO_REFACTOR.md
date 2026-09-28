# What to refactor

How the experiment harness today differs from the target arena design: four independent
system types (environment, defender, attacker, background traffic), each with start/stop
inputs, a spec from the user, a spec from the arena, and its own status outputs.

Baseline for this doc is the `arena-refactor` branch (the live `gcp-backend` work +
`bg-traffic`'s traffic and Velociraptor commits).

## System by system

| | Target design | Harness today |
|---|---|---|
| **Environment** | A system type with interchangeable implementations (MHBench, RangeFactory, ...). Inputs: start, stop, environment spec. Outputs: statuses, plus separate attacker-relevant and defender-relevant specs. | **Not a plugin.** `experiment_manager/environment/deployer.py` directly runs MHBench's CLI (`cli.py provision`, `cli.py configure`) from `cfg.mhbench_dir` and reads `environments/<spec>.json`. Adding RangeFactory means rewriting this module. |
| **Environment output to others** | A filtered spec for the attacker and another for the defender | One `DeployedEnvironment` for everyone: the path to MHBench's raw topology JSON, the Kali IP (found by scanning the file for `vm_type == "kali_running"`), and the environment name. No filtering: the defender sees the whole topology, attacker subnet included. |
| **Defender inputs** | The defender's environment spec (from the arena) plus the defender spec (from the user) | The MHBench topology path plus `mgmt_ip`. Each runner parses MHBench JSON itself: `defender/plugins/topology.py` builds Perry's network from it and hardcodes user accounts per MHBench `vm_type`. The LLM SOC runner also calls `openstack.connect()` and reads Elasticsearch directly. |
| **Defender telemetry output** | The defender sends its telemetry requirements (source channel, destination, protocol) to the environment | Doesn't exist. Telemetry is chosen by picking an `*_instrumented` environment, and the LLM SOC runner can install Falco itself (`InstallFalco`). |
| **Attacker** | Attacker environment spec in, statuses out | The attacker's setup reruns MHBench's configure with `--attacker-play` to prepare Kali, so the attacker is tied to MHBench too. It gets the environment name and the Kali IP. |
| **Traffic** | Environment spec in; deploying / deployed / running / stopping / stopped out | Reads MHBench's topology file and MHBench's SSH key directly, and runs Ansible from MHBench's venv through the bastion. Only one traffic plugin per experiment (`traffic: Optional[TrafficConfig]`), so generators can't be mixed. Only `caldera_human` exists (no GHOSTS, no Rockfish). |

## Status signals

The target design gives each system its own status outputs. The harness has one status for
the whole experiment (`ExperimentStatus`): Queued, Deploying, Deployed, Configuring,
Configured, Running, Retrying, Error, Finished, TimedOut, Blocked. Environment states are
folded into it.

| System | Signals today |
|---|---|
| Defender | Only "ready": a marker file (`defender/defender_ready`) plus a check that its process is alive. No started / running / stopping / stopped. |
| Attacker | "Ready" means `setup()` returned (the C2 agent has checked in). The attacker process's exit code is the verdict. |
| Traffic | None. Lifecycle methods return or raise. |
| Environment | No tearing-down or torn-down status. Teardown is best-effort and not reported. |

## Things the harness has that the target design should keep

1. **Provision and configure as separate steps.** The harness holds separate deploy and
   configure slots to limit load, and the defender's host has to be set up between the two.
2. **Collect logs.** Environment, attacker and traffic each pull their logs before teardown.
   Scoring depends on it; every system needs a collect input.
3. **Log rotation** just before the attack, so setup noise is cleared.
4. **Failure outputs.** Every system needs a "failed (with reason)" signal. The harness
   distinguishes Error, Retrying, TimedOut (wall-clock cap) and Blocked (LLM refusal).
5. **Readiness gating.** The attacker starts only after the defender reports ready. That is
   the arena's job and should be drawn in the design.

## Where to start

Make the environment a real plugin type, like the other three: provision, configure, collect
and teardown, plus an output that produces the attacker's and the defender's specs. Most of the
MHBench coupling elsewhere exists because nothing gives the other systems a neutral
description of the environment, so they read MHBench files directly.

## Regression guard

`tests/test_arena_contract.py` locks the cross-component contract in place so a refactor of one
system can't silently break what the others read from it. See that file's docstring for what it
asserts and how to run it (fast, no cloud), plus the opt-in live smoke test.
