# Experiment lifecycle

The arena (`arena/main.py`) drives every experiment through a fixed sequence of stages,
calling each system only through its base-class interface. This page is the order of operations and the
one piece of cross-system timing that matters: the defender-readiness handshake.

## Stages

1. **Admission / capacity.** Before anything deploys, the arena asks the environment plugin for the
   experiment's VM footprint (`capacity()` → per-VM `(vcpus, ram_mb, disk_gb)`) and queues it against the
   configured caps (total VMs, CPUs, concurrent setups). A matchup larger than the cap still runs — alone
   — rather than deadlocking.

2. **Provision.** `environment.provision()` spins up the network (victims, the attacker's foothold, the
   bastion/management host, and — when a defender is present — an isolated defender box). Emits
   `DEPLOYING → DEPLOYED` (or `FAILED`).

3. **Configure.** `environment.configure()` configures the hosts and, crucially, **issues the per-system
   scoped credentials** (attacker key on the foothold, defender key on the box + victims) and injects
   them. Emits `CONFIGURING → CONFIGURED`. Any backend-specific post-step (e.g. MHBench log rotation for a
   clean ground-truth baseline) is internal to the plugin, not a lifecycle stage.

4. **Defender setup + arm** (only if a defender is present). The arena runs `defender.setup()`, opens the
   box ingress the defender declared via `box_ingress()` (`environment.program_ingress()`), then launches
   the defender via `defender.run()`. `run()` only *spawns* the defender; arming (standing up ES on the
   box, placing decoys / honey-credentials, initializing the detection loop) then takes minutes. **The
   arena blocks here** — see the handshake below.

5. **Attacker run.** The arena hands the attacker its agent-facing spec + `SetupAccess`, the attacker
   preps its own foothold, and the engagement runs under a wall-clock cap. On expiry the attacker is
   `SIGTERM`'d (then `SIGKILL`ed if it ignores that) and marked `TimedOut`.

6. **Collect.** `environment.collect()` pulls host-side logs (the scorer's ground truth) into the
   experiment's output tree *before* teardown. Best-effort and bounded.

7. **Teardown.** `defender.teardown()` (harness-side cleanup) runs first, then `environment.teardown()`
   reclaims all VMs/networks. Emits `TEARING_DOWN → TORN_DOWN`. Teardown is uncapped so a finished
   experiment releases its VMs immediately instead of queueing behind new provisions. Backend-specific
   stray-VM cleanup (e.g. sweeping decoy VMs before the network teardown) is the environment's job, done
   as the first step of its own teardown.

Terminal states: `Finished`, `Error`, `TimedOut`, `Blocked`. The environment emits its own signal stream
(`DEPLOYING/DEPLOYED/CONFIGURING/CONFIGURED/TEARING_DOWN/TORN_DOWN` + failed-with-reason) so the arena can
track and surface per-stage status.

## Defender readiness — armed in `setup()`

This is the one timing subtlety, and the defender handles it exactly the way the attacker does. A naive
`run()` returns as soon as its process exists — long before the defense is actually armed. Letting the
attacker in at that point was a real bug: on one measured run the defender took 3m45s to arm while the
attacker finished its whole chain in 1m38s, so the detection loop never executed once.

The fix mirrors the attacker: **all arming happens in `setup()`, which blocks until the defense is
actually armed** (stand up the box ES, deploy decoys, plant honey-creds; a box-resident defender
SSH-polls its own box). `run_setup` emits **READY only after `setup()` returns**, and the arena holds
the attacker behind that READY. There is no separate marker file and no `wait_until_ready` gate —
**`setup()` returning IS armed == READY**, the same contract as a C2 attacker that blocks on its first
agent beacon. If `setup()` raises, run_setup emits FAILED and the experiment fails rather than quietly
handing an undefended range to the attacker — an undefended run is never reported as defended.

## Where this lives

- Lifecycle signals: `arena/environment/lifecycle.py` (`EnvironmentSignal`).
- Defender lifecycle (SETUP_STARTED → READY → RUNNING → STOPPING → STOPPED, arming in `setup()`):
  `arena/defender/plugins/base.py` (`run_setup` / `run_start`), a mirror of `AttackerPlugin`.
- The driver that sequences all of it: `arena/main.py`.

See [plugins.md](plugins.md) for what each plugin must implement at each stage, and
[architecture.md](architecture.md) for the arena/plugin boundary.
