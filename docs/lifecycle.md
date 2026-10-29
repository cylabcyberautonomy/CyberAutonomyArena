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
   scoped credentials** (attacker key on the foothold, defender key on the box + victims, and — only
   when the experiment runs traffic — a traffic key on the victims) and injects them. Emits `CONFIGURING → CONFIGURED`. Any backend-specific post-step (e.g. MHBench log rotation for a
   clean ground-truth baseline) is internal to the plugin, not a lifecycle stage.

4. **Traffic setup + warm-up** (only if traffic is present). `traffic.setup()` installs and starts the
   generators on the victims and blocks until they are verified active; it emits READY, then RUNNING. The
   arena then waits `warmup_seconds` before arming the defender, so the defender never sees the environment
   without traffic. Traffic is a steady process with no phases (`persona_traffic` fires activities as a
   Poisson process at each persona's `events_per_hour`), so it can start and stop at any time and every
   window of the run carries the same expected load. A
   traffic failure fails the experiment: a run that asked for traffic is never reported as a quiet one.
   Traffic keeps running through the attack and stops last (after the defender). If a defender rebuilds a
   victim, the environment re-grants the traffic key there and traffic restarts its generator on it
   (`restore_traffic_access()` → `traffic.rearm()`), so a restored host does not go conspicuously silent.

5. **Defender setup + arm** (only if a defender is present). The arena runs `defender.setup()`, opens the
   box ingress the defender declared via `box_ingress()` (`environment.program_ingress()`), then launches
   the defender via `defender.run()`. `run()` only *spawns* the defender; arming (standing up ES on the
   box, placing decoys / honey-credentials, initializing the detection loop) then takes minutes. **The
   arena blocks here** — see the handshake below.

6. **Attacker setup + run.** Only after the defender is armed, the arena hands the attacker its
   agent-facing spec + `SetupAccess`, the attacker preps its own foothold (so the defender watches that
   too), and the engagement runs inside the **run window** (`arena/main.py` `_run_window`). The window
   opens when the attacker is running and closes on the first of:
   - **attacker_exited**: the attacker process ends (`Finished`, or `Error` on a nonzero exit);
   - **attacker_timeout**: `attacker_timeout_seconds` elapses (`TimedOut`);
   - **duration**: `run_duration_seconds` (else `default_run_duration_seconds`) elapses (`Finished`);
   - **manual**: `POST /experiments/{name}/stop` or the dashboard's *stop* button (`Finished`);
   - **defender_exited**: the defender loop exits nonzero, so the run is no longer defended (`Error`,
     retried). A defender that exits 0 has finished on its own; the window stays open.

   For every reason but `attacker_exited` the attacker is `SIGTERM`'d (then `SIGKILL`ed if it ignores
   that). The reason is recorded as `run_stop_reason`, with `run_started_at` / `run_finished_at`.

7. **Collect.** Traffic is stopped and its labelled activity logs (the benign ground truth) are pulled
   first, then `environment.collect()` pulls host-side logs (the scorer's ground truth) into the
   experiment's output tree *before* teardown. Best-effort and bounded.

8. **Teardown.** `defender.teardown()` and `traffic.teardown()` (harness-side cleanup) run first, then `environment.teardown()`
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
- Traffic lifecycle (the same signal set, setup() blocks until generating): `arena/traffic/plugins/base.py`.
- The driver that sequences all of it: `arena/main.py`.

See [plugins.md](plugins.md) for what each plugin must implement at each stage, and
[architecture.md](architecture.md) for the arena/plugin boundary.
