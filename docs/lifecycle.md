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

4. **Defender setup + arm** (only if a defender is present). The environment opens the ports declared by `box_ingress()` through `program_ingress()`. Then `defender.setup()` blocks until the defense is armed and returns its prepared state. The base emits READY after setup and config generation succeed; only then does `run_start()` launch or adopt the reactive-loop process.

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

A running process is not sufficient evidence that the defense is armed. Each defender's `setup()` must wait until its required services, decoys, credentials, and detection loop are ready. It may poll a plugin-specific readiness marker internally.

The base `run_setup()` emits READY only after `setup()` returns and the runner configuration is written. The arena holds the attacker behind that signal. If setup fails, the experiment fails rather than reporting an undefended run as defended.

## Where this lives

- Lifecycle signals: `arena/environment/lifecycle.py` (`EnvironmentSignal`).
- Defender lifecycle (SETUP_STARTED → READY → RUNNING → STOPPING → STOPPED, arming in `setup()`):
  `arena/defender/plugins/base.py` (`run_setup` / `run_start`), a mirror of `AttackerPlugin`.
- The driver that sequences all of it: `arena/main.py`.

See [plugins.md](plugins.md) for what each plugin must implement at each stage, and
[architecture.md](architecture.md) for the arena/plugin boundary.
