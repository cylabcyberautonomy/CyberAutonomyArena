# Environment interface refactor

Goal (from WHAT_TO_REFACTOR.md): make the environment a real **plugin type** like
attacker/defender/traffic — a registry + lifecycle (provision, configure, collect, teardown),
a capacity estimate, and **two filtered outputs** (an attacker-relevant spec and a
defender-relevant spec) — instead of the harness shelling out to MHBench `cli.py` directly and
every other system reading MHBench `topology.json`.

Worktree: `~/experiment_harness-arena-env`, branch `arena-refactor-env` (off `arena-refactor`).

## The environment always provides an attacker box AND a defender box (decided)

Both agents run from an environment-provided box, and **the environment guarantees both boxes exist —
neither is ever nonexistent** — with **internet EGRESS but no INGRESS** (outbound NAT/SNAT so each box
can reach the internet / the LLM API; no inbound from the internet, so a box is never reachable from
outside):

- **Attacker box** (its foothold, e.g. Kali): location is FLEXIBLE ("wherever" — in-env or elsewhere),
  but it MUST be provisioned and **served to the attacker through the specs** (`AttackerEnvSpec.footholds`
  — always non-empty). Egress-only (its LLM/tools reach out; nothing reaches in). The attacker runs
  its own prep on it (attacker owns foothold prep).
- **Defender box**: a dedicated box in an isolated ("super-secret") subnet, hidden from the attacker.
  Egress-only, same as the attacker box. Details below.

Every topology includes a dedicated **defender box** in an isolated subnet, injected by the environment
plugin exactly like the management/bastion host is today. **The defender RUNS on that box** (the harness
ships + launches it there, like the attacker runs on Kali) — NOT on the harness host (beluga). The box:
- reaches the victims (to act / install bespoke sensors with the host creds) and the per-experiment
  telemetry relay on the mgmt host (to consume telemetry);
- is **hidden from the attacker** — isolated subnet, not in the attacker's topology
  (attacker → defender box is blocked);
- needs **egress to the LLM API** for LLM defenders (OpenRouter/Anthropic) while staying unreachable
  from the attacker. So: attacker→box blocked; box→{victims, relay, LLM API} allowed. **Ownership
  split**: the *environment* provisions the egress PATH — root on the box can't open a cloud-enforced
  route or punch a security group. The *defender* (root) does box-side setup (SDK, DNS, `HTTP_PROXY`).
  The API key is shipped to the box by the harness, not conjured by root. NAT egress is outbound-only,
  so internet egress never makes the box reachable from the attacker.
  - **Scoping egress to *just* the LLM API is done with a forward proxy, not IP rules.** LLM APIs live
    behind shared, rotating CDN IPs, so a cloud IP/CIDR allowlist can't isolate them (only fixed-IP
    dests — relay, victims — allowlist cleanly by IP). Instead the environment runs a small
    **egress forward proxy** (Squid/Envoy, or GCP Secure Web Proxy) on the management plane with a
    **domain allowlist** (`api.anthropic.com`/`openrouter.ai`); cloud firewall lets the box reach only
    the proxy (box→internet denied). Root on the box can't bypass it (no route out except the proxy,
    which enforces the domains).

## Management-plane isolation is an explicit environment responsibility

Hiding IPs (e.g. the bastion) in a spec is NOT a control — the adversary can scan its own network. The
real control is the environment **isolating the management plane**, which the env plugin must own and
which carries into the formal interface. `AttackerEnvSpec`/`DefenderEnvSpec` are consumed by the
**trusted attacker/defender plugins, never the adversary**, so their contents are not a disclosure risk;
the isolation is. Duties:
- firewall the bastion / defender box / relay **off from the victims and the foothold**, except the
  specific allowed paths (victims→relay forward-only; harness→box jump; box→victims for defender
  actions);
- **forward-only jump creds** (the bastion key jumps but is not reusable laterally);
- **box-scoped keys, no global key left in-env** — including the LLM key on the defender box
  (scoped/rotated per run, not a reusable global cred);
- the **scoped egress proxy** above for the defender box's LLM access.
`DefenderEnvSpec` serves the box as the defender's home base (address + access creds + its reachability
to victims/relay/ground-truth). For MHBench the wrapper deploys this extra box alongside the mgmt host.

## Instrumentation ownership (decided): relay hybrid

Per-run sensor install on every host is a large time cost that tests nothing about the defense, so
the model is a **relay hybrid** — fairer AND faster than pure defender-installs:

- **Common telemetry ships to ONE fixed bake target — a transparent forwarding RELAY on the mgmt host
  — which redirects to the defender's endpoint. (Chosen over a NATS bus: simpler, no shims.)**
  - **One fixed bake target.** The management host's internal IP is **constant across experiments**
    (`management.host_ip = 10.0.1.10`), so the telemetry-instrumented images bake their sensors to
    `10.0.1.10:<port>` once — never re-pointed per run. (This is exactly the existing GCP
    `gcp_relay_ip` socat relay, generalized to every backend.)
  - **The relay redirects, with no shim.** A plain TCP/HTTP forwarder (socat / HAProxy / nginx) on the
    per-experiment mgmt host receives the sensor's *native* stream and forwards the bytes to the
    defender's endpoint. Because it forwards the sensor's own protocol unchanged, it is byte-for-byte
    with **no publisher and no translation** — as long as the defender consumes the sensors' native
    protocol (it can). No NATS ⇒ no per-sensor publisher/shim (Falco/sf-processor have no NATS output,
    which is the only reason a bus needs shims at all).
  - **Per-experiment + hidden.** The relay runs on that experiment's own mgmt host (separate per
    experiment ⇒ no cross-contamination), is on the victim-reachable management network on every backend
    (works on GCP, where victims can't reach on-prem beluga through egress), and is hidden from the
    attacker (not in the attacker's topology; victims only forward to it). Torn down with the env.
  - **Driven by `(source_channel, dest, protocol)`** — the defender's "TELEMETRY REQS" output. The
    defender never touches the relay: it declares which sensor stream it wants (`source_channel` = a
    relay port), where (`dest`), and how (`protocol`); the ARENA writes the relay's per-experiment
    forward rules. The defender only needs its `dest` reachable.
  - **Multi-stream routing AND fan-out fall out of this.** The arena collects ALL consumers' tuples
    (defender, and later a live dashboard/scorer/shadow defender) and groups them by `source_channel`,
    so each source maps to a *list* of `(dest, protocol)`:
    - different streams → different endpoints = different `source_channel`s with different dests (trivial;
      even dumb socat, one forwarder per stream);
    - same stream → multiple endpoints = one `source_channel` with several dests = **fan-out**, which a
      1:1 socat can't do. Use a **fan-out-capable relay — Vector or Fluent Bit** (one source → N sinks,
      config-driven; receives sensors' native protocols so still NO per-sensor publisher; bytes codec
      keeps it byte-for-byte), or a ~30-line custom fan-out forwarder. This is Vector *as the relay
      itself*, not as a NATS publisher.
  - **This root-fixes the baked-falcosidekick-wrong-ES bug**: the bake target is a constant (the mgmt
    relay), so it can never point at the wrong place; per-defender routing lives in the relay config.
  - **Byte-for-byte:** keep falcosidekick (the reshaper) off the path — point Falco's own
    `http_output`/`file_output` (raw JSON) at the relay, which forwards it verbatim. **Fidelity check**:
    hash each source record vs what's delivered at `dest` (add to the canary/contract test).
  - **Exception — server-mediated agents (Velociraptor, Wazuh):** their telemetry is the *server's*, not
    a tappable raw stream, so they use the **bespoke path** (the defender runs the tool's own server on
    its box), not the common relay.
  - **NATS is a deferred, optional upgrade** — even multi-consumer fan-out is handled by the fan-out
    relay above, so NATS earns its place ONLY for **dynamic pub/sub** (a consumer subscribes/unsubscribes
    at runtime without the arena rewriting the relay config) or **replay/persistence**. In the arena the
    arena controls all consumers, so it just programs the fan-out rules — no bus needed. Adopting NATS
    later would reintroduce publishers/shims (sensors can't speak it) — the cost the relay avoids.
- **The defender owns the CHOICE and owns bespoke installs.** In `setup()` it checks for what it
  needs; if the common telemetry is missing it logs `"couldn't find telemetry X — installing my own"`
  and installs it (the slow path, paid only when needed), using the host credentials in
  `DefenderEnvSpec`.
- **The fallback is measured, not hidden**: record used-common / had-to-install / install-seconds, so
  setup cost becomes a reported *deployability* axis instead of a silent per-run tax. (This gives two
  clean axes: efficacy on the shared common telemetry, and deployability/adaptation cost.)
- **The bake target is the mgmt relay, fixed.** Instrumented-style pre-provisioning is KEPT as the fast
  path; the images ship to the relay and the relay routes to each defender — so nothing is re-pointed
  per defender, and the wrong-ES bug is designed out.
- **Ground-truth logging (auditd/syslog/bash-history) stays environment-owned** regardless — the
  *scorer* uses it, so it must be independent of the defender (no tampering with its own evidence).

The canary defender already built is the availability probe for this: its telemetry/canary_event
checks are exactly "is the common telemetry present and flowing?" — a real defender's `setup()` runs
the same check and branches to consume-vs-install.

`DefenderEnvSpec` therefore advertises: the available common telemetry (source channels) + creds,
PLUS host credentials so the defender can install bespoke sensors when it chooses.

**Log rotation is an MHBench wrapper detail, not a lifecycle stage.** The `mhbench` plugin's
`configure()` runs MHBench `configure` and then MHBench `rotate-logs` internally. It is NOT on the
base `EnvironmentPlugin` interface, the arena never calls it, and other environments never see it.
(Behavioral note: today rotate runs at `main.py:979`, after defender/traffic/attacker setup;
internal-to-configure it runs before them — acceptable because the defender now owns its own sensors
+ baseline, and the scorer already time-scopes the ground-truth audit log to the attack window, so
pre-attack setup noise is excluded regardless.)

## The coupling today (what has to move)

1. **Five modules shell out to MHBench `cli.py` directly**, each building
   `<mhbench_dir>/.venv/bin/python cli.py <verb> environments/<spec>.json --project-name … --mgmt-ip …`:
   - `environment/deployer.py` — `_provision_sync`, `_configure_sync`, `_attacker_play_sync`
     (`configure --attacker-play`), plus `run_attacker_setup_play`
   - `environment/collect.py` — `collect`
   - `environment/rotate.py` — `configure` (log rotation)
   - `environment/teardown.py` — teardown by project name
2. **`DeployedEnvironment`** = `{topology_spec (path to MHBench json), ip (kali), spec (name)}` —
   one unfiltered object handed to everyone. `main.py:794` hand-builds it pointing at
   `<mhbench_dir>/environments/<spec>.json`.
3. **Capacity reads MHBench files directly**: `capacity.count_vm_specs` reads the topology JSON +
   `mhbench config.yaml` (`management.flavor`, the injected +1 mgmt host) to size the VM/CPU
   admission reservation; `estimate_decoy_vms` reads the topology AND reaches into defender
   internals to guess decoy count.
4. **`main.py` owns the lifecycle + status** (DEPLOYING/DEPLOYED/CONFIGURING/CONFIGURED) and the
   sequencing; there is no environment-level status stream.
5. **Consumers read MHBench shapes**: every defender/canary `build_config` reads
   `environment.topology_spec`; the attacker reads `environment.spec` (the MHBench env name, passed
   to Incalmo as `"environment"`) + the Kali IP (from `_kali_ip_from_spec` scanning the JSON).
6. **`ExperimentSpecs.environment` is a plain `str`** (the env name), not a selectable plugin config.

## What the refactor entails

### A. Define `EnvironmentPlugin` base (mirror the other three)
Pydantic model + `_registry` keyed by `config_type`, `ui_schema()`, and a lifecycle the arena drives:
- `provision(experiment, cfg) -> ProvisionResult` (access handle: mgmt/bastion IP, etc.)
- `configure(experiment, cfg, handle)`
- `collect(experiment, cfg, handle, dest)`
- `teardown(experiment, cfg, handle)`
- `capacity(experiment, cfg) -> list[(vcpus, ram, disk)]` (admission stops reading MHBench files)
- outputs: `defender_spec(...) -> DefenderEnvSpec` and `attacker_spec(...) -> AttackerEnvSpec`
Each reports structured status/failure so the arena can emit the env's own signals
(DEPLOYING/DEPLOYED/CONFIGURING/CONFIGURED/TEARING_DOWN/TORN_DOWN + failed-with-reason).

### B. `mhbench` environment plugin (config_type="mhbench")
A wrapper that makes MHBench compatible with the harness. Move the current
deployer/collect/rotate/teardown/capacity bodies here almost verbatim — they already work live.
`configure()` internally runs MHBench `configure` then MHBench `rotate-logs` (rotation is a wrapper
detail, not exposed on the base interface). This is the first concrete plugin, exactly like
`caldera_human` was for traffic.

### C. Two-audience spec split: agent-facing specs + one setup-facing `SetupAccess`

The environment mints, per experiment, specs separated by AUDIENCE — enforceable rule:
**anything with a credential or a route is setup-facing and never reaches `build_config`/the LLM.**

**Agent-facing (identity/knowledge only, safe to hand the LLM via `build_config`):**
- `AttackerEnvSpec` → `objective` + footholds as `{name, host, user}` (the box's own in-env IP +
  account — what the adversary already knows about its own foothold). No keys, no bastion, no routing.
- `DefenderEnvSpec` → topology at the knowledge level (`hosts: {name, ip, role}` — the defender knows
  its estate), the available **source channels** (common-telemetry catalog), objective/critical assets,
  and the defender box's own identity. No creds.

**Setup-facing — `SetupAccess` (harness-only; the trusted plugin's prep; NEVER to any agent):**
- a **LIST** (N per experiment — multiple footholds/victims/boxes), each entry
  `{name, host, user, port, ssh_key, ssh_common_args}` — connection + routing, incl. the bastion
  ProxyCommand in `ssh_common_args`. `name` is the inventory alias / multi-target key.
- consumed symmetrically by plugin setup code: **attacker preps its OWN foothold** (SSH Kali → run its
  vendored ansible; the env does NOT run any attacker play — see below), defender setup (SSH the defender
  box → launch the defender there; reach victims → install bespoke sensors; set the relay's forward rule).
  Renames + generalizes the attacker branch's `FootholdAccess` to both sides (final shared name agreed
  with the attacker-interface session: `SetupAccess`).

Because creds live only in `SetupAccess`, agent-facing specs may even carry IPs — the control
is management-plane isolation + keeping creds out of the agent's hands, not address secrecy (see the
management-plane-isolation section). This replaces the old "one `DeployedEnvironment` for everyone" and
the per-plugin `_mhbench_ssh_key` / `provision_result.json` reads.

Stage 1: `DefenderEnvSpec` still also carries `topology_spec` (a path) so existing defender runners
are untouched; later a neutral `hosts: {name, ip, role}` list replaces the raw MHBench JSON path.
This replaces the per-plugin credential fishing: today `canary`, `velociraptor` and `caldera_human`
each carry a private `_mhbench_ssh_key(cfg)`, `defender.py` hand-injects `management_ip`/`bastion_ip`,
and `rotate`/`collect` re-read `provision_result.json` — all of that becomes `SetupAccess`,
minted by the environment plugin.

**Attacker foothold prep is the ATTACKER's, not the environment's** (adjudicated by the user
2026-09-29). The environment does NOT expose `prepare_attacker_foothold` and does NOT run the
`--attacker-play`. Env→attacker contract = `AttackerEnvSpec` (agent-facing) + the `SetupAccess` list
(harness-only), and nothing else — the environment carries ZERO attacker-C2 info. The attacker preps
its own box over the `SetupAccess` creds (already implemented + live-validated on `arena-refactor` via
`incalmo/foothold.py`, which vendors `start_incalmo`/`install_metasploit`). So `run_attacker_setup_play`
and the `--attacker-play` path in `deployer.py` are removed on the env side entirely.

**Merge mechanics:** the attacker-interface session owns the rename `FootholdAccess` → `SetupAccess`
on `arena-refactor` (attacker side + `env_spec.py`) and pushes; this branch (`arena-refactor-env`)
rebases onto it and adds the defender-side adoption + the environment plugin that mints
`AttackerEnvSpec` + `DefenderEnvSpec` + the `SetupAccess` list.

### D. Config wiring (backward compatible)
`ExperimentSpecs.environment: str` → an `EnvironmentConfig` (dynamic-validated like the others),
e.g. `{type: mhbench, spec: equifax_small}`. A bare string coerces to
`{type: mhbench, spec: <string>}` so existing submissions, `experiment_registry.yaml`, and
`run_experiment_smoke.py` keep working unchanged.

### E. main.py
Replace the five module imports + hand-built `DeployedEnvironment` with calls through
`experiment.environment` plugin; map its lifecycle results to `ExperimentStatus`; capacity admission
calls `plugin.capacity()`; decoy estimate comes from the **defender** plugin, not from capacity
reaching into the topology.

### F. Consumers
Defenders/canary/attacker read the new specs instead of `environment.topology_spec`/`.spec`.

## Staging (shippable, doesn't block on the other agents)

- **Stage 1** — `EnvironmentPlugin` base + `mhbench` plugin wrapping the existing code; keep
  `DeployedEnvironment` as the defender handoff (mhbench plugin produces it) so defenders are
  untouched; `EnvironmentConfig` accepts a bare string. Behavior identical; contract test extended.
- **Stage 2**, roughly in order:
  1. The env plugin PRODUCES the agent-facing specs for BOTH sides — `attacker_spec()` (AttackerEnvSpec)
     and `defender_spec()` (DefenderEnvSpec) — plus `setup_access()` (the shared `SetupAccess` list, per
     approved host). Attacker/defender read these FROM the plugin instead of importing `deployer`
     helpers (`attacker_env_spec`/`attacker_setup_access`) or calling `_mhbench_ssh_key`. (The types
     already exist — the attacker session built them; this makes the environment the producer.)
  2. The always-provisioned **defender box** (isolated subnet) + management-plane isolation + scoped
     egress proxy.
  3. **Telemetry = a transparent fan-out relay on the mgmt host** (one fixed bake target that
     redirects), driven by `(source_channel, dest, protocol)` — NOT a NATS bus (see the instrumentation
     section). Point Falco's raw output at the relay; keep falcosidekick off the path.
  4. Neutralize the defender handoff (`hosts: {name, ip, role}`, not a raw topology path); fold `rotate`
     into `mhbench.configure`; remove `run_attacker_setup_play` / `--attacker-play` from `deployer.py`
     (attacker owns prep); add anything still missing from the env status stream.

## Coordination (settled 2026-09-29)

Agreed with the attacker-interface session (user-adjudicated):
- shared setup-facing type = **`SetupAccess`** (a list; each entry `{name, host, user, port, ssh_key,
  ssh_common_args}`); the attacker session owns the `FootholdAccess` → `SetupAccess` rename + push.
- **attacker owns foothold prep**; the environment adds NO `prepare_attacker_foothold` and runs NO
  `--attacker-play`. Env→attacker contract = `AttackerEnvSpec` (`{objective, footholds:[{name,host,user}]}`)
  + the `SetupAccess` list; zero attacker-C2 info in the environment.
- `SetupAccess` fields the attacker prep needs: exactly `{name, host, user, port, ssh_key,
  ssh_common_args}` — nothing C2-related.
