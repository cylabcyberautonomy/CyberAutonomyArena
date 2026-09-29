# Environment interface refactor

Goal (from WHAT_TO_REFACTOR.md): make the environment a real **plugin type** like
attacker/defender/traffic — a registry + lifecycle (provision, configure, collect, teardown),
a capacity estimate, and **two filtered outputs** (an attacker-relevant spec and a
defender-relevant spec) — instead of the harness shelling out to MHBench `cli.py` directly and
every other system reading MHBench `topology.json`.

Worktree: `~/experiment_harness-arena-env`, branch `arena-refactor-env` (off `arena-refactor`).

## The environment always provides a defender box (decided)

Every topology includes a dedicated **defender box** in an isolated ("super-secret") subnet, injected
by the environment plugin exactly like the management/bastion host is today. **The defender RUNS on
that box** (the harness ships + launches it there, like the attacker runs on Kali) — NOT on the
harness host (beluga). The box:
- reaches the victims (to act / install bespoke sensors with the host creds) and the per-experiment
  broker (to consume telemetry);
- is **hidden from the attacker** — isolated subnet, not in the attacker's topology
  (attacker → defender box is blocked);
- needs **egress to the LLM API** for LLM defenders (OpenRouter/Anthropic) while staying unreachable
  from the attacker. So: attacker→box blocked; box→{victims, broker, LLM API} allowed. **Ownership
  split**: the *environment* provisions the egress PATH — root on the box can't open a cloud-enforced
  route or punch a security group. The *defender* (root) does box-side setup (SDK, DNS, `HTTP_PROXY`).
  The API key is shipped to the box by the harness, not conjured by root. NAT egress is outbound-only,
  so internet egress never makes the box reachable from the attacker.
  - **Scoping egress to *just* the LLM API is done with a forward proxy, not IP rules.** LLM APIs live
    behind shared, rotating CDN IPs, so a cloud IP/CIDR allowlist can't isolate them (only fixed-IP
    dests — broker, victims — allowlist cleanly by IP). Instead the environment runs a small
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
- firewall the bastion / defender box / broker **off from the victims and the foothold**, except the
  specific allowed paths (victims→broker forward-only; harness→box jump; box→victims for defender
  actions);
- **forward-only jump creds** (the bastion key jumps but is not reusable laterally);
- **box-scoped keys, no global key left in-env** — including the LLM key on the defender box
  (scoped/rotated per run, not a reusable global cred);
- the **scoped egress proxy** above for the defender box's LLM access.
`DefenderEnvSpec` serves the box as the defender's home base (address + access creds + its reachability
to victims/broker/ground-truth). For MHBench the wrapper deploys this extra box alongside the mgmt host.

## Instrumentation ownership (decided): subscriber hybrid

Per-run sensor install on every host is a large time cost that tests nothing about the defense, so
the model is a **subscriber hybrid** — fairer AND faster than pure defender-installs:

- **Common telemetry streams to a broker (the NATS bus), NOT an ES database.** The
  telemetry-instrumented images bake their sensors to ship to ONE fixed address — the broker — tagged
  with the experiment id as the subject (e.g. `telem.<exp>.falco.<host>`). Baked once, never
  re-pointed per run. **The broker is a per-experiment NATS box on the environment's
  management/bastion host** — stood up by the environment plugin at provision/configure and torn down
  with the env (no persistent shared infra, no ES shard cap, strong isolation: a whole separate broker
  per run; core NATS stores nothing). Placement wins on **both reachability and latency**, because the defender now runs on an
  environment-provided box in the *same* cloud (see above), so the broker is close to its actual
  consumer:
  - **Reachability**: the management host is on the victim-reachable management network on every backend
    (it already carries ansible + the GCP `gcp_relay_ip` socat relay), so victims can forward to it on
    GCP too, where cloud victims cannot reach on-prem beluga through their egress firewall.
  - **Latency**: the defender box and the broker sit in the same cloud/region, so the telemetry hop to
    the consumer is local (this is why the earlier "co-location is useless" reasoning — which assumed a
    beluga defender — no longer holds).
  The bastion/mgmt host is hidden from the attack surface (not in the attacker's topology); victims only
  forward to it, and the defender box consumes via the arena's adapters.
  **The defender never touches NATS.** It declares a telemetry requirement as
  `(source_channel, dest, protocol)` — which common stream it wants (`source_channel`, e.g.
  `telem.<exp>.falco.*`), where to deliver it (`dest`, its ES/HTTP/host:port), and how (`protocol`:
  NATS push / HTTP POST / syslog / ES-bulk / …). **The ARENA parses that tuple and programs the
  broker** to subscribe to `source_channel` and deliver to `dest` via `protocol` (using the arena's
  protocol adapters). The defender gets no broker address/creds and runs no subscriber — it only needs
  its `dest` reachable. This is the "TELEMETRY REQS (source channel, dest, protocol)" output on the
  defender box in the design diagram. Redirection happens at the broker; nothing on the victims is
  ever rewritten. Near-zero setup, identical common data for every defender (fair comparison).
  **Last hop = arena protocol adapters.** NATS carries opaque payloads **byte-for-byte** (it never
  parses/reshapes), and the arena's per-`protocol` adapters (NATS push / HTTP POST / syslog / ES-bulk)
  forward those bytes to `dest` unchanged — so the arena satisfies "deliver, never change." An adapter
  can be a tiny script or a small Vector instance; it is a *delivery* detail, never on the ingest path.

  **Byte-for-byte (CHOSEN): a passthrough publisher, not falcosidekick.** NATS imposes NO format — a
  message is `subject + headers + opaque payload`, so the only place bytes can change is the host-side
  publisher (Falco has no native NATS output, so something must publish; true of any broker). To
  guarantee raw byte-for-byte:
  1. Falco emits its own raw output: `json_output: true` + `file_output` (`/var/log/falco/events.json`)
     or `stdout` — that JSON line IS the canonical raw record.
  2. Keep falcosidekick OFF the NATS path — it is the reshaper (parses + re-envelopes).
  3. Bake a tiny **passthrough publisher** that forwards each raw line verbatim, never deserializing:
     a ~20-line tail-and-publish NATS-client agent (`tail -F events.json` → `nats.publish(subject,
     line_bytes)`, survives restarts/rotation), OR Falco `program_output` (keep_alive) piping each line
     to a forwarder. NATS → arena adapters → defender `dest` are all opaque-byte passthrough.
  4. sysflow: same — the passthrough agent forwards whatever `sf-processor` writes, verbatim.
  Cost of byte-for-byte = exactly one small baked component (the passthrough agent) instead of reusing
  falcosidekick. The manifest declares the true stream form (`falco: raw Falco JSON lines,
  byte-for-byte`). **Fidelity check**: hash each source line vs the payload delivered at `dest` (add to
  the canary / contract test) to *prove* nothing reshaped it.

  **Streaming-only sensors (no file output).** The reshape risk is never the transport — it's whether
  the RECEIVER parses. So the fixed bake target is really a set of **dumb protocol receiver shims on the
  per-experiment broker box**, one per transport, each capturing the raw payload and republishing it to
  NATS unchanged:
  - HTTP-push (incl. Falco's own `http_output`) → a tiny HTTP server that reads the **raw request body**
    and publishes those bytes (this is falcosidekick without the reshape — so even Falco can skip files:
    `http_output → dumb HTTP shim → NATS`).
  - syslog → a listener republishing each raw message; TCP/gRPC/Kafka → the matching dumb receiver
    forwarding each frame/message verbatim.
  Caveats to disclose in the manifest: **framing** (one event → one NATS message: per POST body / per
  syslog datagram / per gRPC frame; batched senders yield batch payloads); **gRPC/protobuf** byte-for-byte
  = the serialized message bytes (consumer needs the `.proto`); **TLS** push → the shim terminates TLS and
  republishes the decrypted payload. **Exception — server-mediated agents (Velociraptor, Wazuh):** their
  telemetry is the *server's*, not a tappable raw per-event stream, so they use the **bespoke path** (the
  defender runs the tool's own server on its box), not the NATS common stream.
  **This root-fixes the baked-falcosidekick-wrong-ES bug**: the bake target is constant (the broker),
  so it can never point at the wrong place; per-defender routing is subjects/subscriptions/forwards.
  (See the Arena Handshake design for the bus.)
- **The defender owns the CHOICE and owns bespoke installs.** In `setup()` it checks for what it
  needs; if the common telemetry is missing it logs `"couldn't find telemetry X — installing my own"`
  and installs it (the slow path, paid only when needed), using the host credentials in
  `DefenderEnvSpec`.
- **The fallback is measured, not hidden**: record used-common / had-to-install / install-seconds, so
  setup cost becomes a reported *deployability* axis instead of a silent per-run tax. (This gives two
  clean axes: efficacy on the shared common telemetry, and deployability/adaptation cost.)
- **The bake target is the broker, fixed.** Instrumented-style pre-provisioning is KEPT as the fast
  path; the images ship to the broker and the broker routes to each defender — so nothing is re-pointed
  per defender, and the wrong-ES bug is designed out.
- **Ground-truth logging (auditd/syslog/bash-history) stays environment-owned** regardless — the
  *scorer* uses it, so it must be independent of the defender (no tampering with its own evidence).

The canary defender already built is the availability probe for this: its telemetry/canary_event
checks are exactly "is the common telemetry present and flowing?" — a real defender's `setup()` runs
the same check and branches to subscribe-vs-install.

`DefenderEnvSpec` therefore advertises: the available common telemetry + subscribe endpoint + creds,
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
  box → launch the defender there; reach victims → install bespoke sensors; wire the broker adapter).
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
- **Stage 2** — adopt the agent-facing specs + `SetupAccess` (after the attacker session's rename is
  pushed), neutralize the defender handoff (`hosts: {name, ip, role}`, not a raw topology path), move
  capacity + decoy estimate behind the plugins, add the env status stream, and remove
  `run_attacker_setup_play` / `--attacker-play` from `deployer.py`.

## Coordination (settled 2026-09-29)

Agreed with the attacker-interface session (user-adjudicated):
- shared setup-facing type = **`SetupAccess`** (a list; each entry `{name, host, user, port, ssh_key,
  ssh_common_args}`); the attacker session owns the `FootholdAccess` → `SetupAccess` rename + push.
- **attacker owns foothold prep**; the environment adds NO `prepare_attacker_foothold` and runs NO
  `--attacker-play`. Env→attacker contract = `AttackerEnvSpec` (`{objective, footholds:[{name,host,user}]}`)
  + the `SetupAccess` list; zero attacker-C2 info in the environment.
- `SetupAccess` fields the attacker prep needs: exactly `{name, host, user, port, ssh_key,
  ssh_common_args}` — nothing C2-related.
