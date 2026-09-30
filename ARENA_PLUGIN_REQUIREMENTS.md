# Arena plugin requirements

The contract every plugin must satisfy, by system type. Use this when adding a new plugin (a new
environment backend like Ludus, a new attacker, a new defender). Eventually the arena should run a
conformance check against these; for now each item is tagged:

- **[ENFORCED]** — pinned by `tests/test_arena_contract.py` today.
- **[DESIGN]** — a requirement documented here / in docstrings; the arena may verify it at runtime
  later (it is NOT a self-reported flag a plugin can lie about).
- **[DEFERRED]** — needs live provisioning (a real deploy) to implement/validate; interface is in place.

Companion docs: `WHAT_TO_REFACTOR_ENVIRONMENT.md` (the environment refactor design + rationale).

---

## Environment plugin

An environment deploys the network the experiment runs on and is the PRODUCER of everything the
attacker/defender need to reach it. `EnvironmentPlugin` (config_type=...), selected via
`environment_plugin` + `environment_spec` (a PATH to the backend's topology/range file).

### Lifecycle
- **[ENFORCED]** `capacity()` (admission sizing — topology VMs only, no decoy/extra pre-reservation),
  `provision()`, `configure()`, `collect()`, `teardown()`.
- **[ENFORCED]** Emits its own status signals (`EnvironmentSignal`: Deploying/Deployed/Configuring/
  Configured/TearingDown/TornDown/Failed) and records arena→env commands (`EnvironmentCommand`:
  Provision/Configure/Teardown — **no run/start**; the env just idles once configured).
- **[DESIGN]** Any backend-specific post-configure step (e.g. MHBench log rotation) is INTERNAL to the
  plugin (mhbench.configure runs it), NOT on the base interface, and the arena never calls it.

### Spec production (the env is the producer; the split is load-bearing)
- **[ENFORCED]** `attacker_spec()` → agent-facing `AttackerEnvSpec` (objective + foothold identity
  `{name, host, user}`; **NO creds/routing** — safe to hand the LLM via build_config).
- **[ENFORCED]** `defender_spec()` → agent-facing `DefenderEnvSpec` (objective + host inventory
  `{name, ip, role}` + the defender box; **NO creds/routing**).
- **[ENFORCED]** `attacker_setup_access()` / `defender_setup_access()` → harness-only `SetupAccess`
  list (`{name, host, user, port, ssh_key, ssh_common_args}` — creds + routing, NEVER given to the
  agent's LLM). Kept SEPARATE from the agent-facing spec (do not merge).

### Boxes (both agents run on an env-provided box)
- **[VALIDATED 2026-09-29]** `defender_box()` → a `DefenderBox` in an isolated subnet, hidden from the
  attacker; the defender RUNS there. Also carried in `defender_spec().box` and reachable via a
  `defender_setup_access()` entry of the same name. MHBench now declares a `defender_subnet`
  (192.168.250.0/24) + bare `defender` box in every instrumented topology; the box is classified by
  subnet (out of the victim inventory) and the harness reaches it via the bastion. The environment
  provisions ONLY the bare box + its network — the **defender** stands up its own ES / detection
  pipeline on it (defender owns its detection instrumentation; the env never runs ES there). Live-
  validated: chain_2hosts end-to-end + equifax_small multi-tier.
- **[ENFORCED]** The **attacker box** always exists (never nonexistent) and is SERVED to the attacker
  via `attacker_spec().footholds` (non-empty). Location is flexible.
- **[VALIDATED 2026-09-29]** Isolation (MHBench `network_deployer`, mirrors the attacker expansion):
  every victim subnet auto-accepts ingress FROM the defender box (defender reaches all tiers, no per-
  topology authoring); the box accepts only mgmt + its own subnet, so attacker AND victims cannot
  initiate to it (no ES injection) and attacker↔defender is severed both ways.
- **[DESIGN / DEFERRED]** Both boxes get internet **EGRESS (outbound-only)** — for the LLM API — and
  **NO ingress** from the internet. The environment provisions the egress path (NAT/SNAT). Attacker→
  defender-box is blocked. (Defender-box egress live-validated; attacker-box egress is default-on.)
- **[PINNED]** Scoping the LLM egress with a forward proxy + domain allowlist (IP rules can't pin
  CDN-hosted APIs) is **deferred** (user, 2026-09-29): plain egress via the router SNAT suffices for
  now. The interface makes no room for a proxy yet; revisit if egress needs to be locked down.

### Per-system credential issuance (no god-key)
- **[ENFORCED]** `attacker_credential()` and `defender_credential()` are DISTINCT (not one key).
- **[ENFORCED]** The attacker key appears only in attacker `SetupAccess`, scoped to the foothold
  host(s) ONLY; the defender key only in defender `SetupAccess`, scoped to the defender box + victims;
  the attacker foothold is NOT reachable with the defender key (and vice versa).
- **INVARIANT:** no credential in a system's `SetupAccess` may grant access that system couldn't
  legitimately earn by playing the game (attacker key opens its box and nothing else). This is what
  makes SetupAccess carrying a key safe; the spec split keeps the key out of build_config for free.
- **[VALIDATED 2026-09-30]** GENERATING + INJECTING the per-system keypairs is done (harness-side, no
  MHBench change). `deployer.issue_scoped_keys()` generates attacker_key + defender_key (idempotent, at
  the credential paths); `inject_scoped_keys()` appends attacker_key.pub to the foothold ONLY and
  defender_key.pub to the box + victims ONLY, via the bastion, in `configure()` before rotate. Private
  keys never leave the harness; the broad OpenStack management key stays harness-side. Live-validated on
  chain_2hosts_instrumented: attacker_key opens the foothold and FAILS on victims + box; defender_key
  opens box+victims and FAILS on the foothold; management key retains full access.
- The **management/provisioning credential** (broad, used to deploy/configure) is harness-side and
  **NEVER appears in any spec**.

### Management-plane isolation (the real control, not spec secrecy)
- **[DESIGN]** Firewall the bastion / defender box / relay OFF from the victims and the foothold except
  the specific allowed paths (victims→relay forward-only; harness→box jump; box→victims for defender
  actions). Forward-only jump creds. No global key left in-env. (Hiding IPs is NOT a control.)
- **[FIXED 2026-09-29]** MHBench's `management_sg` previously allowed ingress `0.0.0.0/0` on ALL ports —
  the bastion holds a floating IP, so the whole internet could reach the relay (inject telemetry) and
  any control-plane port. Now scoped in `network_deployer`: egress open; ingress tcp/22 (SSH jump,
  key-only) from anywhere; ingress tcp/9200 (relay) only from the victim subnets + mgmt CIDR.
  Tightening 22 to a fixed operator CIDR is a further step (harness connects from varying hosts).
- **[REMAINING] forward-only jump creds:** `SetupAccess.ssh_common_args` still routes the bastion hop
  with the broad management key (`-i <mgmt_key>` in the ProxyCommand). It's harness-only (never
  agent-facing) and the per-system TARGET keys are already scoped, so the agent can't ride it — but a
  clean design gives the bastion hop a forward-only (`-W`-restricted, `ForceCommand`) jump key instead
  of the full management key. Distinct from per-system key issuance (done); tracked here.

### Ground-truth logging (scorer independence)
- **[DESIGN]** The environment owns ground-truth host logging (auditd/syslog) used by the scorer — it
  must be independent of the defender (a defender can't be able to tamper with its own evidence).

### Telemetry relay (fixed bake target that redirects)
- **[ENFORCED]** `telemetry_ingest()` → a fixed `TelemetryIngest` (host/port) sensors bake to (constant
  per backend). `program_telemetry(routes)` accepts `TelemetryRoute` list `(source_channel, dest,
  protocol)`; grouping by source gives multi-stream routing AND same-stream fan-out.
- **[DESIGN]** Byte-for-byte: keep reshaping shippers (falcosidekick) off the path; forward raw sensor
  output. Server-mediated EDRs (Velociraptor/Wazuh) use the bespoke path, not the common relay.
- **[VALIDATED 2026-09-29]** The transparent fan-out relay works live. A stdlib HTTP relay
  (`MHBench src/playbooks/plays/aux_files/telemetry_relay.py`) ran on the mgmt host at the constant
  `telemetry_ingest` address (`10.0.1.10:9200`); host0's falcosidekick, repointed there, delivered
  falco `/etc/shadow` alerts through it into the harness ES byte-for-byte. Redirection lives in the
  relay's `dests.json`, not on the victim.
- **[DEFERRED]** Remaining: auto-provision the relay (systemd unit on the mgmt host started at
  configure with a per-deploy `dests.json`), open `management_sg` tcp/9200 from the victim subnets,
  and bake sensor `es_address` to `telemetry_ingest` instead of a hardcoded ES. (NATS is an optional
  future upgrade, only for dynamic pub/sub or replay.)

---

## Attacker plugin

- **[DESIGN]** OWNS its own foothold prep (installs its tools on its box over the env's `SetupAccess`);
  the environment does NOT run an attacker play. It brings up its own C2; the env carries zero C2 info.
- **[ENFORCED]** Consumes the agent-facing `AttackerEnvSpec` in build_config; the harness-only
  `SetupAccess` (key + routing) stays in the plugin's prep and NEVER enters build_config's output
  (the LLM-facing config). Keep AttackerEnvSpec and SetupAccess SEPARATE.
- **[ENFORCED]** Lifecycle: setup/start/stop + its own signals; the arena gates the attack start on
  everything else being ready.

## Defender plugin

- **[ENFORCED]** Consumes the env-produced `defender_env_spec` (host inventory) + `defender_setup_access`
  (per-victim key + routing) injected into its config by `run_defender` — does NOT compute its own SSH
  key or parse the topology (see the canary as the reference migration).
- **[DESIGN / DEFERRED]** RUNS on the env-provided defender box (isolated subnet), not on the harness
  host. Contributes its decoy VM estimate to admission via `estimated_extra_vms` (currently not
  pre-reserved — see capacity).
- **[DESIGN]** Owns its DETECTION instrumentation (subscribe to the common telemetry via a
  `(source_channel, dest, protocol)` request, or install bespoke sensors with the host creds and log
  the fallback). Ground-truth logging is the environment's, not the defender's.
- Reports detections in a machine-readable form for the scorer; arms only after its readiness/canary
  check (the canary defender is the connectivity probe for this).
