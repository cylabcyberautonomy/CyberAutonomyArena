# Security model

The arena pits an offensive agent against a victim network (and optionally a defender) inside a cloud
tenant the harness owns. Its security model exists to keep the **game honest**: the attacker must *earn*
its access by playing, the defender must not peek at or tamper with its own ground truth, and neither can
reach the harness's own control plane. Two invariants carry almost all of that weight:

1. **No god key** — the environment issues a separate, scoped credential per system.
2. **Adversary-safe vs harness-only** — what the agent sees never contains a credential or a route.

Plus one **management-plane isolation** requirement that address-hiding alone cannot satisfy.

This document also records a **known gap** (telemetry isolation on OpenStack) that is designed-for but
not yet wired — see the last section.

---

## 1. No god key — three scoped credentials

MHBench's native deploy injects **one** keypair as `root` on **every** host. Leaked to the attacker,
that single key is `ssh root@<any-victim>` east–west — it wins the game without exploitation, and bastion
isolation doesn't cover east–west movement. So the arena forbids a god key anywhere. The environment
issues exactly three credentials, each scoped to only its own hosts:

| Credential            | Opens                                   | Who holds it                        | In a spec? |
|-----------------------|-----------------------------------------|-------------------------------------|------------|
| **env / management**  | the environment's own VMs (deploy/configure) | the harness (environment plugin)    | **never**  |
| **attacker key**      | the attacker's foothold box **only**    | injected into the attacker's `SetupAccess` | harness-only |
| **defender key**      | the defender box **+ the victims** it may act on | injected into the defender's `SetupAccess`  | harness-only |

The management key stays inside the environment plugin's deploy path and is **never** placed in any spec
or `SetupAccess`, so it has no accessor on the plugin interface. The attacker and defender keys are minted
and injected by the environment during `configure()` (`attacker_credential()` / `defender_credential()`),
before log rotation.

**The invariant:** no credential in a system's `SetupAccess` may grant access that system couldn't
legitimately earn by playing the game. The attacker key opens its foothold and nothing else; a leak buys
the adversary only what it already had.

### Enforcement: `tests/test_no_god_key.py`

A regression guard greps every plugin file under `attacker/plugins`, `defender/plugins`, and
`traffic/plugins` for the signatures of a management-key read (`openstack_config.ssh_key_path`,
`_mhbench_ssh_key`, the default `id_ed25519` path, etc.). It deliberately does **not** flag the *correct*
pattern — consuming the injected `access["ssh_key"]` — because that is exactly what plugins should do.

The test fails on any **new** god-key read. Two reads remain in a documented baseline, each a known
residual with a stated exit:

- `defender/plugins/velociraptor/velociraptor.py` — **deferred**: its server runs on the bastion, which a
  scoped key can't reach; the fix is moving the server onto the defender box, after which it consumes
  `SetupAccess` like the others.
- `traffic/plugins/caldera_human/caldera_human.py` — **tabled**: needs its own victims-only traffic
  scoped key (it drives no agent and has no adversary, so it is lower-risk).

Shrink the baseline as those land; it must never grow.

---

## 2. Adversary-safe spec vs harness-only `SetupAccess`

The environment produces **two** things per system, split by audience:

- **Agent-facing spec** (`AttackerEnvSpec` / `DefenderEnvSpec`) — objective + identity/knowledge only
  (the attacker's own foothold `{name, host, user}`; the defender's host inventory `{name, ip, role}`).
  Safe to hand the model via `build_config`. **No keys, no bastion, no routing.**
- **Harness-only `SetupAccess`** — a list of `{name, host, user, port, ssh_key, ssh_common_args}`, one per
  reachable host, carrying the scoped key and the bastion ProxyCommand. Consumed only by trusted plugin
  setup code; **never** reaches an agent.

Enforceable rule: **anything with a credential or a route is setup-facing and never enters
`build_config`.** Because creds live only in `SetupAccess`, agent-facing specs may even carry IPs — the
control is credential isolation + management-plane isolation, **not address secrecy** (see §3).

---

## 3. Management-plane isolation

Hiding an IP in a spec is **not** a control: the adversary can scan its own network. The real control is
the environment isolating the management plane, which the environment plugin owns:

- Firewall the bastion / defender box / telemetry relay **off from the victims and the foothold**, except
  the specific allowed paths (victims→relay forward-only; harness→box jump; box→victims for defender
  actions).
- **Forward-only jump credentials** — the bastion key jumps but is not reusable laterally.
- **Box-scoped keys, no global key left in-env** — including the LLM API key on the defender box
  (scoped/rotated per run, shipped by the harness, not a reusable global cred).
- **Scoped egress for the defender box's LLM access via a forward proxy, not IP rules** — LLM APIs sit
  behind rotating CDN IPs, so a CIDR allowlist can't isolate them; a domain-allowlisting forward proxy on
  the management plane can (box→internet denied except through the proxy).

---

## 4. Known gap — victim egress is not scoped on OpenStack

First, two names that collide across the repos:

- **harness ES** — the shared Elasticsearch on the **provider network** (`cfg.host_ip = 10.81.1.20`;
  baked `es_address 10.81.1.25`). This is the harness control plane; victims must never reach it.
- **relay / mgmt host** — MHBench's `management.host_ip = 10.0.1.10`, on the tenant management network
  (`10.0.1.0/24`). Per-experiment, victim-reachable **by design**, and hidden from the attacker.

### What already works (telemetry *flow* isolation)

Victim telemetry is routed through a transparent forwarder (the relay) on the mgmt host instead of letting
sensors ship to the harness ES. In the arena this is **implemented** (MHBench-side), as **box mode**:

- MHBench runs `telemetry_relay.py` (`telemetry_relay.service`) on the per-experiment mgmt host
  (`10.0.1.10:9200`), forwarding byte-for-byte to a dest from `/etc/telemetry_relay/dests.json`.
- When the environment provides a **defender box**, the defender's ES lives on that isolated box. The
  defender declares the box port it needs via `DefenderPlugin.box_ingress()` (`{"telemetry": [9200]}`),
  and `MHBenchEnvironment.program_ingress()` both opens that port and points the relay at the box
  (`request-ingress --telemetry`). Victim sensors ship to the relay → box ES; the harness runner **skips**
  installing/repointing sensors (`llm_soc/runner.py` "box mode"), and attacker↔box is severed.
- **Legacy mode** (no defender box) is the old path: sensors ship straight to the harness ES at
  `management_ip` (= `cfg.host_ip`).

**Why the relay is necessary (and sufficient).** The defender box is on an isolated subnet and victims
**cannot initiate** connections to it (one-way isolation: box→victims allowed, victim→box blocked). So
victims can't ship to the box directly; the mgmt-host relay — which victims *can* reach and which *can*
reach the box — bridges that gap. One interface expresses the whole need: the defender names a port
(`box_ingress()`), the environment opens it and routes the relay there (`program_ingress()`). There is no
separate `telemetry_ingest()`/`program_telemetry()`/`TelemetryRoute` interface — that was unbuilt
fan-out scaffolding with no consumers, and it was **removed**; the relay address a defender's sensors use
on the legacy path comes from `telemetry_relay_ip()`.

**The shared harness ES still exists** for the two decoy defenders (`deception`, `prompt_injection`),
which bind `http://{cfg.host_ip}:9200` directly and were **not** migrated to box mode — that migration is
deferred because it needs a richer environment interface (a defender asking the environment for *a decoy*).
Only `llm_soc` uses box mode today. Eliminating the shared ES entirely is blocked on that deferred work.

### What does NOT work (network *reachability*)

Telemetry flow is isolated; **raw network reachability is not.** On OpenStack
(`MHBench/src/deployment/network_deployer.py`):

- every topology subnet, including victim subnets, is attached to a router whose **external gateway SNATs
  to the provider network** (where the harness ES lives), and
- victim egress defaults to **`0.0.0.0/0`** (`internet_egress = True` by default,
  `abstractions/network.py`), with **no per-destination scoping**.

So a compromised victim can open a socket **directly** to the harness ES (`10.81.1.x`) and the rest of the
provider net — **bypassing the relay entirely, in either mode.** That both leaks the control-plane address
to the adversary and (in principle) lets it read or tamper with the defender's ground-truth telemetry
store, an experiment-integrity problem.

Why it isn't already fixed: OpenStack security groups are **allow-only** (no deny rules), so you can't
"deny `10.81.1.x` while allowing `0.0.0.0/0`." The only egress knob is `internet_egress`, and setting it
`False` today restricts a victim to its **own CIDR only** — which also severs the relay (`10.0.1.10`),
because the OpenStack backend, unlike GCP (`gcp_backend.py` adds `management.cidr` to its restricted
egress-allow set), does **not** allow the management CIDR. GCP's exposure is narrower only by topology (no
provider ES subnet to reach; NAT goes to the internet), not by an explicit block of the mgmt host.

> **Fix shape** (MHBench-side, environment-owned): make victim egress an **allow-list** of
> `{all internal subnet CIDRs} + {management.cidr}` and drop the blanket `0.0.0.0/0` + provider-net
> reachability — i.e. set instrumented victim subnets to `internet_egress: False` **and** fix the
> OpenStack backend to include `management.cidr` in the restricted egress-allow (mirroring GCP), so the
> relay keeps working while the harness ES and the internet become unreachable from victims. Prefer **box
> mode** as the standing posture. Needs live validation; see the engineering notes for the full change
> set. Until then, OpenStack victim→control-plane reachability is a documented known limitation.
