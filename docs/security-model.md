# Security model

The arena pits an offensive agent against a victim network (and optionally a defender) inside a cloud
tenant the harness owns. Its security model exists to keep the **game honest**: the attacker must *earn*
its access by playing, the defender must not peek at or tamper with its own ground truth, and neither can
reach the harness's own control plane. Two invariants carry almost all of that weight:

1. **No god key** — the environment issues a separate, scoped credential per system.
2. **Run spec vs setup access** — each system's runtime spec (what the agent acts on) is produced
   separately from its setup-time access (the keys + routing the plugin uses to stand it up).

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
| **attacker key**      | the attacker's foothold box **only**    | injected into the attacker's `SetupAccess` | in `SetupAccess` (setup) |
| **defender key**      | the defender box **+ the victims** it may act on | injected into the defender's `SetupAccess`  | in `SetupAccess` (setup) |

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

## 2. Run spec vs setup access

The environment produces **two** things per system, split by **when they're used** — runtime vs setup —
not by secrecy:

- **Run spec** (`AttackerEnvSpec` / `DefenderEnvSpec`) — the runtime information the agent acts on:
  objective + identity/knowledge (the attacker's own foothold `{name, host, user}`; the defender's host
  inventory `{name, ip, role}`). Handed to the agent via `build_config`. **No keys, no bastion, no
  routing** — the agent doesn't need them at runtime.
- **`SetupAccess`** — the setup-time information: a list of `{name, host, user, port, ssh_key,
  ssh_common_args}`, one per reachable host, carrying the scoped key and the bastion ProxyCommand. Used by
  trusted plugin setup code to stand the system up.

Credentials and routes live in `SetupAccess` because that's where setup uses them — the split is by
purpose, not a rule that they must be hidden from the agent. The security doesn't rest on that secrecy: it
rests on credential **scoping** (§1 — a leaked scoped key only opens what that system could already reach)
plus **management-plane isolation** (§3). So agent-facing specs may even carry IPs — the control is
scoping + isolation, **not address secrecy** (see §3).

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

Every telemetry-consuming defender reads its **own per-experiment Elasticsearch on the defender box** —
there is no shared, persistent harness ES. This is **box mode**, and all three ES defenders (`llm_soc`,
`deception`, `prompt_injection`) use it:

- MHBench runs `telemetry_relay.py` (`telemetry_relay.service`) on the per-experiment mgmt host
  (`10.0.1.10:9200`), forwarding byte-for-byte to a dest from `/etc/telemetry_relay/dests.json`.
- The defender stands up ES on the isolated box (`DefenderPlugin.prepare_box_es`, on the base) and opens
  an ssh -L tunnel to read it. It declares the box port it needs via `DefenderPlugin.box_ingress()`
  (`{"telemetry": [9200]}`), and `MHBenchEnvironment.program_ingress()` both opens that port and points
  the relay at the box (`request-ingress --telemetry`). Victim sensors ship to the relay → box ES; the
  runner does **no** `InstallFalco`/sysflow-repoint (the environment owns sensor shipping), and
  attacker↔box is severed.
- `prepare_box_es` is **fail-closed**: if there is no defender box it raises — there is no
  shared-harness-ES fallback. (The old shared ES — a `mhbench-elasticsearch` container on `cfg.host_ip`,
  bootstrapped by a `deception/setup.py` — has been removed, along with that bootstrap.)

**Why the relay is necessary (and sufficient).** The defender box is on an isolated subnet and victims
**cannot initiate** connections to it (one-way isolation: box→victims allowed, victim→box blocked). So
victims can't ship to the box directly; the mgmt-host relay — which victims *can* reach and which *can*
reach the box — bridges that gap. One interface expresses the whole need: the defender names a port
(`box_ingress()`), the environment opens it and routes the relay there (`program_ingress()`). There is no
separate `telemetry_ingest()`/`program_telemetry()`/`TelemetryRoute` interface — that was unbuilt
fan-out scaffolding with no consumers, and it was **removed**.

`telemetry_relay_ip()` was also **removed**: in box mode the environment's own relay provisioning points
victim sensors at the relay, so the defender never needs a relay address — it does no sensor install and
reads only its box ES over the tunnel. (A consequence: the relay's internal IP is no longer in the
defender's self-protection set; the mgmt/bastion host it runs on is still protected via `bastion_ip`.)

The decoy *deployment* path (the defender asking the environment for *a decoy*) is a separate, richer
interface that remains deferred; only the *ES consumption* of the decoy defenders was moved to box mode.

### What does NOT work (network *reachability*)

Telemetry flow is isolated; **raw network reachability is not.** On OpenStack
(`MHBench/src/deployment/network_deployer.py`):

- every topology subnet, including victim subnets, is attached to a router whose **external gateway SNATs
  to the provider network** (where the harness host and the on-prem infrastructure live), and
- victim egress defaults to **`0.0.0.0/0`** (`internet_egress = True` by default,
  `abstractions/network.py`), with **no per-destination scoping**.

So a compromised victim can open a socket **directly** to the harness host (`cfg.host_ip`, `10.81.1.x`)
and the rest of the provider net — bypassing the relay. Removing the shared harness ES (above) took the
highest-value target off that path — there is no longer a central telemetry store on the provider net to
read or tamper with — so what remains is reachability to the harness host/manager and the provider
network generally. That is now a **defense-in-depth** gap rather than a direct integrity hole, but it
should still be closed.

Why it isn't already fixed: OpenStack security groups are **allow-only** (no deny rules), so you can't
"deny `10.81.1.x` while allowing `0.0.0.0/0`." The only egress knob is `internet_egress`, and setting it
`False` today restricts a victim to its **own CIDR only** — which also severs the relay (`10.0.1.10`),
because the OpenStack backend, unlike GCP (`gcp_backend.py` adds `management.cidr` to its restricted
egress-allow set), does **not** allow the management CIDR. GCP's exposure is narrower only by topology (no
provider subnet to reach; NAT goes to the internet), not by an explicit block of the mgmt host.

> **Fix shape** (MHBench-side, environment-owned): make victim egress an **allow-list** of
> `{all internal subnet CIDRs} + {management.cidr}` and drop the blanket `0.0.0.0/0` + provider-net
> reachability — i.e. set instrumented victim subnets to `internet_egress: False` **and** fix the
> OpenStack backend to include `management.cidr` in the restricted egress-allow (mirroring GCP), so the
> relay keeps working while the harness ES and the internet become unreachable from victims. Prefer **box
> mode** as the standing posture. Needs live validation; see the engineering notes for the full change
> set. Until then, OpenStack victim→control-plane reachability is a documented known limitation.
