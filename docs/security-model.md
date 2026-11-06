# Security model

The arena pits an offensive agent against a victim network (and optionally a defender) inside a cloud
tenant the harness owns. Its security model exists to keep the **game honest**: the attacker must *earn*
its access by playing, the defender must not peek at or tamper with its own ground truth, and neither can
reach the harness's own control plane. Two invariants carry almost all of that weight:

1. **No god key** — the environment issues a separate, scoped credential per system.
2. **Run spec vs setup access** — each system's runtime spec (what the agent acts on) is produced
   separately from its setup-time access (the keys + routing the plugin uses to stand it up).

Plus one **management-plane isolation** requirement that address-hiding alone cannot satisfy.

The last section describes the implemented egress policy and the remaining limits of management-plane isolation.

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

### Enforcement: `scripts/tests/test_no_god_key.py`

A regression guard greps every plugin file under `attacker/plugins` and `defender/plugins`
for the signatures of a management-key read (`openstack_config.ssh_key_path`,
`_mhbench_ssh_key`, the default `id_ed25519` path, etc.). It deliberately does **not** flag the *correct*
pattern — consuming the injected `access["ssh_key"]` — because that is exactly what plugins should do.

The test fails on any **new** god-key read. One read remains in a documented baseline, a known
residual with a stated exit:

- `defender/plugins/velociraptor/velociraptor.py` — **deferred**: its server runs on the bastion, which a
  scoped key can't reach; the fix is moving the server onto the defender box, after which it consumes
  `SetupAccess` like the others.

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

## 4. Egress policy and isolation limits

The harness host and the per-experiment management host are distinct. The harness runs the manager; MHBench's management host provides the SSH jump path and telemetry relay. Victim telemetry reaches a defender's Elasticsearch through the relay when the defender requests telemetry ingress.

For non-routed environments, `internet_egress: false` restricts new outbound connections to topology subnet CIDRs and the management host's /32, with DHCP preserved. OpenStack removes default allow-all egress rules before applying this policy. GCP applies the same destination policy with its metadata/DNS endpoint exception. Ingress still requires the destination's own policy; an outbound allowance alone does not establish an application path.

In routed environments, the permitted control and data destinations are kept separate. Data subnets have no Neutron gateway or router attachment, and guest forwarding guards reject transit traffic entering or leaving a router's control NIC. See MHBench's routing guide for the routed interface and reply-source permissions.

`internet_egress` defaults to true. A non-routed victim with unrestricted egress can therefore reach provider-network services through Neutron SNAT if those services accept it. Restricted egress removes the blanket allowance; it does not deny an address already covered by a topology CIDR or the management-host exception, and it preserves the management services allowed by their security group.

OpenStack security groups are allow-only, so unrestricted Internet egress cannot simultaneously exclude an arbitrary provider CIDR. Choose topology egress settings and control-service permissions explicitly; credential scoping and the telemetry relay do not by themselves prevent raw network access to the harness.
