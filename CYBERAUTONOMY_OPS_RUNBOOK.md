# MHBench Cyber-Autonomy — Operations Runbook & Session Log

_Last updated: 2026-09-23. Covers the attacker-LLM × FalcoLLM-C2Block experiment operations,
the root causes diagnosed, the fixes applied, and the standing operational procedures._

This document spans multiple repos:
- `~/experiment_harness` — the experiment managers (FastAPI/uvicorn) + config
- `~/MHBench` — provisioning / ansible / collect
- `~/Incalmo` — the attacker (Incalmo C2 + LLM agent) and the in-env Kali C2
- `~/Defense-MHBench-compatible` — the LLM-SOC defender (FalcoLLM / FalcoLLM-C2Block)
- `~/o46_mobile` — the status dashboard (dump.py cron → status.json → index.html over Tailscale)

---

## 1. Topology

Three experiment managers run concurrently (each `uvicorn experiment_manager.main:app`):

| Port | Backend | Config | Output tree | Notes |
|------|---------|--------|-------------|-------|
| 8000 | OpenStack | `config.yaml` (default) | `output/` | The main matrix host. `c2_on_kali: true`. |
| 8001 | GCP | `config.gcp.yaml` | `output_gcp/` | GCP-backend manager. |
| 8002 | GCP | `config.gcp2.yaml` | `output_gcp2/` | 2nd GCP-backend manager. |

**Restart hazard:** `_clean_slate` on startup/shutdown deletes ALL OpenStack servers (all-projects)
and the registry is in-memory. Restarting :8000 wipes the OpenStack cloud. GCP managers are separate
processes — never restart them when only :8000 needs it. Always scope kills to the :8000 pid.

### c2_on_kali
The Incalmo C2 runs on the in-env Kali VM (in-tenant `192.168.202.100:8888`, no floating IP).
beluga reaches it via a persistent `ssh -L` tunnel through the experiment's bastion (mgmt FIP).
Victims beacon in-tenant; a FalcoLLM-C2Block defender can `BlockIP` the whole Kali C2 IP.

### Shared FIP / L3 datapath (why setup is brittle)
Each experiment gets its **own** bastion floating IP from one pool (`external`, `192.168.1.0/24`),
but routing is **centralized Neutron L3 (non-DVR)** across just **2 network nodes (beluga1/beluga2)**.
All floating-IP traffic funnels through those nodes' `br-ex` / conntrack / uplink — a shared
bottleneck. Under high concurrency the persistent tunnels lose keepalives and drop. Mitigated by the
2-wide setup gates below; the architectural fix (DVR) is out of scope.

### Concurrency gates (`config.yaml`)
- `max_active_vms: 135` — primary knob (caps total VMs; also keeps ES's disk under the flood watermark).
- `max_active_experiments: 20`
- `max_concurrent_openstack_ops: 2`, `max_concurrent_configures: 2`, `max_concurrent_collects: 2`,
  `max_concurrent_attacker_setups: 2` — the brittle bastion phases are serialized to 2-wide.
- `attacker_timeout_seconds: 2700` (45-min real wall-clock cap → TimedOut), `max_retries: 2`.

---

## 2. Root causes diagnosed & fixes (this session)

### 2.1 "SSH to Kali never came up" — ProxyJump / known_hosts stale-key trap  ★ dominant
**Symptom:** attacker setup fails at `[kali-c2] SSH to Kali … never came up`; intermittent, worsens
under load; only ever the attacker phase (provision/configure never SSH to Kali).
**Root cause (proven live):** `kali_c2.py` reached Kali via `-o ProxyJump=root@<bastion>`. The
command-line `UserKnownHostsFile=/dev/null` does NOT propagate to the ProxyJump hop, so the **bastion**
host key is checked against `~/.ssh/known_hosts`. Bastion FIPs are recycled from a pool, so a reused IP
presents a new key → `REMOTE HOST IDENTIFICATION HAS CHANGED` → fail. Deterministic per reused-IP; was
masked for months because the poll discarded ssh stderr. Ansible was always immune (it uses a
`ProxyCommand` with `/dev/null` on the jump).
**Fix (code, needs manager restart to load):** in `kali_c2.py`, `_ssh_to_kali()` and the tunnel now use
`-o ProxyCommand="ssh -W %h:%p … -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no … root@<bastion>"`
instead of `ProxyJump`. Jump hop ignores known_hosts entirely.
**Bridge (live now, no restart):** `knownhosts_janitor.sh` truncates `~/.ssh/known_hosts` every 20s so
the old ProxyJump code always accept-news. **NOTE:** the janitor must have NO self-limit (an earlier 4h
cap expired and the trap resurfaced — see §4). Retire it once the ProxyCommand fix is live.
Memory: `kali-c2-proxyjump-knownhosts-trap.md`.

### 2.2 ControlMaster poisoning (`Connection closed by UNKNOWN port 65535`)
**Root cause:** the poll ran `ControlMaster=auto`; the first attempt raced to open the master through
the ProxyJump and, under contention, lost → `UNKNOWN:65535`; a half-open socket then poisoned all 45
retries.
**Fix (kali_c2.py):** decoupled the reachability poll from ControlMaster (poll with a plain, non-mux
ssh), open the master explicitly only after reachability is confirmed, and reap any stale/half-open
master with `_close_master` (`ssh -O exit` + unlink) at start and between retries. Result: `UNKNOWN:65535`
count → 0.

### 2.3 Post-attack tunnel drops (`Errno 111` → attacker `exit 1`)  ★ money-waster
**Symptom:** a run attacks for a long time, then dies with `ConnectionError [Errno 111]` on
`127.0.0.1:<localport>/agents` (the ssh -L tunnel dropped), discarding all LLM spend, then retries.
**Root cause:** the tunnel occasionally drops under FIP saturation; the resilient supervisor reconnects
in seconds, but the C2 client made **bare `requests.get/post` with zero retry** — one refused poll in
the gap crashed the whole attacker.
**Fix (`Incalmo/incalmo/api/server_api.py`, applies to next attacker subprocess — NO manager restart):**
`C2ApiClient` now uses a shared `Session` with `HTTPAdapter(max_retries=Retry(total=12, connect=12,
read=2, status=3, backoff_factor=1.5, …))` + a per-request timeout `(10,60)` (via a `Session` subclass).
`connect=12` (refused = never sent → safe to retry, even POST) rides out multi-minute reconnects;
`read=2` bounds double-execution of the non-idempotent `send_command` POST.
**Instrumentation:** `_LoggingRetry` prints a `[c2-retry] <ts> <method> <url> — bridging failure: <err>`
line per retry, so a run's log now shows exactly how many tunnel drops it bridged and when.
Memory: `incalmo-c2-client-retry.md`.

### 2.4 Elasticsearch shard cap blocks defender arming  ★
**Symptom:** a wave of runs retrying with `Defender failed to arm — Defender exited (code 1) while
arming`. Looks model-specific but isn't.
**Root cause:** single-node ES; each run's defender creates per-experiment `falco-<exp>` + `sysflow-<exp>`
indices, each with a primary + an unassigned replica (useless on one node) that still counts against
`cluster.max_shards_per_node` (default 1000). A session's worth accumulated to ~999/1000 → new
`indices.create()` rejected → defender exits while arming.
**Fix:** `PUT _cluster/settings {cluster.max_shards_per_node: 2000}`; `PUT falco-*,sysflow-*/_settings
{number_of_replicas: 0}` (drops phantom replica shards; cluster → green); index template
`mhbench-defender-noreplica` so new falco-/sysflow- default to 0 replicas.
Memory: `es-shard-cap-blocks-defender-arming.md`.

### 2.5 Kali sshd MaxStartups (contributing, not dominant)
`ansible_runner.py run_parallel()` raises the Kali attacker host's `MaxStartups` to `200:30:400` at
configure (mirrors the bastion pre-warm), so the setup connection burst can't trip stock `10:30:100`.
(Superseded as the primary "never came up" cause by §2.1 — see the memory correction.)

### 2.6 Kali SSH-readiness gate at end of configure
`ansible_runner.py run_parallel()` now probes Kali through the pre-warmed bastion master right before
handoff; if Kali is unreachable, configure fails EARLY for a clean retry instead of wasting the
image-build + attacker-setup stages. (Most misses are a later transient, so this closes the
"configure green while Kali is down" hole; the later-transient case is covered by the poll + tunnel.)

### 2.7 Orphaned ssh from `kill -9` restarts
`kill -9` of the manager orphans its in-flight ssh/ansible children (reparented to init); they pile up
on bastion connection slots. `_clean_slate` in `main.py` has an ssh-reaper that SIGKILLs orphaned
OpenStack ssh (id_ed25519) while sparing GCP (gcloud / google_compute / config.gcp / 34.x bastions /
GCP ControlMaster mux masters). Manual scoped reaps used during restarts.

### 2.8 dump.py dashboard bugs
- `qm_` (Qwen) rows were only mapped to the GCP source; the Qwen matrix runs on :8000 → they were
  dropped. Added `qm_` to the :8000 prefix set + a name-dedup (so a name can't double-render).
- `localhost` → `127.0.0.1` for all three manager fetches (localhost could resolve to IPv6 `::1` while
  managers bind IPv4 only → intermittent "Connection refused / keeping last good" staleness).

### 2.9 Timeout analysis (GLM & Qwen) — genuine, not an error
TimedOut runs were investigated with the `[c2-retry]` instrumentation + `actions.json`/`token_usage.json`:
no exceptions/API errors; TimedOut runs make as many high-level actions as Finished ones (Qwen median
14 vs 14) with more LLM calls; varied progressing techniques (LateralMove / Exfil / FindInfo). The high
timeout rate (Qwen ~58%, GLM ~46%) is **model pacing** — thorough/verbose models that don't declare
"done" in 45 min — NOT an infrastructure fault. Lever: raise `attacker_timeout_seconds` if completion
(vs the measured 45-min condition) is wanted.

---

## 3. Standing automation (cron + background)

- **`~/o46_mobile/dump.py`** — cron `* * * * *`; snapshots :8000/:8001/:8002 → `status.json`.
- **`~/experiment_harness/es_index_cleanup.py`** — cron `*/30 * * * *`; reaps `falco-<exp>`/`sysflow-<exp>`
  indices for terminal runs. Safety: never deletes an index whose run is active in any reachable
  registry; deletes only confirmed-terminal runs older than a **6h grace** (keeps recent runs' Falco
  alerts queryable) or unknown-to-all indices older than 2h; **aborts if :8000 is unreachable**. Log:
  `es_index_cleanup.log`. Run with `--dry-run` to preview.
- **`knownhosts_janitor.sh`** (scratch-launched, no self-limit) — truncates `~/.ssh/known_hosts` every
  20s. TEMPORARY bridge for §2.1 until the ProxyCommand fix is live via a restart.

---

## 4. Operational procedures

### Submit a matrix
Submit specs (flat form) to `POST http://127.0.0.1:8000/experiments`:
```json
{"experiment_name":"<prefix>_<abs>_<env>_c2b_t<trial>",
 "environment":"instrumented/<env>_instrumented",
 "attacker_plugin":"incalmo_llm","attacker_spec":{"planning_llm":"<model>","execution_llm":"<model>","abstraction":"incalmo|shell"},
 "defender":{"type":"llm_soc","strategy":"FalcoLLMC2Block","llm_model":"anthropic/claude-sonnet-5"},
 "trial":<0|1|2>,"overwrite":true}
```
Naming convention: `glm_inc_`, `glm_sh_`, `k3_inc_`, `k3_sh_`, `qm_inc_`, `qm_sh_` + `<env>_c2b_t<n>`.
Model IDs: GLM `glm-5.2`; Kimi `kimi-k3`; Qwen `qwen3.8-max`. Envs (12 instrumented): ch, chpe, db,
dbpe, st, stpe, ea, eb, eqs, eqm, eql, ics. Keep names ≤ ~33 chars (SSH ControlPath limit).
Reusable submit scripts are in this session's scratchpad (`submit_*_c2b.py`).

### Restart :8000 safely (to load kali_c2.py / ansible_runner.py / main.py / config.yaml changes)
1. `pgrep -f "uvicorn experiment_manager.main:app --port 8000" | xargs -r kill -9`
2. Scoped orphan reap: SIGKILL PPID=1 ssh with `192.168.` targets; SPARE `34.x` and GCP mux groups.
3. Relaunch detached from `~/experiment_harness`:
   `setsid nohup .venv/bin/python -m uvicorn experiment_manager.main:app --port 8000 > <log> 2>&1 &`
4. Startup runs `_clean_slate` (deletes leftover OpenStack servers — can take ~15–25 min) then binds.
5. **Verify GCP untouched:** `:8001` and `:8002` pids unchanged (`ps -eo pid,lstart,cmd | grep uvicorn`).
6. Re-submit the matrix (registry is in-memory; overwrite=true).
7. If the ProxyCommand fix (§2.1) is now live, the knownhosts_janitor can be stopped.

### Priority scheduling (choose what runs next)
Every experiment carries an integer `priority` (default `0`; **higher = admitted from the queue sooner**;
ties break FIFO). Unlabeled runs (priority 0) behave exactly as before — "whoever fits."
- **At submission:** add `"priority": <int>` to the POST body (0–1000, clamped).
- **On the fly (re-prioritize a still-queued run):** `POST /experiments/<name>/priority` body `{"priority": N}`.
  Returns `requeued: true` if it was still waiting and got re-ranked.
- **Semantics:** a higher-priority run is admitted before lower ones **when it fits**; if it's too big for
  the currently-free capacity, a smaller lower-priority run still fills the gap (no head-of-line stall).
  Applies at every gate: the VM-capacity queue (`CapacityTracker.reserve`, the main queue), the
  active-experiment gate (`_inflight_gate`), and the setup gates (provision/configure/attacker-setup).
- **Implementation:** `experiment/models.py` (`priority` field), `environment/capacity.py`
  (priority-aware `reserve()` + `reprioritize()`), `main.py` (`_gate_priority`, `_inflight_gate` is now a
  `_PriorityLock`, the `/priority` endpoint). Unit-tested in `scratchpad/test_priority.py`.
  **Needs a :8000 restart to activate** (loads at startup).

### Dashboard
Served by `python3 -m http.server 8199 --bind 0.0.0.0 --directory ~/o46_mobile` over Tailscale
(`http://100.81.48.61:8199/`). Adding a matrix grid = a `<section>` panel with `<div class="grid"
id="gridXxx">` + a `buildGrid("gridXxx","<prefix>_","inc|sh","<title>","c2b")` call, and ensure dump.py's
prefix filter includes the prefix. Static files (e.g. large zips) dropped in `~/o46_mobile/` are
curl-able at `http://100.81.48.61:8199/<file>` (no resume — http.server ignores Range).

---

## 5. Files changed this session

| File | Change |
|------|--------|
| `experiment_harness/config.yaml` | `max_active_vms: 135`; added `max_concurrent_collects`, `max_concurrent_attacker_setups`; `c2_on_kali: true` |
| `experiment_harness/experiment_manager/main.py` | ssh-reaper in `_clean_slate` (spares GCP); `_has_gcp_ancestor`; priority locks for collect/attacker-setup; removed pre-launch stale-C2 teardown |
| `experiment_harness/experiment_manager/attacker/plugins/incalmo/kali_c2.py` | ProxyCommand (not ProxyJump); decoupled poll + dead-master reap; resilient auto-reconnect tunnel supervisor; poll stderr capture + hop-attribution probe |
| `MHBench/src/deployment/ansible_runner.py` | Kali MaxStartups raise; Kali SSH-readiness gate at end of configure |
| `Incalmo/incalmo/api/server_api.py` | C2 client retry Session + per-request timeout + `[c2-retry]` logging |
| `Incalmo/incalmo/c2server/c2server.py` | `_purge_stale_dynamic_payloads()` on C2 startup |
| `experiment_harness/es_index_cleanup.py` | NEW — automated ES index reaper (+ cron) |
| `o46_mobile/dump.py` | `qm_` on :8000 source + dedup; `localhost`→`127.0.0.1` |
| `o46_mobile/index.html` | c2b grids: k3 shell, GLM inc, GLM shell, Qwen inc, Qwen shell |

---

## 6. Matrices run this session (all × FalcoLLM-C2Block / Sonnet-5, 12 instrumented envs × 3 trials, :8000)

- `glm_inc_*_c2b` (GLM-5.2 incalmo) — completed
- `glm_sh_*_c2b` (GLM-5.2 shell)
- `k3_inc_*_c2b`, `k3_sh_*_c2b` (Kimi-K3 incalmo + shell) — completed earlier; full data archived
  (`kimi_falcollm_c2b_full_*.zip`)
- `qm_inc_*_c2b` (Qwen3.8-Max incalmo)
- `qm_sh_*_c2b` (Qwen3.8-Max shell)

---

## 7. Open items

- **ProxyCommand fix (§2.1) is staged but not live** — needs a :8000 restart. Until then the
  knownhosts_janitor bridges it. Do the restart between batches, then stop the janitor.
- **Timeouts are genuine** — if Qwen/GLM completion matters more than the 45-min measured condition,
  raise `attacker_timeout_seconds` (costs more credits, slower batch).
- **ES per-experiment indices** still accumulate ~1 shard/run; the cron keeps it bounded (cap 2000).
- **Concurrent-agent worktree:** `o46_mobile/` and some repos are edited by another agent — keep edits
  additive and stage around WIP.
