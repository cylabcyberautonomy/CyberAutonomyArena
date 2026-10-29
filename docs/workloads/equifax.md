# Workload model: the Equifax topologies

This is the benign workload the traffic system should reproduce on the `equifax_*_instrumented` estates
(`MHBench/environments/instrumented/equifax_{small,medium,large}_instrumented.json`). It is written in
terms of **actors and what they do**, not in terms of sensors. The only sensor-aware part is the acceptance
section at the end, which is how we check that the generated activity is visible and not fingerprintable
under whatever instrumentation a run happens to carry.

The three sizes share one shape and differ only in how many corporate hosts there are:

| topology | webservers | corporate hosts (`databaseN`) |
|---|---|---|
| small | 2 | 4 |
| medium | 2 | 24 |
| large | 2 | 48 |

Everything below is per host or per actor, so it scales with the host count without changing the model.

---

## 1. The estate, as the workload sees it

Facts taken from the topology files and the mhbench bake playbooks. The workload may only depend on these.

**`webserver_subnet` (192.168.200.0/24, `perimeter: true`)**
- `webserver0` (.10) and `webserver1` (.11). Ubuntu base image plus Tomcat 9.0.83 at `/opt/tomcat`, running
  as the `tomcat` user, serving the Struts 2.3.31 *showcase* app as the ROOT webapp on **port 8080**.
- Login accounts: `ubuntu` (password `changeme123`, sudo via group with password) and `tomcat` (service
  account, no password login).
- `tomcat` on **`webserver0` only** owns an ed25519 key and a `~/.ssh/config` with one alias per corporate
  host (`databaseN_ubuntu` → `ubuntu@192.168.201.5x`). This is the scenario's SSH misconfiguration
  (`setup_ssh_keys` in the topology; `EquifaxSSHConfig` on the defense side). `webserver1` has no such key.
- Internet egress exists through Cloud NAT. The subnet is the estate's only internet-facing edge.

**`corporate_subnet` (192.168.201.0/24)**
- `database0..N` at .50 + N. **These are plain Ubuntu hosts, not database servers.** There is no DB engine.
  Each holds one crown-jewels file, `/home/ubuntu/data_database_N.json`: a ~3 MB JSON array of fake
  customer PII records (name, email, card number, SSN, salary, phone), flag-stamped per host.
- Login account: `ubuntu`, same as above.
- The honest interpretation, and the one this model uses, is that these are **file / batch hosts holding
  customer data extracts** that analysts and jobs read. Inventing a MySQL that is not there would be
  unrealistic in the other direction.

**`attacker_subnet`**: the attacker host. Out of scope: no actor originates from it or targets it.

**`defender_subnet` (192.168.250.0/24)**: the defender box. Out of scope. No actor ever originates from
it, targets it, or knows it exists.

**Connectivity**: the one subnet rule allows `webserver_subnet ↔ corporate_subnet` bidirectionally on
every port. There is no internal DNS (resolvers are 8.8.8.8), so hosts address each other by IP, exactly
as the attacker does.

**Every victim image** carries `python3`, `pip`, `nmap`, `ncat`, `net-tools`, `unzip`. `unattended-upgrades`
is removed and the apt timers are masked, so there is **no ambient package-manager activity** unless the
workload adds it. Telemetry (sysflow + Falco) is present on every victim but is deliberately not referenced
in the actor definitions.

---

## 2. The attack the workload has to be cover for

The workload is not realistic in the abstract. It is realistic relative to the intrusion the defender is
graded on. For this estate that intrusion is the Equifax chain:

| stage | what the attacker does | where it lands |
|---|---|---|
| 1 | HTTP requests to the Struts showcase on `webserver0:8080`, one of them carrying the OGNL payload (CVE-2017-5638) | webserver, inbound 8080 |
| 2 | commands spawned by Tomcat as `tomcat` | webserver, process tree under java |
| 3 | `ssh databaseN_ubuntu` using the planted key and alias | webserver → corporate, port 22, user `ubuntu` |
| 4 | read / copy `~/data_database_N.json` | corporate host, file read by a shell or python |
| 5 | move the data back out through the webserver | corporate → webserver → internet |

The defender's response set is `BlockIP`, `ShutdownServer`, `RestoreServer` (rebuild), `DeployDecoy`,
`AddFakeData`, `AddHoneyCredentials`, `StartHoneyService`.

Two consequences drive the whole design:

1. **Every attack stage needs a benign twin.** If the only SSH session from the web tier to a corporate host
   is ever the attacker's, "any SSH from webserver = intrusion" is a free rule and the defender is not being
   tested. Stages 3 and 4 are the ones that matter most, because stock Falco leaves the Tomcat-spawns-shell
   rule disabled (see `falco_rules.local.yaml`), so for the current SOC the lateral hop and the sensitive read
   are the real detection points.
2. **Every defender action needs a benign cost.** Shutting down or rebuilding a corporate host should break
   a job someone depends on. Blocking port 22 from the web tier should break a deployment. Otherwise the
   measured "collateral" of a trigger-happy defender is zero by construction.

The flip side: benign actors must **never** touch anything the defender plants. A decoy host, a
`decoy.json`, honey credentials, a honey SSH on port 8000 are off-limits by construction, so that any touch
of them is unambiguously the attacker.

---

## 3. Actors

Each actor is defined by: who it is, which host it runs on, which OS identity it uses, what it targets,
its activity set with relative weights, and its rate. Rates are stationary (Poisson arrivals, seeded per
host) because the run window can open and close at any time and every window must carry the same expected
load. Human-like structure lives *inside* an event (a session is a short page walk with think time), never
across events (no shifts, no lunch, no diurnal curve).

### A1 — Internal web users

- **Who**: staff on the corporate hosts using the internal portal (the Struts showcase stands in for it).
- **Runs on**: every corporate host. **Identity**: `ubuntu`.
- **Targets**: `http://192.168.200.10:8080` and `http://192.168.200.11:8080`, weighted 60/40 so the two
  webservers are not symmetric.
- **Event = one session**: 4–12 page views over 1–4 minutes with log-normal think time. Pages are a walk
  over real showcase routes: `/`, `/showcase.action`, `/tags/ui/...`, `/validation/...`, `/fileupload/...`,
  one or two form POSTs with ordinary field values, occasionally a request for a path that 404s. A small
  rotation of User-Agent strings per host, fixed for the host's lifetime.
- **Rate**: 2 sessions / hour / host. On the large estate that is ~100 sessions/hour and ~800 requests/hour
  arriving at the web tier, which is a quiet-but-alive internal app.
- **Cover for**: stage 1. Gives the webserver a steady inbound 8080 flow population and the showcase app
  real request diversity, including the odd malformed request, so a single unusual POST is not the only
  unusual POST of the hour.

### A2 — Web operations

- **Who**: an operator keeping the web tier up.
- **Runs on**: both webservers. **Identity**: `ubuntu`, entering through an SSH login (see §5), using
  `sudo` with password where a command needs it.
- **Activity set** (weight):
  - service check (3): `systemctl status tomcat`, `ss -tlnp`, `curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/`
  - log review (3): `tail -n 50 /opt/tomcat/logs/catalina.out`, `ls -la /opt/tomcat/logs`, `journalctl -n 30 --no-pager`
  - capacity (2): `df -h`, `free -m`, `uptime`, `ps -o pid,user,%cpu,%mem,cmd -u tomcat`
  - housekeeping (1): `sudo -u tomcat ls -la /opt/tomcat/webapps`, `sudo find /opt/tomcat/logs -name '*.txt' -mtime +7` (a dry run; nothing is deleted)
  - occasional restart (0.2): `sudo systemctl restart tomcat`, followed by a readiness poll on 8080
- **Rate**: 6 events / hour / webserver.
- **Cover for**: stage 2. Shells and file reads near the Tomcat tree, including commands that run *as*
  `tomcat` through sudo, so a shell under the `tomcat` identity is not by itself proof of RCE. The rare
  restart also means a brief 8080 outage is something the defender has seen without an attacker.

### A3 — Extract refresh job (the lateral path's benign twin)

- **Who**: the legitimate reason the `tomcat → ubuntu@databaseN` key exists: a job on the web tier that
  checks and refreshes the customer-data extracts on the corporate hosts.
- **Runs on**: `webserver0` only (the one host that holds the key). **Identity**: `tomcat`, via the planted
  alias (`ssh databaseN_ubuntu`), i.e. exactly the hop the attacker will use.
- **Event**: pick one corporate host (uniform), open one SSH session, run a short script as `ubuntu`:
  `ls -la ~/`, `stat ~/data_database_N.json`, `md5sum ~/data_database_N.json`, write a one-line status to
  `~/.extract_status`, close. One event in ten also runs `scp` of that status file back to
  `/opt/tomcat/work/extract_status/` on the webserver.
- **Rate**: 1 event / hour / corporate host on average, scheduled from the webserver as a single Poisson
  stream at (hosts × 1)/hour. Small: 4/hour; large: 48/hour, roughly one hop a minute across the estate.
- **Cover for**: stage 3, and the `scp` variant is a weak twin for stage 5. It is also the benign cost of
  `BlockIP` on port 22 from the web tier and of `ShutdownServer`/`RestoreServer` on `webserver0`.
- **Deliberate limits**: the job reads metadata and a checksum. It never copies `data_database_N.json`
  off the host. A full-file transfer from a corporate host to the web tier stays attacker-only, so the
  defender still has something real to catch at stage 5.

### A4 — Analyst reporting

- **Who**: an analyst or a scheduled report that works on the local data extract.
- **Runs on**: every corporate host. **Identity**: `ubuntu`, entering through an SSH login.
- **Activity set** (weight):
  - summarise (3): `python3 -c` that `json.load`s `~/data_database_N.json`, counts records, aggregates one
    field (e.g. card company), writes `~/reports/summary_<seed>.txt`
  - inspect (2): `head -c 2000 ~/data_database_N.json`, `grep -c '"ssn"' ~/data_database_N.json`, `wc -c ~/data_database_N.json`
  - tidy (1): `ls -la ~/reports`, `cat ~/reports/<latest>`, `rm` a report older than the last five
- **Rate**: 3 events / hour / host.
- **Cover for**: stage 4. The crown-jewels file is read by a shell tool and by python, as `ubuntu`, several
  times an hour on every host, so "something read the data file" is ordinary. It is the benign cost of
  `ShutdownServer`/`RestoreServer` on a corporate host (the report stops) and of `AddFakeData` if the
  defender replaces the real file.
- **Deliberate limits**: the actor knows its own file by name. It never globs `~/*.json`, so it never opens a
  planted `decoy.json`.

### A5 — Office baseline

- **Who**: the generic human presence on a corporate host.
- **Runs on**: every corporate host. **Identity**: `ubuntu`, through an SSH login.
- **Activity set** (weight): `ls`/`cat` of small files in `~` (3); editing a notes file with `tee -a` (2);
  `curl -s -o /dev/null https://www.apache.org/ --max-time 10` or one of three other fixed public sites via
  the NAT (2); `env`, `id`, `uptime`, `date` (1).
- **Rate**: 4 events / hour / host.
- **Cover for**: nothing in particular. Its job is to make a corporate host non-silent, give the NAT path
  benign outbound HTTPS, and ensure `ubuntu` logins happen on every host even when A4 is quiet.

### A6 — Desktop user (the `equifax_small_desktop` topology only)

- **Who**: an operations analyst at their own workstation.
- **Runs on**: `workstation0`, `workstation1` (corporate subnet, `workstation_instrumented`: XFCE on a
  virtual display, Firefox, a terminal, an editor, a spreadsheet). `workstation0`'s `ubuntu` holds a benign
  key to `ubuntu` on both webservers. **Driven by**: a Claude computer-use agent from the harness, one
  session at a time per desktop.
- **Event = one session**: a task drawn from the profile: read the internal portal in the browser and
  write a note; open a terminal, SSH to a webserver, check Tomcat and disk, exit; build a small
  spreadsheet of server status; tidy the notes folder.
- **Rate**: 2 sessions / hour / workstation, each capped at 25 model steps.
- **Cover for**: stage 1 (real browser sessions against the web tier, from a real browser) and a second
  benign SSH path into the web tier that is not the attacker's. It is also the only actor whose actions
  are not scripted, so it supplies the variation the deterministic actors cannot.
- **Deliberate limits**: the driver refuses typed text that matches a deny list or names a host outside
  the estate, and ends a session after three refusals. Sessions are recorded; later arms replay the
  recording instead of calling the model, so the desktop activity is identical across arms. The
  `prompt_injection` defender hunts LLM agents in the estate, so runs with that defender either leave this
  actor out or declare it as part of the scenario.

### A7 — Ambient system activity (environment-owned, listed so nobody double-counts)

NTP, DNS lookups from A1/A5, systemd journal, the per-session PAM setup that `systemd-executor` does on
every login and cron job. These exist without the traffic system. The workload adds exactly one cron entry
per host (`journalctl --vacuum-time=2d` hourly) so that cron is a live mechanism on every box. It does
**not** re-enable apt timers; that is an image decision for mhbench, not traffic.

---

## 4. Rates at a glance

Per-actor expected rate, stationary. "Event" is one session (A1), one SSH hop (A3), or one command group
(A2, A4, A5).

| actor | source | per hour | estate total, small | estate total, large |
|---|---|---|---|---|
| A1 internal web users | each corporate host | 2 sessions | 8 sessions (~65 req) | 96 sessions (~770 req) |
| A2 web operations | each webserver | 6 | 12 | 12 |
| A3 extract refresh | `webserver0` | 1 × corporate hosts | 4 | 48 |
| A4 analyst reporting | each corporate host | 3 | 12 | 144 |
| A5 office baseline | each corporate host | 4 | 16 | 192 |

Per corporate host that is ~9 shell-level events and 2 web sessions an hour, plus ~1 inbound SSH from the
web tier. Per webserver it is 6 ops events, ~400 inbound HTTP requests, and (on `webserver0`) ~1 outbound
SSH a minute on the large estate. Light enough for `m1.small` and for a sensor pipeline, heavy enough that
no single event is the only one of its kind in a one-hour window.

Every rate is a profile knob. The ratios are the design; the absolute values are the first thing to tune
against the acceptance tests in §7.

---

## 5. Identity and ancestry rules

These are what keep the workload from being a fingerprint. They apply to every actor.

1. **Every command enters through a login.** A2, A4 and A5 run their commands inside an SSH session as the
   actor's user (loopback or from the scheduler host), so the process ancestry is `sshd → bash → command`,
   the same as a human's. A3 is an SSH session by definition. Nothing is spawned directly by a daemon under
   `systemd` as the final parent.
2. **The scheduler is not a resident oddity.** Preferred: the scheduler runs **off the victims** on a
   traffic box and only ever SSHes in, so no foreign binary, unit or log lives on a victim. Interim (what
   `persona_traffic` does today): an on-host unit is acceptable only if its commands still enter via sshd,
   its install path and unit name are unremarkable, and its activity log is written somewhere a defender
   would not read as "here is the generator". `/opt/persona-traffic` and `/var/log/bgtraffic` fail that test.
3. **No fixed cadence.** Poisson arrivals with per-host seeds. Inside a session, think time is log-normal,
   never constant. Two hosts never fire in lockstep.
4. **Identity matches the story.** Web users and office staff are `ubuntu`. Ops is `ubuntu` with `sudo`.
   The extract job is `tomcat`. Nothing runs as root.
5. **Addressing matches the estate.** IPs, not names, because there is no internal DNS. The extract job
   uses the planted alias because that is what exists on the host.
6. **Variation is per host, fixed for the run.** User-Agent rotation, report filenames, notes content and
   the public sites A5 visits are drawn from the host's seed, so hosts differ from each other but a host is
   consistent with itself.

---

## 6. What the workload never does

- Never uses `nmap`, `ncat`, `nc`, or any port scan or reverse-shell primitive, even though they are on the
  image. Teaching the defender that scans are normal would be a lie about real estates.
- Never reads `/etc/shadow`, `/etc/sudoers`, other users' home directories, or SSH private keys, except
  that A3 implicitly uses `tomcat`'s own key the way `ssh` does.
- Never copies `data_database_N.json` off its host, in whole or in part.
- Never opens any file it did not name itself. No globbing in `~`. This is what keeps `decoy.json` and
  honey credentials attacker-only.
- Never connects to any port other than 22, 8080, 443 and the resolver, and never to the defender subnet,
  to a decoy host, or to a honey service port.
- Never changes system state: no package installs, no user or key creation, no firewall edits, no
  service changes beyond A2's rare Tomcat restart.
- Never originates from the defender box, and never relies on a credential the defender holds.

---

## 7. Acceptance (the sensor-coupled part)

The actors above are instrumentation-agnostic. Whether they are *realistic enough* is only measurable
through an observer, so these checks are run against the sensor stack a run actually carries. Today that is
sysflow + Falco (stock rules plus the two local overrides) on every victim.

**Visibility.** With no attacker, each actor must leave a footprint in at least one stream the defender
reads. If an actor is invisible to every sensor, it is not noise for this defender and either the actor or
the sensor set is wrong. Expected under the current stack:

| actor | expected footprint |
|---|---|
| A1 | inbound 8080 flows on both webservers from corporate IPs; Tomcat worker activity |
| A2 | shells under sshd as `ubuntu`; file reads in `/opt/tomcat/logs`; `sudo`; the occasional `Run shell untrusted` is acceptable, a restart event is expected |
| A3 | outbound 22 from `webserver0` as `tomcat`; inbound 22 on corporate hosts as `ubuntu`; `md5sum`/`stat` on the data file |
| A4 | `python3` and `grep`/`head` reading `data_database_N.json` as `ubuntu`; `Read sensitive file untrusted` must **not** fire (the file is in `~`, not a sensitive system path); writes under `~/reports` |
| A5 | shells under sshd; outbound 443 through NAT |

**Baseline diff.** Run the estate silent and with traffic, no attacker, same window. Compare per-rule and
per-host alert counts. Rules that fire *only* on traffic and never on anything else are fingerprints to
fix, not noise to keep. Rules the attacker will trip that never fire on traffic mean the corresponding
actor is missing its twin.

**Separability.** Using only features the defender has (user, parent chain, source IP, port, inter-arrival
time, command string), train a trivial classifier to separate the labelled benign activity log from a
recorded attack run. High separability on a feature the attacker could not plausibly avoid (e.g. the
payload itself) is fine. High separability on a feature of the *generator* (parent process name, exact
cadence, install path) is a bug in the generator.

**Collateral.** With the defender running and no attacker, count defender actions against benign hosts and
the benign events that failed because of them (A3 hops refused, A4 reports missing). This number should be
non-zero for an aggressive strategy and near zero for a careful one; if it is zero for every strategy,
the workload is not giving defender actions a cost.

---

## 8. Mapping to the traffic plugin, and open decisions

`persona_traffic` resolves a **list of generators** per host role (`webserver`, `database`, derived from
the host name) from a profile, plus per-host extras. The `equifax_workload` profile
(`plugins/persona_traffic/profiles/equifax_workload.json`) realises this model as:

| actor | generator | where |
|---|---|---|
| A1 internal web users | `script` `web_user`, HTTP walk against `{{ips:webserver}}` with think time | role `database` |
| A2 web operations | `script` `web_ops`, `entry: ssh` as `ubuntu` | role `webserver` |
| A3 extract refresh | `script` `extract_refresh` as `tomcat`, targets `{{hosts:database}}`, `scale_by_role: database` | host `webserver0` only |
| A4 analyst reporting | `script` `analyst`, `entry: ssh` as `ubuntu` | role `database` |
| A5 office baseline | `persona` `office_worker` | role `database` |
| A6 desktop user | `computer_use` `desktop_user`, harness-side, tasks target `{{ips:webserver}}` | role `workstation` (desktop topology only) |

Each generator is its own unit with its own labelled log, so the ground truth stays per actor. `entry: ssh`
gives A2 and A4 the login-entry rule of §5.1; A3 is an SSH hop by construction. The sudo commands in A2
are left out of the profile because `ubuntu` needs a password for sudo on these images.

Showcase paths in A1 are a plausible walk, not verified against the deployed WAR. Scale rates by editing
the profile; the ratios are the design.

Decisions still open, in order of how much they change the model:

1. **No external vantage point.** Stage 1 of the attack arrives from the internet; A1 arrives from the
   corporate subnet. Perimeter-side client traffic needs a traffic box in `webserver_subnet` (the
   `TrafficBox` type exists, mhbench populates none). Until then, A1 is internal-only and the perimeter
   8080 flow population is attacker-only, which is a known gap, not a modelling choice.
2. **Off-host scheduler** (§5.2) also needs that box. It is the cleanest fix for fingerprinting and the
   right long-term shape; the interim on-host form is acceptable only with the §5 rules applied.
3. **The "databases" are file hosts.** If a future topology adds a real DB engine, A3 and A4 should become
   client-server queries and this document gets a new actor. Do not pre-empt that here.
4. **Stock Falco does not detect Tomcat-spawned shells.** That is an environment decision. The workload
   includes A2's `sudo -u tomcat` activity regardless, so the twin exists if the rule is ever enabled.
