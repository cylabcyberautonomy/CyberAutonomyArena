# How the defenders are coupled to the environment, and the two-spec fix

Today every defender reaches directly into MHBench's checkout, OpenStack, the harness
Elasticsearch, and MHBench's raw topology JSON. Conforming the defender to the arena spec means
the **environment** hands the defender exactly two things, and the defender stops reaching around
it:

- **Setup spec** — the credentials and targets the defender needs to *act on* the estate
  (instrument hosts, read/write telemetry, later take response actions). "How to reach and change
  the estate."
- **Env spec** — the details of the whole environment the defender *reasons about* (hosts, roles,
  accounts, subnets, reachability), knowledge-filtered so the attacker's own subnet never appears.
  "What the estate is."

The defender still instruments the hosts itself (installs/points Falco/sysflow, deploys its own
agents) — the environment does not do that for it. The specs just give it the access and the facts.

---

## The coupling today (grounded in the code)

### A. Reaches into MHBench's checkout for credentials & tools
| Where | What it does | Fixed by |
| --- | --- | --- |
| `canary/canary.py:_mhbench_ssh_key`, `velociraptor/velociraptor.py:_mhbench_ssh_key` | Open `cfg.mhbench_dir/<mhbench_config>`, parse backend + `ssh_key_path` to get the victims' private key | **Setup spec** provides `ssh_key` |
| `velociraptor.py:_topology_path` | `cfg.mhbench_dir/"environments"/<spec>.json` — reads MHBench's env file directly | **Env spec** (hosts); no raw path needed |
| `velociraptor.py:_ansible_playbook_bin` | Runs `cfg.mhbench_dir/.venv/bin/ansible-playbook` — borrows MHBench's venv | **Setup spec** (defender ships/points its own ansible) |

### B. Parses MHBench's raw topology JSON and its `vm_type` vocabulary
| Where | What it does | Fixed by |
| --- | --- | --- |
| `plugins/topology.py:build_network` | Builds Perry's `Network` from `network_data["networks"][0]` — assumes MHBench's exact shape (single network, `subnet_connections`, `vm_type`) | **Env spec** carries neutral `hosts` + subnets |
| `plugins/topology.py:host_users` | **Hardcodes** accounts per `vm_type` (`webserver`→ubuntu+tomcat, else ubuntu) | **Env spec** carries `users` per host |
| `plugins/topology.py:defendable_host_ips` / `telemetry_host_ips` | Filter hosts by `vm_type.startswith("kali")` / `"instrumented"` | **Env spec** (already excludes attacker subnet; `instrumented` flag per host) |
| `build_config` in every defender (`llm_soc`, `deception`, `prompt_injection`, `velociraptor`, `canary`) | Passes `environment.topology_spec` (the MHBench JSON path); each runner `json.loads` it | Defenders read **env spec**, never the path |

### C. Talks to the cloud directly
| Where | What it does | Fixed by |
| --- | --- | --- |
| `llm_soc/runner.py:107`, `prompt_injection/runner.py:140` | `openstack.connect()` (reads OS_*/clouds.yaml) → builds `OpenstackOrchestrator`/`GCPOrchestrator` for response actions (restore host, block IP, deploy decoy) | **Setup spec** provides action access; longer-term, cloud-level actions go through the environment's action API (host-level actions use the setup spec's ssh creds) |

### D. Wires the telemetry pipeline from harness-injected IPs
| Where | What it does | Fixed by |
| --- | --- | --- |
| `defender.py:65` | Injects `management_ip = cfg.host_ip` (harness ES address) + (gcp) `falco_relay_ip` | **Setup spec** telemetry target (`es_endpoint`, `ship_target`) |
| runners: `es_url=http://{management_ip}:{port}`, `Elasticsearch(es_url)`, indices from `perry_cfg.experiment_name` | Read/pre-create per-exp `falco-<exp>`/`sysflow-<exp>` | **Setup spec** carries the endpoint + index names |
| `llm_soc/runner.py:159` sets `perry_cfg.external_ip`; runs `InstallFalco(defendable_host_ips(...), perry_cfg)` | Defender points falcosidekick at the harness ES and installs Falco itself | **Keep** (defender instruments), but inputs come from setup spec (`ship_target`) + env spec (`hosts`), not `cfg.host_ip` + topology parse |

### E. Imports the defender's own framework (Perry) — this coupling stays
Every runner prepends `cfg.deception_dir` to `sys.path` and imports Perry's `Config`, `AnsibleRunner`,
`build_network`, `InstallFalco`, orchestrators, strategies. Perry is the **defender's implementation**,
not the environment — that's fine. What must change is *what Perry is fed*: today it's fed MHBench
topology + OpenStack + `cfg.host_ip`; after the refactor it's fed the setup spec + env spec.

---

## The fix: two specs from the environment

### Setup spec (credentials + targets — the defender *acts* with these)
- `ssh_key`, `bastion_ip`, `entry_user` (root), ProxyCommand shape → reach every host (replaces A, D's `mgmt_ip` threading)
- telemetry target: `es_endpoint` (read + pre-create indices), `ship_target` (victim-reachable address to point sensors at), `falco_index`/`sysflow_index` namespace (replaces D)
- (later) action access for cloud-level response (replaces C's `openstack.connect()`)

### Env spec (environment details — the defender *reasons* about these)
- `hosts`: `id`, `role`, `ip`, `users`, `instrumented` (replaces B)
- subnets + reachability (replaces `build_network`'s topology assumptions)
- knowledge-filtered: attacker subnet excluded

### What changes in this worktree
`experiment_manager/defender/env_spec.py` currently has **one** `DefenderEnvSpec` that conflates both.
Per the two-spec decision it splits into:
- `DefenderSetupSpec` — `ssh_key`, `bastion_ip`, `entry_user`, `telemetry` (the `DefenderTelemetry` already there)
- `DefenderEnvSpec` — `objective`, `hosts`, subnets/reachability

Stage A: the `from_deployed()` adapter fills both from today's MHBench `DeployedEnvironment` +
harness config, so behaviour is unchanged while runners migrate off `topology.py`/`openstack.connect`/
`cfg.host_ip`. Stage B: the real environment plugin emits both specs directly and the adapter is deleted.
