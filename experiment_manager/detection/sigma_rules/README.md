# Custom Sigma rules (MHBench auditd keys)

Portable Sigma rules that fire on the high-value auditd `-k` keys MHBench's `audit.rules`
emits (see `MHBench/src/playbooks/plays/aux_files/audit.rules`). The shipped SigmaHQ Linux
ruleset leans on process-execution/discovery patterns and does **not** cover these
credential-access / lateral-movement / evasion behaviors, so we author them here.

Each rule keys off the auditd `key` field (the `-k` tag on the rule that produced the event),
which survives into Zircolite's queryable schema. The detection runner points Zircolite at both
the stock `rules_linux.json` and this directory.

These are vendor-neutral Sigma — convertible to Splunk/Elastic/Sentinel via pySigma — not
Zircolite-specific.

| Rule | Auditd key | ATT&CK |
|---|---|---|
| `credential_access_shadow_file.yml` | `etcshadow` | T1003.008 |
| `credential_access_root_ssh_key.yml` | `rootkey` | T1552.004 |
| `execution_memfd_fileless.yml` | `anon_file_create` | T1620 |
| `defense_evasion_timestomp.yml` | `file_timestomp` | T1070.006 |
| `discovery_failed_connect_sweep.yml` | `network_connect_fail` | T1046 |
| `defense_evasion_ebpf_load.yml` | `bpf` | T1562.001 |
| `persistence_kernel_module_load.yml` | `modules` | T1547.006 |
| `privilege_escalation_failed_setuid.yml` | `priv_change` (success=no) | T1548 |
