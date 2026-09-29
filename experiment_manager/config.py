import os
from pathlib import Path
from typing import Dict, Optional

import yaml
from pydantic import BaseModel

_HERE = Path(__file__).parent.parent
_DEFAULT_CONFIG_PATH = _HERE / "config.yaml"


class ExperimentManagerConfig(BaseModel):
    incalmo_dir: Path
    incalmo_python: Optional[Path] = None
    mhbench_dir: Path
    host_ip: str
    output_dir: Path = _HERE / "output"
    ansible_log_dir: str = "experiment/ansible"  # per-experiment subpath under output_dir/<exp>/ for per-host ansible logs
    registry_path: Path = _HERE / "experiment_registry.yaml"
    os_cloud: str = "openstack"
    cloud_backend: str = "openstack"  # "openstack" (default) or "gcp"; gcp routes MHBench via mhbench_config and skips OpenStack clean-slate
    mhbench_config: Optional[str] = None  # passed to MHBench cli as --config (relative to mhbench_dir), e.g. "config/config.gcp.yaml"; None = MHBench default (OpenStack)
    gcp_relay_ip: str = "10.0.1.10"  # GCP-only: internal IP of the management/bastion host on the victim-reachable management CIDR (10.0.1.0/24) where a socat ES relay (falco-es-relay.service) listens on :9200. GCP victims' egress firewall blocks the on-prem harness ES (host_ip 10.81.1.20) but permits the management host, so falcosidekick on GCP victims ships to this relay, which forwards over a reverse SSH tunnel to the harness ES. Unused on OpenStack (victims reach host_ip directly).
    # NOTE: c2_on_kali is NOT a harness-global flag — it is Incalmo-specific and lives on the Incalmo
    # attacker plugin config (incalmo_strategy/incalmo_llm: c2_on_kali). The defender no longer reads
    # it; it protects its own telemetry by never blocking its own ES/mgmt IP (see llm_soc runner).
    max_concurrent_openstack_ops: int = 3   # concurrent PROVISION (VM spin-up) + teardown — compute-heavy, keep tight
    max_concurrent_configures: int = 5       # concurrent ansible CONFIGURE — light, gate wider than provision
    max_concurrent_collects: int = 2         # concurrent post-attacker host-log COLLECT. Collect fans a per-host SSH burst out over the experiment's bastion; many large collects finishing together storm the shared FIP/L3 datapath (which the vCPU/VM trackers don't model) and wedge (observed: collects hung >1.5h). Gate it like configure so the storm never forms. Non-fatal + holds no other slot, so a small cap only briefly delays teardown.
    max_concurrent_attacker_setups: int = 2  # concurrent attacker C2 bring-up (attacker.setup). ONLY enforced when c2_on_kali is on: that mode SSHes into the in-env Kali (no floating IP) THROUGH the bastion to install docker + ship the C2 image + open the tunnel, so many large setups at once storm the shared FIP/L3 datapath and the kali_c2 SSH poll never connects ("SSH to Kali never came up"). Gate it like configure. Legacy beluga-docker C2 setup is a local `docker run` (no bastion SSH) so the gate is skipped there (runs ungated).
    max_retries: int = 3
    max_active_experiments: int = 25  # hard cap on concurrently ACTIVE experiments (DEPLOYING..RUNNING..teardown); excess stays QUEUED. Bounds cluster network load (routers/FIPs/L3) which the vCPU CapacityTracker does not model - at ~27 concurrent, mgmt-FIP SSH began timing out during provisioning.
    max_active_vms: Optional[int] = None  # cap on total VMs across active experiments (harness-tracked by CapacityTracker; counts each topology's VMs incl. mgmt host, plus an estimate of the defender's decoy VMs - see capacity.estimate_decoy_vms). None = no cap. Bounds compute/VM pile-up more predictably than max_active_experiments (which varies 6-35 VMs/env). A single env larger than the cap still runs alone rather than deadlocking.
    # GCP-only capacity limits (opt-in). Both default to "off" so the OpenStack backend's admission is
    # byte-for-byte unchanged. On GCP the binding quota is the GLOBAL CPUS_ALL_REGIONS, which a VM-count
    # cap cannot model (an e2-standard-8 attacker is 1 VM but 8 CPUs), so set these in config.gcp.yaml.
    max_active_cpus: Optional[int] = None  # CPU-budget admission cap sized to the GCP global CPUS_ALL_REGIONS quota (minus headroom for the per-experiment C2 host, which is not in the topology). When set, an experiment is admitted only if its GCP vCPU cost fits the remaining budget; an env whose own cost exceeds the budget waits in QUEUED rather than provisioning partway and stranding. None = no CPU gate.
    gcp_flavor_cpu_cost: Dict[str, int] = {}  # MHBench flavor -> GCP CPUS_ALL_REGIONS cost (measured live: e2-small/m1.small=1, e2-standard-8/m2.large=8). Feeds max_active_cpus and the decoy CPU estimate; a flavor absent here falls back to the placeholder vCPU count. Empty = no remap (OpenStack).
    max_deployed: int = 10  # back-pressure: cap experiments in the deploy stage (DEPLOYING+DEPLOYED). A deploy slot is held from provision-start until configure-start, so when configure backs up, provisioning halts instead of piling up idle hosts.
    attacker_timeout_seconds: Optional[float] = None  # harness-enforced attacker wall-clock cap on REAL elapsed time; None = no cap. On timeout the harness SIGTERMs the attacker (escalating to a SIGKILL of its process group if it ignores that) and marks status TimedOut (terminal, no retry). No rate-limit backoff credit — a heavily-throttled run is measured on real time, so raise the cap if throttling pushes healthy runs over it.
    ansible_verbosity: int = int(os.environ.get("ANSIBLE_VERBOSITY", "0"))  # 0-4 (-vvvv); default from $ANSIBLE_VERBOSITY (main.sh), config.yaml overrides
    deception_dir: Optional[Path] = None
    # How long to wait for a defender to finish arming (its strategy's initialize():
    # booting decoys, planting fake data and honey credentials) before the attacker
    # is allowed to start. Generous by default - arming is bounded by real VM boots
    # and ansible runs, and scales with the arsenal size. Exceeding it fails the
    # experiment rather than silently racing.
    defender_ready_timeout_seconds: float = 1800
    attacker_setup_started_timeout_seconds: float = 120  # handshake backstop: how long the arena waits for the attacker's setup_started ack (emitted at the top of setup) before giving up. NOT the setup/ready cap — setup itself (C2 bring-up, foothold prep) is bounded by its own internal waits.
    deception_python: Optional[Path] = None
    # Background-traffic (third plugin class): local checkout of the
    # caldera-human-traffic repo, deployed onto victim hosts by the CalderaHuman
    # traffic plugin. None (default) = no traffic layer available; a run that asks
    # for one then fails fast with a clear message rather than a silent no-noise run.
    bgtraffic_dir: Optional[Path] = None
    # Velociraptor EDR defender: dir holding the velociraptor binary at bin/velociraptor
    # (downloaded once; a single static Go binary). The plugin ships it to the experiment
    # bastion (server) and victim hosts (clients). None (default) = the velociraptor
    # defender is unavailable; selecting it then fails fast with a clear message.
    velociraptor_dir: Optional[Path] = None
    # Detection: Zircolite runs the shipped Sigma Linux ruleset over each host's collected auditd log.
    zircolite_dir: Path = Path.home() / "Zircolite"
    zircolite_python: Optional[Path] = None  # defaults to <zircolite_dir>/.venv/bin/python
    sigma_ruleset: str = "rules/rules_linux.json"  # relative to zircolite_dir; the Auditd/Sysmon-for-Linux ruleset
    # Custom Sigma rules for MHBench's high-value auditd keys (credential access, lateral movement,
    # evasion) that the stock ruleset doesn't cover. A dir of .yml Sigma rules, versioned with the harness.
    custom_sigma_rules_dir: Path = _HERE / "experiment_manager" / "detection" / "sigma_rules"

    def get_incalmo_python(self) -> Path:
        return self.incalmo_python or (self.incalmo_dir / ".venv" / "bin" / "python")

    def get_zircolite_python(self) -> Path:
        return self.zircolite_python or (self.zircolite_dir / ".venv" / "bin" / "python")

    def get_deception_python(self) -> Path:
        return self.deception_python or (self.deception_dir / ".venv" / "bin" / "python")

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ExperimentManagerConfig":
        # An explicit arg wins; else $EXPERIMENT_MANAGER_CONFIG (lets a second manager run a
        # non-default backend safely); else the default config.yaml. Without this a second
        # manager silently loads config.yaml (OpenStack) and its startup clean-slate wipes the
        # shared cloud — see the 2026-09-16 incident.
        if path is None:
            env = os.environ.get("EXPERIMENT_MANAGER_CONFIG")
            path = Path(env) if env else _DEFAULT_CONFIG_PATH
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
