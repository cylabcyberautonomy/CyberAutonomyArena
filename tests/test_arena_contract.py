"""
Arena cross-component contract test — the CI/CD regression guard for the refactor.

WHY THIS EXISTS
    The refactor (see ../WHAT_TO_REFACTOR.md) turns environment / attacker / defender /
    background-traffic into four independent systems. This file pins the contract each
    system exposes to the others, so refactoring one can't silently break what another
    reads from it — WITHOUT deploying anything to the cloud or spending LLM credits.

    Run it before AND after refactoring a component; if it stays green the wiring the other
    components rely on is intact.

TWO TIERS
    FAST (this file — default, no cloud, no LLM, ~1s):
        <venv>/bin/python -m pytest tests/test_arena_contract.py -q
        (e.g. /home/lakshmi/experiment_harness/.venv/bin/python)

    LIVE SMOKE (opt-in, real cloud + LLM credits — NOT run here):
        See tests/README_live_smoke.md. It submits the named baseline combo to a manager
        and asserts the attacker reached the DB tier and the defender armed. Do NOT point it
        at the shared OpenStack manager casually: a manager's startup clean-slate wipes the
        cloud (all projects).

THE NAMED BASELINE COMBO (what must keep working across the refactor):
    environment = equifax_small
    attacker    = incalmo_strategy / GraphSearch
    defender    = llm_soc / FalcoLLM        (reads telemetry; deploys NO decoys)
    traffic     = caldera_human / office_worker   (optional; validated for composability)
"""
from __future__ import annotations

import json
from types import SimpleNamespace
import os
from pathlib import Path

import pytest

# Importing the plugin packages triggers auto-registration of every plugin subclass.
import experiment_manager.attacker.plugins  # noqa: F401
import experiment_manager.defender.plugins  # noqa: F401
import experiment_manager.traffic.plugins   # noqa: F401
from experiment_manager.attacker.plugins.base import AttackerPlugin
from experiment_manager.defender.plugins.base import DefenderPlugin
from experiment_manager.traffic.plugins.base import TrafficPlugin
from experiment_manager.environment import DeployedEnvironment
from experiment_manager.attacker.env_spec import AttackerEnvSpec, AttackerFoothold, SetupAccess
from experiment_manager.experiment.models import ExperimentSpecs

ENV_SPEC = "environments/non-generated/equifax_small.json"  # path (relative to mhbench_dir)
ENV_STEM = "equifax_small"  # the short label = path stem
ATTACKER = {"type": "incalmo_strategy", "strategy": "GraphSearch"}
DEFENDER = {"type": "llm_soc", "strategy": "FalcoLLM"}
TRAFFIC = {"type": "caldera_human", "persona": "office_worker"}

FAKE_ENV = DeployedEnvironment(
    topology_spec="/tmp/equifax_small.json",
    ip="192.168.202.100",   # attacker (kali) IP in equifax_small
    spec=ENV_STEM,
)
# The adversary-safe spec build_config consumes: objective + foothold identity only (no keys/bastion).
FAKE_ATTACKER_SPEC = AttackerEnvSpec(
    objective=ENV_STEM,
    footholds=[AttackerFoothold(name="kali", host="192.168.202.100", user="root")],
)


def _mhbench_dir() -> Path | None:
    """Best-effort locate MHBench's checkout so we can assert the env spec file exists.
    Reads the harness config.yaml if present, else falls back to ~/MHBench. Returns None
    if nothing plausible is found (that check then skips)."""
    import yaml
    for cfg_path in (
        Path(__file__).resolve().parent.parent / "config.yaml",
        Path.home() / "experiment_harness" / "config.yaml",
    ):
        try:
            d = yaml.safe_load(cfg_path.read_text())
            md = d.get("mhbench_dir")
            if md and Path(md).exists():
                return Path(md)
        except Exception:
            continue
    fallback = Path.home() / "MHBench"
    return fallback if fallback.exists() else None


# --------------------------------------------------------------------------- registries

def test_registries_have_expected_plugins():
    """Each system type must still offer the plugins the arena selects by name."""
    assert {"incalmo_strategy", "incalmo_llm", "cai_llm"} <= set(AttackerPlugin._registry)
    assert {"llm_soc", "velociraptor", "deception", "prompt_injection", "canary"} <= set(DefenderPlugin._registry)
    assert {"caldera_human"} <= set(TrafficPlugin._registry)


# ------------------------------------------------------------------ spec validation layer

def test_named_combo_experimentspecs_validates():
    """The user-facing submission for the named combo must validate and round-trip.
    This is the arena's single entry contract: one spec naming all four systems."""
    specs = ExperimentSpecs(
        experiment_name="ci_contract_smoke",
        environment=ENV_SPEC,
        attacker=ATTACKER,
        defender=DEFENDER,
        traffic=TRAFFIC,
    )
    # environment is a validated EnvironmentConfig (bare string → mhbench).
    assert specs.environment.environment_plugin == "mhbench"
    assert specs.environment.environment_spec == ENV_SPEC
    dumped = specs.model_dump()
    # the sub-configs survive a dump/reload cycle (what the registry persists + replays)
    assert dumped["environment"] == {"environment_plugin": "mhbench", "environment_spec": ENV_SPEC}
    assert dumped["attacker"]["strategy"] == "GraphSearch"
    assert dumped["defender"]["strategy"] == "FalcoLLM"
    assert dumped["traffic"]["persona"] == "office_worker"


def test_environmentconfig_selectable_and_backcompat():
    """ExperimentSpecs.environment is a selectable config: accepts the explicit
    {environment_plugin, environment_spec} shape, a bare env-name string, and the legacy {type, spec}
    dict (all back-compat); each validates to the same EnvironmentConfig."""
    explicit = ExperimentSpecs(experiment_name="ci_env_explicit",
                               environment={"environment_plugin": "mhbench", "environment_spec": ENV_SPEC},
                               attacker=ATTACKER)
    assert explicit.environment.environment_plugin == "mhbench"
    assert explicit.environment.environment_spec == ENV_SPEC
    bare = ExperimentSpecs(experiment_name="ci_env_bare", environment=ENV_SPEC, attacker=ATTACKER)
    legacy = ExperimentSpecs(experiment_name="ci_env_legacy",
                             environment={"type": "mhbench", "spec": ENV_SPEC}, attacker=ATTACKER)
    assert (explicit.model_dump()["environment"]
            == bare.model_dump()["environment"]
            == legacy.model_dump()["environment"]
            == {"environment_plugin": "mhbench", "environment_spec": ENV_SPEC})


def test_experimentspecs_without_traffic_still_valid():
    """Traffic is optional: a plain attacker-vs-defender run must not require it."""
    specs = ExperimentSpecs(
        experiment_name="ci_no_traffic",
        environment=ENV_SPEC,
        attacker=ATTACKER,
        defender=DEFENDER,
    )
    assert specs.traffic is None


# ------------------------------------------------- attacker -> runner build_config contract

def test_attacker_env_spec_is_adversary_safe():
    """AttackerEnvSpec could be handed to the adversary and be fine: objective + foothold IDENTITY
    only, no keys / bastion / routing. Those live in the harness-only SetupAccess."""
    spec_fields = set(AttackerEnvSpec.model_fields)
    assert spec_fields == {"objective", "footholds"}, f"spec leaks fields: {spec_fields}"
    foothold_fields = set(AttackerFoothold.model_fields)
    assert foothold_fields == {"name", "host", "user"}, f"foothold leaks fields: {foothold_fields}"
    # anything sensitive must NOT be nameable on the adversary-safe types
    for banned in ("ssh_key", "ssh_common_args", "jump", "bastion", "key"):
        assert banned not in spec_fields and banned not in foothold_fields


def test_foothold_access_is_harness_only_and_carries_routing():
    """SetupAccess is the harness-only side: keys + opaque routing for the trusted plugin's prep."""
    fields = set(SetupAccess.model_fields)
    assert {"ssh_key", "ssh_common_args", "host", "user"} <= fields


def test_defender_self_protection_never_blocks_own_ip():
    """The defender must never block its own telemetry/mgmt IP, with no knowledge of the attacker's
    C2 (that replaced the MHB_C2_ON_KALI attacker-coupled gate). SelfProtectingOrchestrator drops a
    BlockIP aimed at a protected IP and passes everything else through."""
    from experiment_manager.defender.plugins.self_protect import SelfProtectingOrchestrator

    class _Block:
        def __init__(self, ip): self.ip_to_block = ip
    class _Other:  # a non-block action (no ip_to_block)
        pass
    class _Inner:
        def __init__(self): self.ran = None
        def run(self, actions): self.ran = actions; return "ok"

    inner = _Inner()
    skipped = []
    orch = SelfProtectingOrchestrator(inner, {"10.81.1.20", "192.168.1.5"}, on_skip=skipped.append)

    # block on own ES IP is dropped; block on a victim + a non-block action pass through
    result = orch.run([_Block("10.81.1.20"), _Block("192.168.200.10"), _Other()])
    passed = inner.ran
    assert skipped == ["10.81.1.20"]
    assert len(passed) == 2 and passed[0].ip_to_block == "192.168.200.10"
    assert result == "ok"

    # if EVERY action was self-directed, nothing reaches the inner orchestrator
    inner2 = _Inner()
    orch2 = SelfProtectingOrchestrator(inner2, {"10.81.1.20"})
    assert orch2.run([_Block("10.81.1.20")]) is None and inner2.ran is None
    # non-block methods delegate straight through
    assert orch2.protected_ips == {"10.81.1.20"}


def test_environment_produces_both_spec_and_access():
    """The environment serves up the adversary-safe spec AND the harness-only access — the arena
    hands each to the right place; the attacker never parses topology."""
    from experiment_manager.environment import deployer
    assert callable(deployer.attacker_env_spec)
    assert callable(deployer.attacker_setup_access)


def test_attacker_graphsearch_build_config_contract():
    """What the Incalmo runner subprocess reads out of build_config must stay stable."""
    atk = AttackerPlugin._registry["incalmo_strategy"].model_validate(ATTACKER)
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, "http://c2.example:8888")
    assert built["name"] == "ci_exp"
    assert built["strategy"]["name"] == "GraphSearch"
    assert built["environment"] == ENV_STEM
    assert built["c2c_server"] == "http://c2.example:8888"
    assert "blacklist_ips" in built


@pytest.mark.parametrize("cfg", [
    {"type": "incalmo_strategy", "strategy": "GraphSearch"},
    {"type": "incalmo_llm", "abstraction": "shell", "planning_llm": "openrouter/anthropic/claude-sonnet-5"},
])
def test_attacker_never_blacklists_victim_ips(cfg):
    """REGRESSION (commit 'incalmo: never blacklist victim IPs'): the shipped config once
    excluded 192.168.x.10 — webserver0, the DB key-holder — so every run exfiltrated 0 files.
    build_config must exclude ONLY Kali's docker bridge, never a victim subnet."""
    atk = AttackerPlugin._registry[cfg["type"]].model_validate(cfg)
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, "http://c2.example:8888")
    bl = built.get("blacklist_ips", [])
    assert bl == ["172.17.0.0/16"], f"unexpected blacklist: {bl}"
    assert not any(str(ip).startswith("192.168") for ip in bl), f"victim IP blacklisted: {bl}"


# ------------------------------------------------- defender -> runner build_config contract

def test_defender_llm_soc_build_config_contract():
    """What the FalcoLLM runner reads out of build_config must stay stable, and the
    environment's topology_spec must flow through to it (env -> defender contract)."""
    dfn = DefenderPlugin._registry["llm_soc"].model_validate(DEFENDER)
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert built["strategy"] == "FalcoLLM"
    assert built["topology_spec"] == FAKE_ENV.topology_spec
    assert "llm_model" in built


def test_defender_canary_build_config_contract():
    """The canary (connectivity diagnostic) defender: no decoys, no LLM, stdlib runner.
    Stage 2b: build_config carries only the connectivity knobs; hosts + per-host SSH access come from
    the arena-injected defender_env_spec / defender_setup_access, NOT from build_config (no ssh_key,
    no topology_spec — that coupling is gone)."""
    dfn = DefenderPlugin._registry["canary"].model_validate({"type": "canary"})
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert set(built["checks"]) <= {"ssh", "resolve", "telemetry", "canary_event"}
    assert "fail_closed" in built
    assert "ssh_key" not in built and "topology_spec" not in built  # migrated to injected specs


def test_defender_velociraptor_build_config_contract():
    """Velociraptor is the least MHBench-coupled defender (a good early refactor target);
    lock its build_config shape too."""
    dfn = DefenderPlugin._registry["velociraptor"].model_validate({"type": "velociraptor"})
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert built["topology_spec"] == FAKE_ENV.topology_spec
    assert "response_mode" in built


# ----------------------------------------------- defender-requested box ingress (env opens exactly these)

def test_defender_box_ingress_declarations():
    """Each defender declares the box ports the environment must open (telemetry->box:9200 relay
    route, forward->victim:8000 passthrough). The harness reads box_ingress() at arm and requests
    exactly these — the box surface matches what the defender uses. Config-aware."""
    reg = DefenderPlugin._registry
    assert reg["llm_soc"].model_validate(DEFENDER).box_ingress() == {"telemetry": [9200]}
    assert reg["velociraptor"].model_validate({"type": "velociraptor"}).box_ingress() == {"forward": [8000]}
    assert reg["deception"].model_validate({"type": "deception", "strategy": "ReactiveLayered"}).box_ingress() == {"telemetry": [9200]}
    # canary is config-aware: telemetry checks -> request 9200; ssh/resolve-only -> open nothing
    assert reg["canary"].model_validate({"type": "canary"}).box_ingress() == {"telemetry": [9200]}
    assert reg["canary"].model_validate({"type": "canary", "checks": ["ssh", "resolve"]}).box_ingress() == {}
    # base default is empty (a defender needing no box ingress opens zero ports)
    assert DefenderPlugin.box_ingress.__doc__  # documented contract


# ------------------------------------------------------------------ arena-facing lifecycle

def test_attacker_lifecycle_methods_present():
    atk = AttackerPlugin._registry["incalmo_strategy"].model_validate(ATTACKER)
    for m in ("setup", "start", "stop", "collect_logs"):
        assert callable(getattr(atk, m)), f"attacker missing {m}()"


def test_defender_lifecycle_methods_present():
    dfn = DefenderPlugin._registry["llm_soc"].model_validate(DEFENDER)
    for m in ("setup", "run", "teardown", "build_config"):
        assert callable(getattr(dfn, m)), f"defender missing {m}()"
    # the arena blocks the attacker on this readiness gate
    assert callable(getattr(DefenderPlugin, "wait_until_ready"))


def test_traffic_lifecycle_methods_present():
    trf = TrafficPlugin._registry["caldera_human"].model_validate(TRAFFIC)
    for m in ("setup", "start", "stop", "collect_logs", "teardown"):
        assert callable(getattr(trf, m)), f"traffic missing {m}()"


def test_capacity_counts_only_topology_vms():
    """Admission counts ONLY the topology VMs — no 'extra'/decoy pre-reservation. capacity must not
    own a decoy estimate, and reserve() must not take extra_vms/extra_vcpus."""
    import inspect
    from experiment_manager.environment import capacity
    assert not hasattr(capacity, "estimate_decoy_vms"), "capacity must not own a decoy estimate"
    params = set(inspect.signature(capacity.CapacityTracker.reserve).parameters)
    assert "extra_vms" not in params and "extra_vcpus" not in params, \
        "reserve() must not carry extra_vms/extra_vcpus"


def test_environment_is_a_plugin():
    """Environment is now the 4th selectable plugin type, with mhbench registered."""
    import experiment_manager.environment.plugins  # noqa: F401 — auto-discovery
    from experiment_manager.environment.plugins.base import EnvironmentPlugin
    assert "mhbench" in EnvironmentPlugin._registry
    assert EnvironmentPlugin._registry["mhbench"].ui_schema()["config_type"] == "mhbench"


def test_build_environment_coerces_bare_string():
    """A bare environment-name string coerces to the mhbench plugin (back-compat), a dict validates
    by type, and an unknown type raises."""
    from experiment_manager.environment import build_environment
    env = build_environment(ENV_SPEC)
    assert env.type == "mhbench" and env.spec == ENV_STEM and env.environment_spec == ENV_SPEC
    assert build_environment({"type": "mhbench", "spec": "x"}).spec == "x"
    with pytest.raises(ValueError):
        build_environment({"type": "nope"})


def test_environment_plugin_lifecycle_and_signals():
    """The plugin exposes the arena-driven lifecycle, and provision/configure/teardown accept the
    lifecycle channel; EnvironmentLifecycle records the emitted signals."""
    import inspect
    from experiment_manager.environment.plugins.base import EnvironmentPlugin
    from experiment_manager.environment import EnvironmentLifecycle, EnvironmentSignal, build_environment
    env = build_environment(ENV_SPEC)  # → MHBenchEnvironment
    for m in ("capacity", "provision", "configure", "collect", "teardown"):
        assert callable(getattr(env, m)), f"environment plugin missing {m}()"
    for m in ("provision", "configure", "teardown"):
        assert "lc" in inspect.signature(getattr(env, m)).parameters, f"{m}() must accept lc"
    # signal channel records status + history
    seen = []
    lc = EnvironmentLifecycle(on_emit=lambda sig, err: seen.append(sig))
    lc.emit(EnvironmentSignal.DEPLOYING)
    lc.emit(EnvironmentSignal.DEPLOYED)
    assert lc.status == EnvironmentSignal.DEPLOYED
    assert lc.history == [EnvironmentSignal.DEPLOYING, EnvironmentSignal.DEPLOYED]
    assert seen == [EnvironmentSignal.DEPLOYING, EnvironmentSignal.DEPLOYED]
    assert {"Deploying", "Deployed", "Configuring", "Configured", "TearingDown", "TornDown", "Failed"} \
        == {s.value for s in EnvironmentSignal}


def test_environment_commands_arena_to_env():
    """The arena also has commands it SENDS to the environment (Provision/Configure/Teardown),
    recorded for an auditable command/ack trace. There is deliberately NO run/start command — the
    environment just idles as VMs once configured."""
    from experiment_manager.environment import EnvironmentLifecycle, EnvironmentCommand
    cmds = {c.value for c in EnvironmentCommand}
    assert cmds == {"Provision", "Configure", "Teardown"}
    assert not any("run" in c.lower() or "start" in c.lower() for c in cmds), \
        "environment must have no run/start command"
    sent = []
    lc = EnvironmentLifecycle(on_command=lambda c: sent.append(c))
    lc.send(EnvironmentCommand.PROVISION)
    lc.send(EnvironmentCommand.TEARDOWN)
    assert lc.commands == [EnvironmentCommand.PROVISION, EnvironmentCommand.TEARDOWN]
    assert sent == [EnvironmentCommand.PROVISION, EnvironmentCommand.TEARDOWN]


def test_experiment_environment_property_returns_plugin():
    """experiment.environment derives the plugin from environment_spec (path → mhbench)."""
    from experiment_manager.experiment.models import Experiment, ExperimentStatus
    exp = Experiment("ci_env_prop", ExperimentStatus.QUEUED, ENV_SPEC)
    assert exp.environment.type == "mhbench"
    assert exp.environment.spec == ENV_STEM
    assert exp.environment_spec == ENV_SPEC
    assert exp.environment_status is None  # its own lifecycle signal, distinct from status


def test_env_plugin_produces_both_agent_specs_and_setup_access():
    """The environment PLUGIN is the producer of the agent-facing specs (attacker_spec + defender_spec)
    and the harness-only SetupAccess for both sides. Invariant: agent-facing specs carry NO credential
    field; SetupAccess carries the key + routing."""
    from experiment_manager.environment import build_environment, DeployedEnvironment
    from experiment_manager.attacker.env_spec import AttackerEnvSpec, AttackerFoothold, SetupAccess
    from experiment_manager.defender.env_spec import DefenderEnvSpec, DefenderHost

    md = _mhbench_dir()
    if md is None:
        pytest.skip("mhbench_dir not resolvable")
    topo = md / ENV_SPEC
    if not topo.exists():
        pytest.skip(f"{ENV_SPEC} not found")

    env = build_environment(ENV_SPEC)
    deployed = DeployedEnvironment(topology_spec=str(topo), ip="192.168.202.100", spec=ENV_STEM)
    cfg = SimpleNamespace(mhbench_dir=md, mhbench_config=None)

    # method presence on the base contract
    for m in ("attacker_spec", "attacker_setup_access", "defender_spec", "defender_setup_access"):
        assert callable(getattr(env, m)), f"env plugin missing {m}()"

    # attacker: agent-facing spec = objective + foothold identity, NO creds
    aspec = env.attacker_spec(deployed, cfg)
    assert isinstance(aspec, AttackerEnvSpec)
    assert aspec.primary and aspec.primary.host == "192.168.202.100"
    assert "ssh_key" not in AttackerFoothold.model_fields and "ssh_key" not in AttackerEnvSpec.model_fields
    # attacker: setup access = harness-only creds + bastion routing
    aacc = env.attacker_setup_access(deployed, "1.2.3.4", cfg)
    assert aacc and isinstance(aacc[0], SetupAccess) and aacc[0].ssh_key
    assert "ProxyCommand" in aacc[0].ssh_common_args

    # defender: agent-facing spec = host inventory (victims only, roles), NO creds
    dspec = env.defender_spec(deployed, cfg)
    assert isinstance(dspec, DefenderEnvSpec)
    names = {h.name for h in dspec.hosts}
    assert names and "attacker" not in names  # kali excluded
    assert any(h.role == "webserver" for h in dspec.hosts) and any(h.role == "database" for h in dspec.hosts)
    assert "ssh_key" not in DefenderHost.model_fields and "ssh_key" not in DefenderEnvSpec.model_fields
    # defender: setup access = one SetupAccess per victim (+ the defender box), with creds
    dacc = env.defender_setup_access(deployed, "1.2.3.4", cfg)
    acc_names = {a.name for a in dacc}
    assert names <= acc_names and "defender_box" in acc_names
    assert all(a.ssh_key for a in dacc)


def _deployed_for(plugin_name):
    """A minimal DeployedEnvironment so attacker_spec can produce a foothold. mhbench derives the
    foothold (kali) from the topology + kali IP; ludus's stub returns a mock regardless."""
    if plugin_name == "mhbench":
        md = _mhbench_dir()
        topo = str(md / ENV_SPEC) if md else "/tmp/x.json"
        return DeployedEnvironment(topology_spec=topo, ip="192.168.202.100", spec=ENV_STEM)
    return None


@pytest.mark.parametrize("plugin_name,spec_val", [
    ("mhbench", ENV_SPEC),
    ("ludus", "ranges/example.yaml"),
])
def test_env_infra_guarantees_are_backend_agnostic(plugin_name, spec_val):
    """The always-provisioned defender box + the telemetry-relay ingest are GENERIC environment
    guarantees — a second, non-MHBench backend (ludus) implements the same interface. Proving these
    aren't MHBench-shaped hacks."""
    from experiment_manager.environment import build_environment
    from experiment_manager.environment.telemetry import TelemetryIngest, TelemetryRoute
    from experiment_manager.defender.env_spec import DefenderBox, DefenderEnvSpec
    from experiment_manager.attacker.env_spec import AttackerEnvSpec
    import asyncio

    env = build_environment({"environment_plugin": plugin_name, "environment_spec": spec_val})
    cfg = SimpleNamespace(gcp_relay_ip="10.0.1.10", mhbench_dir=(_mhbench_dir() or "/tmp"))

    # the generic infra methods are on the base contract
    for m in ("defender_box", "telemetry_ingest", "program_telemetry"):
        assert callable(getattr(env, m)), f"{plugin_name} missing {m}()"

    # always-provisioned defender box, in an isolated subnet (egress/ingress is a design requirement the
    # arena may verify later, not a self-reported field — see ARENA_PLUGIN_REQUIREMENTS.md)
    box = env.defender_box(None, cfg)
    assert isinstance(box, DefenderBox) and box.ip and box.subnet

    # the attacker box is guaranteed too — always SERVED via the attacker spec (footholds non-empty)
    assert env.attacker_spec(_deployed_for(plugin_name), cfg).footholds

    # fixed telemetry-relay ingest (the bake target)
    ing = env.telemetry_ingest(None, cfg)
    assert isinstance(ing, TelemetryIngest) and ing.host and ing.port

    # agent-facing specs are the right types; the defender spec carries the box
    assert isinstance(env.attacker_spec(None, cfg), AttackerEnvSpec)
    dspec = env.defender_spec(None, cfg)
    assert isinstance(dspec, DefenderEnvSpec) and dspec.box is not None and dspec.box.name == box.name

    # the defender's setup access includes an entry to reach the box
    dacc = env.defender_setup_access(None, "1.2.3.4", cfg)
    assert any(a.name == box.name for a in dacc)

    # relay programming accepts routes (multi-stream + fan-out expressed as a route list)
    routes = [TelemetryRoute(source_channel="falco", dest="10.0.0.9:5000", protocol="tcp"),
              TelemetryRoute(source_channel="falco", dest="10.0.0.9:9200", protocol="es-bulk")]
    asyncio.run(env.program_telemetry(None, cfg, routes))


@pytest.mark.parametrize("plugin_name,spec_val", [
    ("mhbench", ENV_SPEC),
    ("ludus", "ranges/example.yaml"),
])
def test_env_issues_scoped_per_system_credentials(plugin_name, spec_val):
    """The environment issues SEPARATE per-system credentials (no single god-key): the attacker key is
    scoped to its foothold only, the defender key to the defender box + victims (not the foothold).
    INVARIANT: no credential in a system's SetupAccess grants access that system couldn't legitimately
    earn — attacker key opens its box and nothing else."""
    from experiment_manager.environment import build_environment
    env = build_environment({"environment_plugin": plugin_name, "environment_spec": spec_val})
    cfg = SimpleNamespace(gcp_relay_ip="10.0.1.10", mhbench_dir=(_mhbench_dir() or "/tmp"),
                          mhbench_config=None)
    deployed = _deployed_for(plugin_name)

    acred = env.attacker_credential(deployed, cfg)
    dcred = env.defender_credential(deployed, cfg)
    assert acred and dcred and acred != dcred  # per-system, not one god-key

    # attacker SetupAccess: all use the attacker cred; hosts are the foothold(s) ONLY
    aacc = env.attacker_setup_access(deployed, "1.2.3.4", cfg)
    assert aacc and all(a.ssh_key == acred for a in aacc)
    foothold_hosts = {f.host for f in env.attacker_spec(deployed, cfg).footholds}
    assert {a.host for a in aacc} <= foothold_hosts

    # defender SetupAccess: all use the defender cred; the attacker foothold is NOT reachable with it
    dacc = env.defender_setup_access(deployed, "1.2.3.4", cfg)
    assert dacc and all(a.ssh_key == dcred for a in dacc)
    assert foothold_hosts.isdisjoint({a.host for a in dacc})


def test_environment_module_exposes_lifecycle():
    """The environment is not a plugin yet, but the arena drives it through these module
    functions. The refactor should turn these into a plugin with the same lifecycle."""
    from experiment_manager.environment import deployer, collect, teardown
    assert callable(deployer.provision_environment)
    assert callable(deployer.configure_environment)
    assert callable(collect.collect_environment)
    assert callable(teardown.teardown_environment)


# ------------------------------------------------------------------------- ui + env object

@pytest.mark.parametrize("registry,key", [
    (AttackerPlugin, "incalmo_strategy"),
    (DefenderPlugin, "llm_soc"),
    (DefenderPlugin, "velociraptor"),
    (DefenderPlugin, "canary"),
])
def test_ui_schema_returns_dict(registry, key):
    schema = registry._registry[key].ui_schema()
    assert isinstance(schema, dict)
    assert schema.get("config_type") == key


def test_deployed_environment_object_shape():
    """DeployedEnvironment is the env -> {attacker, defender} handoff object today.
    The refactor will split it into attacker- and defender-relevant specs; this pins the
    current shape so consumers keep working until then."""
    env = DeployedEnvironment(topology_spec="/x/equifax_small.json", ip="1.2.3.4", spec=ENV_STEM)
    assert env.topology_spec.endswith("equifax_small.json")
    assert env.spec == ENV_STEM


# ---------------------------------------------------------- environment spec (needs MHBench)

def test_equifax_small_spec_exists_and_protects_keyholder():
    """The named environment must exist and still place a Kali attacker + a webserver0 at
    .10 (the DB key-holder the blacklist regression protects). Skips if MHBench isn't local."""
    md = _mhbench_dir()
    if md is None:
        pytest.skip("mhbench_dir not resolvable; skipping env-file check")
    spec_path = md / ENV_SPEC
    if not spec_path.exists():
        pytest.skip(f"{ENV_SPEC} not found under {md}")
    topo = json.loads(spec_path.read_text())
    hosts = [h for net in topo["networks"] for sub in net["subnets"] for h in sub["hosts"]]
    vm_types = {h["vm_type"] for h in hosts}
    assert any(vt == "kali_running" for vt in vm_types), "no kali attacker host in spec"
    assert any(str(h.get("ip_address", "")).endswith(".10") for h in hosts), \
        "no .10 host (DB key-holder) in spec"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
