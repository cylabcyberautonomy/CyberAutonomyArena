"""
Arena cross-component contract test — the CI/CD regression guard for the refactor.

WHY THIS EXISTS
    The arena (see docs/architecture.md) turns environment / attacker / defender /
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
import arena.attacker.plugins  # noqa: F401
import arena.defender.plugins  # noqa: F401
import arena.traffic.plugins   # noqa: F401
import arena.environment.plugins  # noqa: F401 — populate the env registry for registry-driven params
from arena.environment.plugins.base import EnvironmentPlugin
from arena.attacker.plugins.base import AttackerPlugin, PreparedAttacker
from arena.attacker.plugins.incalmo.incalmo import IncalmoPreparedC2
from arena.defender.plugins.base import DefenderPlugin
from arena.traffic.plugins.base import TrafficPlugin
from arena.environment import DeployedEnvironment
from arena.attacker.env_spec import AttackerEnvSpec, AttackerFoothold, SetupAccess
from arena.experiment.models import ExperimentSpecs

ENV_SPEC = "environments/non-generated/equifax_small.json"  # path (relative to mhbench_dir)
ENV = {"environment_plugin": "mhbench", "environment_spec": ENV_SPEC}  # the explicit environment selection (no coercion)
ENV_STEM = "equifax_small"  # the short label = path stem
ATTACKER = {"type": "incalmo_strategy", "strategy": "GraphSearch"}  # for direct plugin model_validate
ATTACKER_PLUGIN = "incalmo_strategy"          # the (plugin, spec) pair — the only way to select an attacker
ATTACKER_SPEC = {"strategy": "GraphSearch"}   # inline spec dict (may also be a path to a JSON/YAML file)
DEFENDER = {"type": "llm_soc", "strategy": "FalcoLLM"}
TRAFFIC = {"type": "caldera_human", "persona": "office_worker"}

# A representative environment_spec per backend, so the env security invariants below run over EVERY
# registered environment plugin — not just mhbench. A newly-registered backend with no sample here is
# yielded with spec_val=None and fails the test loudly: its security coverage must be wired, never
# silently skipped. (ENV_SPEC is defined just below; this list is built lazily in _env_security_params.)
ENV_SAMPLE_SPECS = {"mhbench": "environments/non-generated/equifax_small.json"}


def _env_security_params():
    """(plugin_name, sample_spec) for every registered env plugin — the registry is the source of truth."""
    return [(name, ENV_SAMPLE_SPECS.get(name)) for name in sorted(EnvironmentPlugin._registry)]

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
    assert {"incalmo_strategy", "incalmo_llm", "cai_llm", "terminus_llm", "openshell", "sliver_llm"} <= set(AttackerPlugin._registry)
    assert {"llm_soc", "velociraptor", "deception", "prompt_injection", "canary"} <= set(DefenderPlugin._registry)
    assert {"caldera_human"} <= set(TrafficPlugin._registry)


# ------------------------------------------------------------------ spec validation layer

def test_named_combo_experimentspecs_validates():
    """The user-facing submission for the named combo must validate and round-trip.
    This is the arena's single entry contract: one spec naming all four systems."""
    specs = ExperimentSpecs(
        experiment_name="ci_contract_smoke",
        environment=ENV,
        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC,
        defender=DEFENDER,
        traffic=TRAFFIC,
    )
    # environment is a validated EnvironmentConfig (explicit plugin+spec).
    assert specs.environment.environment_plugin == "mhbench"
    assert specs.environment.environment_spec == ENV_SPEC
    dumped = specs.model_dump()
    # the sub-configs survive a dump/reload cycle (what the registry persists + replays)
    assert dumped["environment"] == {"environment_plugin": "mhbench", "environment_spec": ENV_SPEC}
    assert dumped["attacker"]["strategy"] == "GraphSearch"
    assert dumped["defender"]["strategy"] == "FalcoLLM"
    assert dumped["traffic"]["persona"] == "office_worker"


def test_environmentconfig_requires_explicit_shape():
    """ExperimentSpecs.environment must be the EXPLICIT {environment_plugin, environment_spec}:
    environment_plugin names a registered plugin, environment_spec is a path. The bare-string and legacy
    {type, spec} shorthands are no longer coerced — they're rejected — and an unknown plugin is rejected."""
    explicit = ExperimentSpecs(experiment_name="ci_env_explicit",
                               environment={"environment_plugin": "mhbench", "environment_spec": ENV_SPEC},
                               attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC)
    assert explicit.environment.environment_plugin == "mhbench"
    assert explicit.environment.environment_spec == ENV_SPEC
    assert explicit.model_dump()["environment"] == {"environment_plugin": "mhbench", "environment_spec": ENV_SPEC}
    # a bare string is no longer accepted (was back-compat coercion)
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="x", environment=ENV_SPEC,
                        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC)
    # the legacy {type, spec} dict is no longer accepted
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="x", environment={"type": "mhbench", "spec": ENV_SPEC},
                        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC)
    # an unknown plugin is rejected
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="x",
                        environment={"environment_plugin": "nope", "environment_spec": ENV_SPEC},
                        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC)


def test_attacker_plugin_plus_spec_file(tmp_path):
    """New shape: attacker_plugin selects the implementation; attacker_spec is a PATH to a file
    holding the plugin's bespoke spec. It resolves to the same plugin instance as the embedded form."""
    spec_file = tmp_path / "atk_spec.json"
    spec_file.write_text(json.dumps({"strategy": "GraphSearch", "script_path": "/tmp/replay.json"}))
    specs = ExperimentSpecs(
        experiment_name="ci_plugin_spec",
        environment=ENV,
        attacker_plugin="incalmo_strategy",
        attacker_spec=str(spec_file),
        defender=DEFENDER,
    )
    # resolved into .attacker as the real plugin instance
    assert specs.attacker.type == "incalmo_strategy"
    assert specs.attacker.strategy == "GraphSearch"
    assert specs.attacker.script_path == "/tmp/replay.json"
    # a YAML spec works too, and an absent spec file means plugin defaults
    yspec = tmp_path / "atk.yaml"
    yspec.write_text("strategy: Darkside\n")
    s2 = ExperimentSpecs(experiment_name="x", environment=ENV,
                         attacker_plugin="incalmo_strategy", attacker_spec=str(yspec))
    assert s2.attacker.strategy == "Darkside"


def test_embedded_attacker_is_rejected():
    """The attacker is selected only by attacker_plugin (+ attacker_spec). Passing an embedded
    'attacker' block is rejected ('attacker' is a derived field, not an input)."""
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="x", environment=ENV, attacker=ATTACKER)


def test_attacker_plugin_unknown_name_rejected():
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="x", environment=ENV, attacker_plugin="no_such_plugin")


def test_experimentspecs_without_traffic_still_valid():
    """Traffic is optional: a plain attacker-vs-defender run must not require it."""
    specs = ExperimentSpecs(
        experiment_name="ci_no_traffic",
        environment=ENV,
        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC,
        defender=DEFENDER,
    )
    assert specs.traffic is None


def test_experiment_base_is_environment_plus_attacker():
    """The experiment base is environment + attacker; defender and traffic are optional. A spec with
    only environment + attacker (no defender, no traffic) must validate, with both left None."""
    specs = ExperimentSpecs(
        experiment_name="ci_base_only",
        environment=ENV,
        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC,
    )
    assert specs.defender is None
    assert specs.traffic is None


def test_experimentspecs_requires_an_attacker():
    """environment + attacker are the required base: a spec with no attacker (neither the plugin pair
    nor the embedded form) must be rejected, not fail later mid-run."""
    with pytest.raises(Exception, match="requires attacker_plugin"):
        ExperimentSpecs(experiment_name="ci_no_attacker", environment=ENV)


def test_experimentspecs_requires_an_environment():
    """environment is required (the other half of the base)."""
    with pytest.raises(Exception):
        ExperimentSpecs(experiment_name="ci_no_env",
                        attacker_plugin=ATTACKER_PLUGIN, attacker_spec=ATTACKER_SPEC)


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


def test_environment_produces_both_spec_and_access():
    """The environment serves up the adversary-safe spec AND the harness-only access — the arena
    hands each to the right place; the attacker never parses topology."""
    from arena.environment.plugins.mhbench import deployer
    assert callable(deployer.attacker_env_spec)
    assert callable(deployer.attacker_setup_access)


def test_terminus_build_config_contract():
    """Terminus-2 LLM shell attacker: build_config carries model/api routing + objective + the kali
    box IP the runner drives; ui_schema is well-formed."""
    atk = AttackerPlugin._registry["terminus_llm"].model_validate(
        {"type": "terminus_llm", "model": "anthropic/claude-opus-4-1"})
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, PreparedAttacker())
    assert built["model"] == "anthropic/claude-opus-4-1"
    assert built["foothold_ip"] == "192.168.202.100"
    assert "objective" in built and "max_turns" in built
    assert atk.ui_schema()["config_type"] == "terminus_llm"


def test_openshell_build_config_contract():
    """NVIDIA OpenShell attacker: an LLM coding agent driven under OpenShell on the foothold. agent +
    policy are selectable; build_config carries the provider/key routing, image, generated-policy
    inputs, objective and the kali IP; ui_schema is well-formed."""
    reg = AttackerPlugin._registry["openshell"]
    # default: claude agent (claude-code provider type), restrictive policy (the fully-valid posture)
    atk = reg.model_validate({"type": "openshell"})
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, PreparedAttacker())
    assert built["agent"] == "claude"
    assert built["provider_type"] == "claude-code"
    assert built["cred_envs"] == ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]
    assert built["image"] == ""            # claude omits --from (agent default image)
    assert built["policy"] == "restrictive"
    assert built["foothold_ip"] == "192.168.202.100"
    assert "objective" in built
    # two egress planes: HTTP/forward-proxy CIDRs (valid hostless) + native-TCP only via declared hosts
    assert built["http_cidrs"] and built["http_ports"] == [80, 443, 8080]
    assert built["tcp_hosts"] == [] and built["tcp_ports"] == [22, 445, 3389, 3306, 5432]
    assert built["model"] == "claude-sonnet-4-5"  # per-agent default when model omitted
    assert built["agent_cmd_template"] and "{objective}" in built["agent_cmd_template"]
    # tcp_hosts parse "name" and "name=IP" -> per-host native-TCP endpoints (the only lateral-move path)
    perm = reg.model_validate({"type": "openshell", "policy": "permissive",
                               "tcp_hosts": ["webserver0=192.168.202.10", "database0"]})
    bp = perm.build_config("e", FAKE_ATTACKER_SPEC, PreparedAttacker())
    assert bp["policy"] == "permissive"
    assert bp["tcp_hosts"] == [{"name": "webserver0", "ip": "192.168.202.10"}, {"name": "database0", "ip": ""}]
    # codex uses the codex agent type + CODEX_AUTH_* OAuth creds (not an API key)
    codex = reg.model_validate({"type": "openshell", "agent": "codex",
                                "model": "gpt-5-codex", "image": "x/y:z"})
    b2 = codex.build_config("e", FAKE_ATTACKER_SPEC, PreparedAttacker())
    assert b2["provider_type"] == "codex" and b2["image"] == "x/y:z"
    assert "CODEX_AUTH_ACCESS_TOKEN" in b2["cred_envs"]
    # opencode uses the openrouter inference provider + its documented image
    oc = reg.model_validate({"type": "openshell", "agent": "opencode"}).build_config("e", FAKE_ATTACKER_SPEC, PreparedAttacker())
    assert oc["provider_type"] == "openrouter" and oc["model"] == "openrouter/anthropic/claude-sonnet-5"
    assert oc["image"] == "ghcr.io/anomalyco/opencode:latest" and oc["cred_envs"] == ["OPENROUTER_API_KEY"]
    assert atk.ui_schema()["config_type"] == "openshell"


def test_sliver_llm_build_config_contract():
    """The bare LLM + Sliver C2 attacker: its OWN C2 lifecycle (not _IncalmoAttacker), requires_docker
    False (Sliver is a binary). build_config carries the Sliver C2 coordinates from its own prepared
    baton (operator config + listener) + model routing. (Runner/lifecycle are not live-validated.)"""
    from arena.attacker.plugins.sliver.sliver_c2 import SliverPreparedC2
    atk = AttackerPlugin._registry["sliver_llm"].model_validate(
        {"type": "sliver_llm", "model": "gpt-5", "api_base": "https://api.openai.com/v1"})
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC,
                             SliverPreparedC2(operator_cfg="/run/op.cfg", listener_addr="192.168.202.100:8443"))
    assert built["operator_cfg"] == "/run/op.cfg"            # its own prepared.operator_cfg
    assert built["listener_addr"] == "192.168.202.100:8443"  # its own prepared.listener_addr
    assert built["model"] == "gpt-5"
    assert "objective" in built and "max_turns" in built
    assert atk.requires_docker is False                      # Sliver is a single binary, no harness Docker
    assert atk.ui_schema()["config_type"] == "sliver_llm"


def test_attacker_graphsearch_build_config_contract():
    """What the Incalmo runner subprocess reads out of build_config must stay stable."""
    atk = AttackerPlugin._registry["incalmo_strategy"].model_validate(ATTACKER)
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, IncalmoPreparedC2(local_url="http://c2.example:8888", remote_url="http://kali:8888"))
    assert built["name"] == "ci_exp"
    assert built["strategy"]["name"] == "GraphSearch"
    assert built["environment"] == ENV_STEM
    assert built["c2c_server"] == "http://c2.example:8888"        # from prepared.local_url (the tunnel)
    assert built["agent_c2c_server"] == "http://kali:8888"        # from prepared.remote_url (victim-facing)
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
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, IncalmoPreparedC2(local_url="http://c2.example:8888", remote_url="http://kali:8888"))
    bl = built.get("blacklist_ips", [])
    assert bl == ["172.17.0.0/16"], f"unexpected blacklist: {bl}"
    assert not any(str(ip).startswith("192.168") for ip in bl), f"victim IP blacklisted: {bl}"


# ------------------------------------------------- defender -> runner build_config contract

def test_defender_llm_soc_build_config_contract():
    """What the FalcoLLM runner reads out of build_config must stay stable. The host inventory no longer
    flows via topology_spec: the runner builds its Perry network from the arena-injected defender_env_spec
    (env -> defender contract), so build_config carries NO topology_spec — the defender is env-agnostic."""
    dfn = DefenderPlugin._registry["llm_soc"].model_validate(DEFENDER)
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert built["strategy"] == "FalcoLLM"
    assert "llm_model" in built
    assert "topology_spec" not in built  # migrated to the injected defender_env_spec (hosts)


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
    """Velociraptor now builds its monitored estate from the arena-injected defender_env_spec (in
    setup()), not a topology parse — so build_config carries NO topology_spec (backend-agnostic)."""
    dfn = DefenderPlugin._registry["velociraptor"].model_validate({"type": "velociraptor"})
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert "topology_spec" not in built  # migrated to the injected defender_env_spec
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


# ----------------------------------------------- defender lifecycle (symmetric with the attacker)

def test_defender_lifecycle_signals_and_persist():
    """DefenderLifecycle drives SETUP_STARTED->READY->RUNNING->STOPPING->STOPPED, and the persister
    records each onto the Experiment (defender_status + timestamps) — mirroring the attacker."""
    import asyncio
    from arena.defender.lifecycle import (
        DefenderLifecycle, DefenderSignal, DefenderLifecycleError, signal_persister,
    )
    from arena.experiment.models import Experiment, ExperimentStatus

    exp = Experiment("ci_lc", ExperimentStatus.QUEUED, ENV, defender=None)
    lc = DefenderLifecycle(on_emit=signal_persister(exp))

    async def drive():
        for sig in (DefenderSignal.SETUP_STARTED, DefenderSignal.READY,
                    DefenderSignal.RUNNING, DefenderSignal.STOPPING, DefenderSignal.STOPPED):
            await lc.emit(sig)
        await lc.wait(DefenderSignal.READY)   # already emitted -> returns
    asyncio.run(drive())

    assert exp.defender_status == "Stopped"
    assert exp.defender_setup_started_at is not None
    assert exp.defender_ready_at is not None
    assert exp.defender_started_at is not None      # RUNNING timestamp (back-compat field)
    assert exp.defender_stopping_at is not None
    assert exp.defender_stopped_at is not None

    # FAILED short-circuits a pending wait for a later signal
    exp2 = Experiment("ci_lc2", ExperimentStatus.QUEUED, ENV, defender=None)
    lc2 = DefenderLifecycle(on_emit=signal_persister(exp2))

    async def fail():
        await lc2.emit(DefenderSignal.SETUP_STARTED)
        await lc2.emit(DefenderSignal.FAILED, "arming crashed")
        try:
            await lc2.wait(DefenderSignal.READY, timeout=1)
        except DefenderLifecycleError as e:
            return str(e)
        return None
    err = asyncio.run(fail())
    assert err and "arming crashed" in err
    assert exp2.defender_status == "Failed"


# ------------------------------------------------------------------ arena-facing lifecycle

def test_attacker_lifecycle_methods_present():
    atk = AttackerPlugin._registry["incalmo_strategy"].model_validate(ATTACKER)
    for m in ("setup", "start", "stop", "collect_logs"):
        assert callable(getattr(atk, m)), f"attacker missing {m}()"


def test_defender_lifecycle_methods_present():
    dfn = DefenderPlugin._registry["llm_soc"].model_validate(DEFENDER)
    for m in ("setup", "prepare", "run", "teardown", "build_config"):
        assert callable(getattr(dfn, m)), f"defender missing {m}()"
    # the arena blocks the attacker on this readiness gate
    assert callable(getattr(DefenderPlugin, "wait_until_ready"))
    # external arming (decoy/cred deploy) runs in prepare() and returns a PreparedDefender baton,
    # mirroring the attacker's setup()->PreparedAttacker; run() then only launches the loop.
    assert callable(getattr(DefenderPlugin, "prepare"))


def test_traffic_lifecycle_methods_present():
    trf = TrafficPlugin._registry["caldera_human"].model_validate(TRAFFIC)
    for m in ("setup", "start", "stop", "collect_logs", "teardown"):
        assert callable(getattr(trf, m)), f"traffic missing {m}()"


def test_capacity_counts_only_topology_vms():
    """Admission counts ONLY the topology VMs — no 'extra'/decoy pre-reservation. capacity must not
    own a decoy estimate, and reserve() must not take extra_vms/extra_vcpus."""
    import inspect
    from arena.environment import capacity
    assert not hasattr(capacity, "estimate_decoy_vms"), "capacity must not own a decoy estimate"
    params = set(inspect.signature(capacity.CapacityTracker.reserve).parameters)
    assert "extra_vms" not in params and "extra_vcpus" not in params, \
        "reserve() must not carry extra_vms/extra_vcpus"


def test_environment_is_a_plugin():
    """Environment is now the 4th selectable plugin type, with mhbench registered."""
    import arena.environment.plugins  # noqa: F401 — auto-discovery
    from arena.environment.plugins.base import EnvironmentPlugin
    assert "mhbench" in EnvironmentPlugin._registry
    assert EnvironmentPlugin._registry["mhbench"].ui_schema()["config_type"] == "mhbench"


def test_build_environment_requires_explicit_shape():
    """build_environment takes the explicit {environment_plugin, environment_spec} (or an
    EnvironmentConfig) and returns the plugin instance. A bare string and the legacy {type, spec} dict
    are no longer coerced, and an unknown plugin raises."""
    from arena.environment import build_environment
    env = build_environment({"environment_plugin": "mhbench", "environment_spec": ENV_SPEC})
    assert env.type == "mhbench" and env.spec == ENV_STEM and env.environment_spec == ENV_SPEC
    with pytest.raises(Exception):
        build_environment(ENV_SPEC)                                    # bare string: no longer accepted
    with pytest.raises(Exception):
        build_environment({"type": "mhbench", "spec": "x"})            # legacy {type, spec}: not accepted
    with pytest.raises(Exception):
        build_environment({"environment_plugin": "nope", "environment_spec": "x"})  # unknown plugin


def test_environment_plugin_lifecycle_and_signals():
    """The plugin exposes the arena-driven lifecycle, and provision/configure/teardown accept the
    lifecycle channel; EnvironmentLifecycle records the emitted signals."""
    import inspect
    from arena.environment.plugins.base import EnvironmentPlugin
    from arena.environment import EnvironmentLifecycle, EnvironmentSignal, build_environment
    env = build_environment(ENV)  # → MHBenchEnvironment
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
    assert {"Deploying", "Deployed", "Configuring", "Configured", "Serving", "Idle",
            "TearingDown", "TornDown", "Failed"} == {s.value for s in EnvironmentSignal}


def test_environment_commands_arena_to_env():
    """The arena has commands it SENDS to the environment, recorded for an auditable command/ack trace.
    The environment now HAS an active phase: between CONFIGURED and teardown the arena ACTIVATEs it as a
    request-serving window (a running defender may mutate the topology via EnvActionRequest events) and
    DEACTIVATEs it when the attack ends — it is not a busy loop, just the window in which env-mutation
    events are honoured."""
    from arena.environment import EnvironmentLifecycle, EnvironmentCommand
    cmds = {c.value for c in EnvironmentCommand}
    assert cmds == {"Provision", "Configure", "Activate", "Deactivate", "Teardown"}
    sent = []
    lc = EnvironmentLifecycle(on_command=lambda c: sent.append(c))
    lc.send(EnvironmentCommand.PROVISION)
    lc.send(EnvironmentCommand.ACTIVATE)
    lc.send(EnvironmentCommand.DEACTIVATE)
    lc.send(EnvironmentCommand.TEARDOWN)
    assert lc.commands == [EnvironmentCommand.PROVISION, EnvironmentCommand.ACTIVATE,
                           EnvironmentCommand.DEACTIVATE, EnvironmentCommand.TEARDOWN]
    assert sent == lc.commands


def test_environment_request_trace_and_primitive_defaults():
    """The env↔defender dynamic interface: a running defender sends EnvActionRequest events; the
    lifecycle records each serviced one (experiment data), and the EnvironmentPlugin primitives default
    to UNSUPPORTED so a static environment is unaffected until a backend opts in."""
    import asyncio
    from arena.environment import (
        EnvironmentLifecycle, EnvActionRequest, EnvActionResult, EnvActionKind, EnvRequestUnsupported,
    )
    from arena.environment.plugins.base import EnvironmentPlugin

    # request DTO validates from a plain dict (how the Defense-repo orchestrator emits it)
    req = EnvActionRequest.model_validate({"kind": "AddHost", "name": "decoy0", "role": "apache_vuln"})
    assert req.kind is EnvActionKind.ADD_HOST and req.name == "decoy0"
    assert EnvActionResult(kind=req.kind, ok=True, name="decoy0", ip="1.2.3.4").ok

    # request trace
    rec = []
    lc = EnvironmentLifecycle(on_request=rec.append)
    lc.record_request({"kind": "AddHost", "name": "decoy0", "ok": True, "ip": "1.2.3.4"})
    assert lc.requests == rec == [{"kind": "AddHost", "name": "decoy0", "ok": True, "ip": "1.2.3.4"}]

    # primitive defaults: unsupported + static-topology flag, so a non-dynamic env is unaffected
    class _Static(EnvironmentPlugin, config_type="static_env_contract_test"):
        environment_spec: str = "x"
    st = _Static(environment_spec="x")
    assert st.supports_dynamic_topology() is False
    for kind in (EnvActionKind.ADD_HOST, EnvActionKind.REMOVE_HOST, EnvActionKind.REBUILD_HOST):
        try:
            asyncio.run(st.handle_env_request(None, None, EnvActionRequest(kind=kind), None))
            assert False, f"{kind} should be unsupported by default"
        except EnvRequestUnsupported:
            pass


def test_env_action_handler_window_budget():
    """The defender→env action handler enforces, in order: experiment existence (404), an OPEN serving
    window (409), and the pre-reserved VM budget ceiling; it records every serviced event and degrades an
    unsupported primitive to ok=False instead of crashing. No token check — the UDS is the boundary."""
    import asyncio
    from types import SimpleNamespace
    from arena.env_action_server import handle_env_action
    from arena.environment import EnvActionResult
    from arena.environment.lifecycle import EnvironmentLifecycle
    from arena.environment.plugins.base import EnvironmentPlugin

    class _DynEnv(EnvironmentPlugin, config_type="dyn_env_contract_test"):
        environment_spec: str = "x"
        def supports_dynamic_topology(self):
            return True
        async def add_host(self, experiment, deployed, request, cfg):
            return EnvActionResult(kind=request.kind, ok=True, name=request.name or "decoy", ip="192.168.9.9")
        async def remove_host(self, experiment, deployed, request, cfg):
            return EnvActionResult(kind=request.kind, ok=True, name=request.target)
        async def rebuild_host(self, experiment, deployed, request, cfg):
            return EnvActionResult(kind=request.kind, ok=True, name=request.target)

    lc = EnvironmentLifecycle()
    exp = SimpleNamespace(experiment_name="ci_dyn", environment=_DynEnv(environment_spec="x"),
                          deployed_environment=None,
                          _env_serving=True, _env_budget_remaining=1, _env_lifecycle=lc)

    class _Reg:
        def get(self, name):
            if name != "ci_dyn":
                raise KeyError(name)
            return exp

    reg = _Reg()
    run = lambda p: asyncio.run(handle_env_action(p, registry=reg, cfg=None, lock=None))  # noqa: E731
    add = {"experiment_name": "ci_dyn", "action": {"kind": "AddHost", "name": "decoy0"}}

    assert run({"experiment_name": "nope", "action": {"kind": "AddHost"}})["status"] == 404
    exp._env_serving = False
    assert run(add)["status"] == 409                                 # closed window rejects everything
    exp._env_serving = True

    r = run(add)                                                     # success: ok, ip, budget decrement, traced
    assert r["status"] == 200 and r["ok"] is True and r["ip"] == "192.168.9.9"
    assert exp._env_budget_remaining == 0
    r2 = run(add)                                                    # over budget -> graceful ok=False
    assert r2["ok"] is False and "budget" in r2["error"]
    run({"experiment_name": "ci_dyn", "token": "secret-token",
         "action": {"kind": "RemoveHost", "target": "decoy0"}})     # remove returns a budget slot
    assert exp._env_budget_remaining == 1
    assert len(lc.requests) >= 3                                     # every serviced event recorded

    # an environment that does not support the primitive degrades to ok=False, not a crash
    class _Static(EnvironmentPlugin, config_type="static_env_action_test"):
        environment_spec: str = "x"
    exp.environment = _Static(environment_spec="x")
    exp._env_budget_remaining = 1
    assert run(add)["ok"] is False


def test_mhbench_dynamic_topology_primitives(monkeypatch):
    """The MHBench env plugin fulfils EnvActionRequests by shelling to per-host CLI subcommands:
    supports_dynamic_topology() is True; add_host returns name/ip + a box-relative scoped SetupAccess;
    rebuild/remove pass the target through. Subprocess is stubbed (no cloud)."""
    import asyncio
    from arena.environment import EnvActionRequest, EnvActionKind, build_environment
    import arena.environment.plugins.mhbench.deployer as dep

    env = build_environment(ENV)
    assert env.supports_dynamic_topology() is True

    calls = {}

    def fake_host_op(op, exp, spec, cfg, **kw):
        calls[op] = kw
        return {"name": kw.get("name") or "decoy0", "ip": "192.168.0.42"} if op == "add-host" else {"ok": True}

    monkeypatch.setattr(dep, "_host_op_sync", fake_host_op)
    monkeypatch.setattr(dep, "_mhbench_ssh_key", lambda cfg: "/scoped/defender_key")

    exp = type("E", (), {"experiment_name": "ci_dyn"})()
    add = asyncio.run(env.add_host(exp, None, EnvActionRequest(kind=EnvActionKind.ADD_HOST, name="decoy0", role="apache_vuln", subnet="victim_net"), None))
    assert add.ok and add.ip == "192.168.0.42" and add.name == "decoy0"
    assert add.access is not None and add.access.host == "192.168.0.42" and add.access.ssh_common_args == ""  # box-relative
    assert calls["add-host"] == {"name": "decoy0", "role": "apache_vuln", "subnet": "victim_net"}

    reb = asyncio.run(env.rebuild_host(exp, None, EnvActionRequest(kind=EnvActionKind.REBUILD_HOST, target="192.168.0.11"), None))
    assert reb.ok and reb.name == "192.168.0.11" and calls["rebuild-host"] == {"target": "192.168.0.11"}
    rem = asyncio.run(env.remove_host(exp, None, EnvActionRequest(kind=EnvActionKind.REMOVE_HOST, target="192.168.0.12"), None))
    assert rem.ok and calls["remove-host"] == {"target": "192.168.0.12"}


def test_defender_box_only_execution_enforced():
    """ENFORCEMENT (box execution is the ONLY path): the box-executing defenders have NO arena-execution
    code — a runner must not call openstack.connect(), construct OpenstackOrchestrator/GCPOrchestrator, or
    build an AnsibleRunner to reach victims from the arena. And each declares executes_from_box so the
    arena always deploys the box agent + arms the env channel. This turns "runs from the box" from a
    convention into an invariant: re-introducing an arena-execution path fails this test."""
    import pathlib
    from arena.defender.plugins.base import DefenderPlugin

    root = pathlib.Path(__file__).resolve().parent.parent / "arena" / "defender" / "plugins"
    forbidden = ("openstack.connect(", "OpenstackOrchestrator(", "GCPOrchestrator(", "AnsibleRunner(",
                 "import OpenstackOrchestrator", "import GCPOrchestrator", "import openstack")
    for plug in ("llm_soc", "deception", "prompt_injection"):
        src = (root / plug / "runner.py").read_text()
        for bad in forbidden:
            assert bad not in src, f"{plug}/runner.py has a re-introduced arena-execution path: {bad!r}"

    for ct in ("llm_soc", "deception", "prompt_injection"):
        cls = DefenderPlugin._registry[ct]
        assert getattr(cls, "executes_from_box", False) is True, f"{ct} must set executes_from_box=True"
    # base default off — checks-only / self-contained defenders don't box-execute via this path
    assert DefenderPlugin.executes_from_box is False


def test_defender_vm_budget_optional_default():
    """defender_vm_budget() is opt-in: the base default is [] (no extra VMs), so a defender that never
    changes topology needs no change and reserves topology+0 at admission."""
    from arena.defender.plugins.base import DefenderPlugin
    # DefenderPlugin is abstract; the method ignores self, so call it unbound with a dummy self.
    assert DefenderPlugin.defender_vm_budget(object()) == []


def test_experiment_environment_property_returns_plugin():
    """experiment.environment derives the plugin from the explicit {environment_plugin, environment_spec}."""
    from arena.experiment.models import Experiment, ExperimentStatus
    exp = Experiment("ci_env_prop", ExperimentStatus.QUEUED, ENV)
    assert exp.environment.type == "mhbench"
    assert exp.environment.spec == ENV_STEM
    assert exp.environment_spec == ENV_SPEC
    assert exp.environment_status is None  # its own lifecycle signal, distinct from status


def test_env_plugin_produces_both_agent_specs_and_setup_access():
    """The environment PLUGIN is the producer of the agent-facing specs (attacker_spec + defender_spec)
    and the harness-only SetupAccess for both sides. Invariant: agent-facing specs carry NO credential
    field; SetupAccess carries the key + routing."""
    from arena.environment import build_environment, DeployedEnvironment
    from arena.attacker.env_spec import AttackerEnvSpec, AttackerFoothold, SetupAccess
    from arena.defender.env_spec import DefenderEnvSpec, DefenderHost

    md = _mhbench_dir()
    if md is None:
        pytest.skip("mhbench_dir not resolvable")
    topo = md / ENV_SPEC
    if not topo.exists():
        pytest.skip(f"{ENV_SPEC} not found")

    env = build_environment(ENV)
    deployed = DeployedEnvironment(topology_spec=str(topo), ip="192.168.202.100", spec=ENV_STEM,
                                   project_name="ci_proj")
    from arena.config import EnvBackendConfig
    cfg = SimpleNamespace(mhbench_dir=md, env_backend=EnvBackendConfig(mhbench_config=None))

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
    # Env-resolved subnet structure (the decoy defenders build Perry's Network from this, NOT the backend
    # topology — topology.py is gone). The env resolves the backend network/sg NAMES + per-host users.
    assert dspec.subnets, "defender_spec must carry the subnet structure"
    assert dspec.management_sg == "ci_proj-management_sg"
    ws = next((s for s in dspec.subnets if any(h.role == "webserver" for h in s.hosts)), None)
    assert ws is not None and ws.network == f"ci_proj-{ws.name}" and ws.sec_group == f"ci_proj-{ws.name}_sg"
    assert any("tomcat" in h.users for h in ws.hosts)  # env knows webserver accounts (honey-cred target)
    # The attacker's own segment is NOT in the defended estate (a real blue team doesn't know where the
    # red team sits) — so there's no attacker subnet and no "attacker" field to leak its position.
    assert all(s.name != "attacker_subnet" for s in dspec.subnets)
    assert all(not any(h.role == "kali" for h in s.hosts) for s in dspec.subnets)
    assert not any(hasattr(s, "attacker") for s in dspec.subnets)
    # defender: setup access = one SetupAccess per victim (+ the defender box), with creds
    dacc = env.defender_setup_access(deployed, "1.2.3.4", cfg)
    acc_names = {a.name for a in dacc}
    assert names <= acc_names and "defender_box" in acc_names
    assert all(a.ssh_key for a in dacc)


def test_defender_subnets_excludes_attacker_and_maps_perimeter(tmp_path):
    """_defender_subnets resolves the DEFENDED estate only, backend-agnostically: it excludes the
    attacker's segment AND the defender's own box subnet, resolves backend network/sg names, carries
    per-host users, and maps the topology's `perimeter` marker (NOT attacker adjacency) through. Fully
    self-contained (synthetic topology) so it doesn't depend on which MHBench checkout is configured."""
    from arena.environment.plugins.mhbench.deployer import _defender_subnets
    topo = {
        "name": "net0",
        "networks": [{"name": "net0", "subnets": [
            {"name": "webserver_subnet", "perimeter": True, "hosts": [
                {"name": "webserver0", "vm_type": "webserver_instrumented", "ip_address": "10.0.0.10"}]},
            {"name": "corporate_subnet", "hosts": [
                {"name": "database0", "vm_type": "database_instrumented", "ip_address": "10.0.1.10"}]},
            {"name": "attacker_subnet", "hosts": [
                {"name": "attacker", "vm_type": "kali_running", "ip_address": "10.0.9.10"}]},
            {"name": "defender_subnet", "hosts": [
                {"name": "defender", "vm_type": "ubuntu_base", "ip_address": "10.0.250.10"}]},
        ]}],
    }
    p = tmp_path / "topo.json"
    p.write_text(json.dumps(topo))
    subnets, net_name, mgmt_sg = _defender_subnets(p, "proj")

    names = {s.name for s in subnets}
    assert names == {"webserver_subnet", "corporate_subnet"}  # attacker + defender box excluded
    assert net_name == "net0" and mgmt_sg == "proj-management_sg"
    ws = next(s for s in subnets if s.name == "webserver_subnet")
    assert ws.perimeter is True and ws.network == "proj-webserver_subnet" and ws.sec_group == "proj-webserver_subnet_sg"
    assert ws.hosts[0].users == ["ubuntu", "tomcat"] and ws.hosts[0].telemetry is True
    corp = next(s for s in subnets if s.name == "corporate_subnet")
    assert corp.perimeter is False  # only the marked tier is the bait target
    # the attacker's position never leaks: no subnet carries an attacker flag
    assert all(not hasattr(s, "attacker") for s in subnets)


def _deployed_for(plugin_name):
    """A minimal DeployedEnvironment so attacker_spec can produce a foothold. mhbench derives the
    foothold (kali) from the topology + kali IP."""
    if plugin_name == "mhbench":
        md = _mhbench_dir()
        topo = str(md / ENV_SPEC) if md else "/tmp/x.json"
        return DeployedEnvironment(topology_spec=topo, ip="192.168.202.100", spec=ENV_STEM)
    return None


@pytest.mark.parametrize("plugin_name,spec_val", _env_security_params())
def test_env_infra_guarantees_are_backend_agnostic(plugin_name, spec_val):
    """The always-provisioned defender box + the telemetry-relay routing are GENERIC environment
    guarantees — part of the EnvironmentPlugin interface, not MHBench-specific hacks. Runs over every
    registered env backend."""
    from arena.environment import build_environment
    from arena.defender.env_spec import DefenderBox, DefenderEnvSpec
    from arena.attacker.env_spec import AttackerEnvSpec

    if spec_val is None:
        pytest.fail(f"env plugin {plugin_name!r} has no ENV_SAMPLE_SPECS entry — add one so its "
                    f"infra guarantees are covered")
    env = build_environment({"environment_plugin": plugin_name, "environment_spec": spec_val})
    from arena.config import EnvBackendConfig
    cfg = SimpleNamespace(mhbench_dir=(_mhbench_dir() or "/tmp"), env_backend=EnvBackendConfig(gcp_relay_ip="10.0.1.10"))

    # the generic infra methods are on the base contract. There is no telemetry_ingest/program_telemetry/
    # telemetry_relay_ip: the defender declares the box port it needs via box_ingress(), and
    # program_ingress() both opens it and points the relay at the box — one path, not two.
    for m in ("defender_box", "program_ingress"):
        assert callable(getattr(env, m)), f"{plugin_name} missing {m}()"

    # always-provisioned defender box, in an isolated subnet (egress/ingress is a design requirement the
    # arena may verify later, not a self-reported field — see docs/security-model.md)
    box = env.defender_box(None, cfg)
    assert isinstance(box, DefenderBox) and box.ip and box.subnet

    # the attacker box is guaranteed too — always SERVED via the attacker spec (footholds non-empty)
    assert env.attacker_spec(_deployed_for(plugin_name), cfg).footholds

    # agent-facing specs are the right types; the defender spec carries the box
    assert isinstance(env.attacker_spec(None, cfg), AttackerEnvSpec)
    dspec = env.defender_spec(None, cfg)
    assert isinstance(dspec, DefenderEnvSpec) and dspec.box is not None and dspec.box.name == box.name

    # the defender's setup access includes an entry to reach the box
    dacc = env.defender_setup_access(None, "1.2.3.4", cfg)
    assert any(a.name == box.name for a in dacc)


@pytest.mark.parametrize("plugin_name,spec_val", _env_security_params())
def test_env_issues_scoped_per_system_credentials(plugin_name, spec_val):
    """The environment issues SEPARATE per-system credentials (no single god-key): the attacker key is
    scoped to its foothold only, the defender key to the defender box + victims (not the foothold).
    INVARIANT: no credential in a system's SetupAccess grants access that system couldn't legitimately
    earn — attacker key opens its box and nothing else. Runs over every registered env backend."""
    from arena.environment import build_environment
    if spec_val is None:
        pytest.fail(f"env plugin {plugin_name!r} has no ENV_SAMPLE_SPECS entry — add one so its "
                    f"scoped-credential invariant is covered")
    env = build_environment({"environment_plugin": plugin_name, "environment_spec": spec_val})
    from arena.config import EnvBackendConfig
    cfg = SimpleNamespace(mhbench_dir=(_mhbench_dir() or "/tmp"),
                          env_backend=EnvBackendConfig(gcp_relay_ip="10.0.1.10", mhbench_config=None))
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
    """MHBench is one environment plugin; its deploy/collect/teardown implementation lives under
    environment/plugins/mhbench/ (not the backend-neutral environment package root)."""
    from arena.environment.plugins.mhbench import deployer, collect, teardown
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


# ------------------------------------------------------------------ env↔defender interface contract

def test_defender_box_spec_detects_the_env_defender_box(tmp_path):
    """The environment's defender-relevant spec: defender_box_spec() reports the defender box (or None) in the deployed
    topology includes a defender box. The arena uses it to enforce 'a configured defender requires a
    defender box from the environment' — the check is the ARENA's, not the defender plugin's."""
    from arena.environment.plugins.mhbench.deployer import defender_box_spec

    base = {"networks": [{"name": "victims", "subnets": [
        {"name": "webserver_subnet", "cidr": "192.168.200.0/24",
         "hosts": [{"name": "webserver0", "vm_type": "webserver_instrumented", "ip_address": "192.168.200.10"}]},
    ]}]}
    no_box = tmp_path / "no_box.json"
    no_box.write_text(json.dumps(base))
    assert defender_box_spec(DeployedEnvironment(topology_spec=str(no_box), spec="x"), None) is None

    with_box = json.loads(json.dumps(base))
    with_box["networks"].append({"name": "defender_net", "subnets": [
        {"name": "defender_subnet", "cidr": "192.168.250.0/24",
         "hosts": [{"name": "defender", "vm_type": "ubuntu_base_running", "ip_address": "192.168.250.10"}]},
    ]})
    box = tmp_path / "with_box.json"
    box.write_text(json.dumps(with_box))
    assert defender_box_spec(DeployedEnvironment(topology_spec=str(box), spec="x"), None) is not None


def test_defender_box_spec_none_when_no_env():
    """No deployed environment (or no topology) => cannot assert a box, so the contract check will fail
    a defender run rather than assume one exists."""
    from arena.environment.plugins.mhbench.deployer import defender_box_spec
    assert defender_box_spec(None, None) is None


# ------------------------------------------------------------------ attacker plugins: no god key

def test_c2_builds_ssh_from_scoped_setupaccess():
    """Regression: the foothold C2 reaches the foothold via the SetupAccess (scoped key + env routing),
    not a management key read off disk."""
    from arena.attacker.plugins.incalmo import c2
    fa = SetupAccess(name="foothold", host="192.168.0.9", user="root", ssh_key="/scoped/attacker_key",
                     ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i /jump/fwd root@1.2.3.4"')
    cmd = " ".join(c2._ssh_to_foothold(fa))
    assert "/scoped/attacker_key" in cmd and "ProxyCommand" in cmd and "root@192.168.0.9" in cmd
    assert "id_ed25519" not in cmd
    import inspect
    assert "_mhb_ssh_key" not in inspect.getsource(c2), "c2 reintroduced a management-key read"
