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
from experiment_manager.attacker.env_spec import AttackerEnvSpec, AttackerJump
from experiment_manager.experiment.models import ExperimentSpecs

ENV_NAME = "equifax_small"
ATTACKER = {"type": "incalmo_strategy", "strategy": "GraphSearch"}
DEFENDER = {"type": "llm_soc", "strategy": "FalcoLLM"}
TRAFFIC = {"type": "caldera_human", "persona": "office_worker"}

FAKE_ENV = DeployedEnvironment(
    topology_spec="/tmp/equifax_small.json",
    ip="192.168.202.100",   # attacker (kali) IP in equifax_small
    spec=ENV_NAME,
)
# The attacker-facing spec the attacker actually consumes (a pure DTO the environment produces).
FAKE_ATTACKER_SPEC = AttackerEnvSpec(
    objective=ENV_NAME,
    entry_ip="192.168.202.100",   # the attacker's Kali box
    entry_ssh_key="/tmp/box_key",
    jump=AttackerJump(host="192.168.1.156", ssh_key="/tmp/jump_key"),  # bastion, separate credential
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
        environment=ENV_NAME,
        attacker=ATTACKER,
        defender=DEFENDER,
        traffic=TRAFFIC,
    )
    assert specs.environment == ENV_NAME
    dumped = specs.model_dump()
    # the sub-configs survive a dump/reload cycle (what the registry persists + replays)
    assert dumped["attacker"]["strategy"] == "GraphSearch"
    assert dumped["defender"]["strategy"] == "FalcoLLM"
    assert dumped["traffic"]["persona"] == "office_worker"


def test_experimentspecs_without_traffic_still_valid():
    """Traffic is optional: a plain attacker-vs-defender run must not require it."""
    specs = ExperimentSpecs(
        experiment_name="ci_no_traffic",
        environment=ENV_NAME,
        attacker=ATTACKER,
        defender=DEFENDER,
    )
    assert specs.traffic is None


# ------------------------------------------------- attacker -> runner build_config contract

def test_attacker_env_spec_is_pure_dto_with_scoped_credentials():
    """AttackerEnvSpec is a provider-agnostic DTO the environment produces — no MHBench-specific
    adapter baked in, and the box credential is separate from the jump credential (so neither is a
    single management key)."""
    assert not hasattr(AttackerEnvSpec, "from_deployed"), "DTO must not carry an env-specific adapter"
    spec = FAKE_ATTACKER_SPEC
    assert spec.objective == ENV_NAME
    assert spec.entry_ssh_key == "/tmp/box_key"
    assert spec.jump is not None and spec.jump.ssh_key == "/tmp/jump_key"
    assert spec.entry_ssh_key != spec.jump.ssh_key  # box key is not the jump key


def test_environment_produces_attacker_env_spec():
    """The environment side (MHBench today) is what serves up the AttackerEnvSpec — the arena gets
    it from there, not from the attacker parsing topology."""
    from experiment_manager.environment import deployer
    assert callable(deployer.attacker_env_spec)


def test_attacker_graphsearch_build_config_contract():
    """What the Incalmo runner subprocess reads out of build_config must stay stable."""
    atk = AttackerPlugin._registry["incalmo_strategy"].model_validate(ATTACKER)
    built = atk.build_config("ci_exp", FAKE_ATTACKER_SPEC, "http://c2.example:8888")
    assert built["name"] == "ci_exp"
    assert built["strategy"]["name"] == "GraphSearch"
    assert built["environment"] == ENV_NAME
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
    Its build_config carries the topology + the connectivity knobs the runner needs."""
    dfn = DefenderPlugin._registry["canary"].model_validate({"type": "canary"})
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert built["topology_spec"] == FAKE_ENV.topology_spec
    assert set(built["checks"]) <= {"ssh", "resolve", "telemetry", "canary_event"}
    assert "fail_closed" in built and "ssh_key" in built


def test_defender_velociraptor_build_config_contract():
    """Velociraptor is the least MHBench-coupled defender (a good early refactor target);
    lock its build_config shape too."""
    dfn = DefenderPlugin._registry["velociraptor"].model_validate({"type": "velociraptor"})
    built = dfn.build_config("ci_exp", FAKE_ENV)
    assert built["experiment_name"] == "ci_exp"
    assert built["topology_spec"] == FAKE_ENV.topology_spec
    assert "response_mode" in built


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
    env = DeployedEnvironment(topology_spec="/x/equifax_small.json", ip="1.2.3.4", spec=ENV_NAME)
    assert env.topology_spec.endswith("equifax_small.json")
    assert env.spec == ENV_NAME


# ---------------------------------------------------------- environment spec (needs MHBench)

def test_equifax_small_spec_exists_and_protects_keyholder():
    """The named environment must exist and still place a Kali attacker + a webserver0 at
    .10 (the DB key-holder the blacklist regression protects). Skips if MHBench isn't local."""
    md = _mhbench_dir()
    if md is None:
        pytest.skip("mhbench_dir not resolvable; skipping env-file check")
    spec_path = md / "environments" / f"{ENV_NAME}.json"
    if not spec_path.exists():
        # non-generated layout
        spec_path = md / "environments" / "non-generated" / f"{ENV_NAME}.json"
    if not spec_path.exists():
        pytest.skip(f"{ENV_NAME}.json not found under {md}/environments")
    topo = json.loads(spec_path.read_text())
    hosts = [h for net in topo["networks"] for sub in net["subnets"] for h in sub["hosts"]]
    vm_types = {h["vm_type"] for h in hosts}
    assert any(vt == "kali_running" for vt in vm_types), "no kali attacker host in spec"
    assert any(str(h.get("ip_address", "")).endswith(".10") for h in hosts), \
        "no .10 host (DB key-holder) in spec"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
