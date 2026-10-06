"""
Registry-driven plugin conformance smoke tests — the GENERIC companion to test_arena_contract.py.

WHY THIS EXISTS (and how it differs from test_arena_contract.py)
    test_arena_contract.py pins the *content* each specific plugin's build_config / spec production
    must emit (terminus needs foothold_ip, llm_soc omits topology_spec, …). Those tests only bind the
    plugins named in them: a NEW plugin that silently violates the shared interface passes CI, because
    nothing iterates the registry.

    This file iterates EVERY registered plugin of each system type (attacker / defender /
    environment) and holds it to the SHARED contract its base class promises. A new plugin is subjected
    to it the moment it registers — no edit here needed. When a plugin is non-conformant the failure
    (a) names the plugin (parametrize id, e.g. test_attacker_plugin_conforms[sliver_llm]) and (b) lists
    EVERY problem found for it at once, so a new-plugin author sees the whole checklist in one run
    instead of fix-rerun-repeat.

    Fast, cloud-free, no LLM credits — same tier as test_arena_contract.py:
        <venv>/bin/python -m pytest tests/test_plugin_conformance.py -q

WHAT IS CHECKED (per plugin, generically)
    - discovery:     every config_type declared in a plugin file is actually in the registry (catches a
                     plugin module that failed to import, so it silently never registered).
    - instantiable:  the plugin builds from {"type": <name>} (+ synthesized placeholders for any other
                     required field), so the arena/dashboard can construct it.
    - type identity: instance.type == the registry key.
    - ui_schema:     well-formed PluginUISchema (config_type matches, has label/fields/cartesian_product,
                     each field has field_type/label/key, every show_when references a sibling field key),
                     AND every REQUIRED model field (no default) is exposed as a ui_schema field so the
                     dashboard can supply it.
    - lifecycle:     the methods the arena drives exist and have the right async-ness.
    - build_config:  (attacker/defender) returns a JSON-serializable dict that leaks no SSH/management
                     credential or routing (the agent config is handed to the agent process), and for an
                     attacker never blacklists a victim subnet.

WHAT IS DELIBERATELY NOT HERE
    Per-plugin build_config *content* (which keys a given runner reads) stays in test_arena_contract.py —
    that is legitimately plugin-specific. This file only asserts the shape every plugin must share.
"""
from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Union, get_args, get_origin

import pytest

# Importing the plugin packages triggers auto-registration of every plugin subclass.
import arena.attacker.plugins   # noqa: F401
import arena.defender.plugins   # noqa: F401
import arena.environment.plugins  # noqa: F401
from arena.attacker.plugins.base import AttackerPlugin
from arena.defender.plugins.base import DefenderPlugin
from arena.environment.plugins.base import EnvironmentPlugin
from arena.environment import build_environment
from arena.attacker.env_spec import AttackerEnvSpec, AttackerBox

_ARENA_ROOT = Path(__file__).resolve().parent.parent / "arena"


def _real_plugins(registry: dict) -> list[str]:
    """Registry keys for shipped plugins, sorted. Excludes test doubles (e.g. the _FakeAttacker in
    test_attacker_lifecycle.py registers a '_fake_lifecycle_test' config_type into the real registry);
    shipped plugins never start with '_', and dropping them keeps parametrization order-independent."""
    return sorted(name for name in registry if not name.startswith("_"))

# A canonical adversary-safe spec + deployed env that build_config consumes (no cloud needed).
_FAKE_ATTACKER_SPEC = AttackerEnvSpec(
    objective="conformance",
    box=AttackerBox(name="kali", ip="192.168.202.100", user="root"),
)

# A credential/routing leak in an agent-facing config is exactly what the adversary-safe vs harness-only
# split forbids (see docs/security-model.md). These target SSH/management material specifically — an LLM
# api_key in an agent config is intentional (the agent calls the model), so it is NOT banned here.
_BANNED_CONFIG_KEYS = {"ssh_key", "ssh_common_args", "ssh_private_key", "private_key", "mgmt_key", "jump", "bastion"}
_BANNED_VALUE_SUBSTRINGS = ("id_ed25519", "BEGIN OPENSSH PRIVATE KEY", "ProxyCommand")

# Plugins whose build_config() still carries an SSH/management credential, with the fix tracked
# elsewhere. test_no_god_key.py is the OWNER of tightening these (it fails if the entry goes stale);
# the leak sub-check here defers to it so the two guards agree instead of double-reporting.
_BUILD_CONFIG_LEAK_BASELINE = {
    "velociraptor": "deferred: server-on-bastion reads the mgmt key; see test_no_god_key.py baseline",
}


# --------------------------------------------------------------------------- generic helpers

def _placeholder(annotation):
    """A throwaway value of the right shape for a required field, so a plugin with required config
    (e.g. incalmo_llm.planning_llm) can still be instantiated for structural checks."""
    origin = get_origin(annotation)
    if origin is Union:  # Optional[X] / X | None
        args = [a for a in get_args(annotation) if a is not type(None)]
        return _placeholder(args[0]) if args else "placeholder"
    if annotation is int:
        return 0
    if annotation is float:
        return 0.0
    if annotation is bool:
        return False
    if origin is list:
        return []
    if origin is dict:
        return {}
    return "placeholder"


def _minimal_instance(cls, type_name: str):
    """Build a plugin from {"type": name} plus synthesized placeholders for any OTHER required field.
    Returns (instance, required_extra_field_names)."""
    kwargs = {"type": type_name}
    required_extra: list[str] = []
    for fname, finfo in cls.model_fields.items():
        if fname == "type":
            continue
        if finfo.is_required():
            required_extra.append(fname)
            kwargs[fname] = _placeholder(finfo.annotation)
    return cls.model_validate(kwargs), required_extra


def _ui_schema_problems(cls, type_name: str, required_extra: list[str]) -> list[str]:
    """Every problem with a plugin's ui_schema() — the dashboard renders forms from these with no
    plugin-specific knowledge, so a malformed one must fail CI, not the UI at runtime."""
    problems: list[str] = []
    try:
        schema = cls.ui_schema()
    except Exception as e:  # noqa: BLE001 — a plugin that can't produce a schema is the finding
        return [f"ui_schema() raised {type(e).__name__}: {e}"]
    if not isinstance(schema, dict):
        return [f"ui_schema() returned {type(schema).__name__}, not a dict"]
    if schema.get("config_type") != type_name:
        problems.append(f"ui_schema()['config_type']={schema.get('config_type')!r} != registry key {type_name!r}")
    for required_key in ("label", "fields", "cartesian_product"):
        if required_key not in schema:
            problems.append(f"ui_schema() missing top-level key {required_key!r}")
    fields = schema.get("fields", [])
    if not isinstance(fields, list):
        problems.append("ui_schema()['fields'] is not a list")
        fields = []
    field_keys = set()
    for i, field in enumerate(fields):
        if not isinstance(field, dict):
            problems.append(f"fields[{i}] is not a dict")
            continue
        for required_key in ("field_type", "label", "key"):
            if required_key not in field:
                problems.append(f"fields[{i}] ({field.get('key', '?')}) missing {required_key!r}")
        if "key" in field:
            field_keys.add(field["key"])
    # every show_when must reference a sibling field key that exists (else the condition is dead)
    for field in fields:
        if isinstance(field, dict):
            for controlling_key in (field.get("show_when") or {}):
                if controlling_key not in field_keys:
                    problems.append(
                        f"field {field.get('key')!r} show_when references {controlling_key!r}, "
                        f"which is not a field key in this schema")
    # a required model field (no default) MUST be supplyable by the dashboard -> must be a ui_schema field
    for field_name in required_extra:
        if field_name not in field_keys:
            problems.append(
                f"required model field {field_name!r} (no default) has no ui_schema field — "
                f"the dashboard cannot supply it")
    return problems


def _lifecycle_problems(instance, methods: dict[str, bool]) -> list[str]:
    """`methods` maps method name -> whether it must be a coroutine function. Checks presence,
    callability, and async-ness (a sync method where the arena awaits one, or vice versa, is a break)."""
    problems: list[str] = []
    for name, must_be_async in methods.items():
        method = getattr(instance, name, None)
        if method is None or not callable(method):
            problems.append(f"missing method {name}()")
            continue
        is_async = inspect.iscoroutinefunction(method)
        if must_be_async and not is_async:
            problems.append(f"{name}() must be async (the arena awaits it)")
        if not must_be_async and is_async:
            problems.append(f"{name}() must be sync, not async")
    return problems


def _config_leak_problems(built: dict, where: str) -> list[str]:
    """A build_config() output is written to a file the agent/runner process reads. It must be a
    JSON-serializable dict carrying no SSH/management credential or routing."""
    problems: list[str] = []
    if not isinstance(built, dict):
        return [f"{where} returned {type(built).__name__}, not a dict"]
    try:
        serialized = json.dumps(built)
    except (TypeError, ValueError) as e:
        return [f"{where} output is not JSON-serializable: {e}"]
    for key in built:
        if key in _BANNED_CONFIG_KEYS:
            problems.append(f"{where} leaks banned key {key!r} into the agent config")
    for banned in _BANNED_VALUE_SUBSTRINGS:
        if banned in serialized:
            problems.append(f"{where} output contains banned substring {banned!r} (SSH/routing leak)")
    return problems


def _declared_keys_problems(cls, built) -> list[str]:
    """The plugin↔runner contract: build_config() must emit every key the plugin declares in
    REQUIRED_CONFIG_KEYS. Exercises the SAME validator the arena runs before writing the config, so the
    test and the runtime fail-fast agree. Also guards the declaration's type (a frozenset/set of str)."""
    declared = getattr(cls, "REQUIRED_CONFIG_KEYS", frozenset())
    problems: list[str] = []
    if not isinstance(declared, (set, frozenset)) or not all(isinstance(k, str) for k in declared):
        problems.append(f"REQUIRED_CONFIG_KEYS must be a set/frozenset of str, got {declared!r}")
        return problems
    try:
        cls.validate_built_config(built)  # the arena's own fail-fast check
    except Exception as e:  # noqa: BLE001
        problems.append(str(e))
    return problems


def _discovery_problems(plugins_subdir: str, registry: dict) -> list[str]:
    """Every `config_type="..."` declared in a plugin file must appear in the registry. A plugin module
    that fails to import is silently skipped by auto-discovery and just never registers — this turns
    'my plugin isn't showing up' into a named failure."""
    declared = {}
    pattern = re.compile(r"""config_type\s*=\s*["']([^"']+)["']""")
    for py in (_ARENA_ROOT / plugins_subdir).rglob("*.py"):
        if py.name == "base.py":
            continue  # the base defines the mechanism (and shows `config_type="..."` in its docstring)
        for m in pattern.finditer(py.read_text()):
            if m.group(1) == "...":
                continue  # a docstring placeholder, not a real registration
            declared[m.group(1)] = str(py.relative_to(_ARENA_ROOT))
    return [f"config_type {name!r} declared in {path} is not registered (import failure?)"
            for name, path in sorted(declared.items()) if name not in registry]


# --------------------------------------------------------------------------- discovery

def test_every_declared_plugin_is_registered():
    """Across all systems, every config_type written in a plugin file is actually registered."""
    problems = (
        _discovery_problems("attacker/plugins", AttackerPlugin._registry)
        + _discovery_problems("defender/plugins", DefenderPlugin._registry)
        + _discovery_problems("environment/plugins", EnvironmentPlugin._registry)
    )
    assert not problems, "Declared plugins missing from a registry:\n  " + "\n  ".join(problems)


def test_registries_are_non_empty():
    """A totally empty registry means auto-discovery is broken (not that there are no plugins)."""
    assert AttackerPlugin._registry, "no attacker plugins registered"
    assert DefenderPlugin._registry, "no defender plugins registered"
    assert EnvironmentPlugin._registry, "no environment plugins registered"


# --------------------------------------------------------------------------- attacker conformance

_ATTACKER_METHODS = {"build_config": False, "setup": True, "start": True, "stop": True, "collect_logs": True}


@pytest.mark.parametrize("name", _real_plugins(AttackerPlugin._registry), ids=lambda n: n)
def test_attacker_plugin_conforms(name):
    """Every registered attacker meets the shared AttackerPlugin contract."""
    cls = AttackerPlugin._registry[name]
    problems: list[str] = []
    try:
        instance, required_extra = _minimal_instance(cls, name)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"[{name}] not instantiable from minimal config: {type(e).__name__}: {e}")
    if instance.type != name:
        problems.append(f"instance.type={instance.type!r} != registry key {name!r}")
    problems += _ui_schema_problems(cls, name, required_extra)
    problems += _lifecycle_problems(instance, _ATTACKER_METHODS)
    # build_config: offline-exercisable via the example_prepared() baton, well-formed, no leak
    try:
        built = instance.build_config("ci_conformance", _FAKE_ATTACKER_SPEC, cls.example_prepared())
        problems += _config_leak_problems(built, "build_config()")
        problems += _declared_keys_problems(cls, built)
        blacklist = built.get("blacklist_ips", []) if isinstance(built, dict) else []
        for ip in blacklist:
            if str(ip).startswith("192.168"):
                problems.append(f"build_config() blacklists a victim subnet IP: {ip!r}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"build_config(..., example_prepared()) raised {type(e).__name__}: {e}")
    assert not problems, f"[{name}] attacker conformance:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- defender conformance

_DEFENDER_METHODS = {"build_config": False, "setup": True, "start": True, "stop": True,
                     "collect_logs": True, "teardown": True}


@pytest.mark.parametrize("name", _real_plugins(DefenderPlugin._registry), ids=lambda n: n)
def test_defender_plugin_conforms(name):
    """Every registered defender meets the shared DefenderPlugin contract."""
    cls = DefenderPlugin._registry[name]
    problems: list[str] = []
    try:
        instance, required_extra = _minimal_instance(cls, name)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"[{name}] not instantiable from minimal config: {type(e).__name__}: {e}")
    if instance.type != name:
        problems.append(f"instance.type={instance.type!r} != registry key {name!r}")
    problems += _ui_schema_problems(cls, name, required_extra)
    problems += _lifecycle_problems(instance, _DEFENDER_METHODS)
    # box_ingress: the env opens exactly these ports, so the shape must be {kind: [int,...]}
    try:
        ingress = instance.box_ingress()
        if not isinstance(ingress, dict):
            problems.append(f"box_ingress() returned {type(ingress).__name__}, not a dict")
        else:
            for kind, ports in ingress.items():
                if kind not in ("telemetry", "forward"):
                    problems.append(f"box_ingress() has unknown kind {kind!r} (want telemetry/forward)")
                if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
                    problems.append(f"box_ingress()[{kind!r}] must be a list[int], got {ports!r}")
    except Exception as e:  # noqa: BLE001
        problems.append(f"box_ingress() raised {type(e).__name__}: {e}")
    # build_config: well-formed, echoes the experiment name, leaks no SSH credential/routing
    try:
        built = instance.build_config("ci_conformance", None, cls.example_prepared())
        if name not in _BUILD_CONFIG_LEAK_BASELINE:  # the leak guard for baselined plugins lives in test_no_god_key.py
            problems += _config_leak_problems(built, "build_config()")
        problems += _declared_keys_problems(cls, built)
        if isinstance(built, dict) and built.get("experiment_name") != "ci_conformance":
            problems.append(f"build_config()['experiment_name']={built.get('experiment_name')!r} != 'ci_conformance'")
    except Exception as e:  # noqa: BLE001
        problems.append(f"build_config() raised {type(e).__name__}: {e}")
    assert not problems, f"[{name}] defender conformance:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- environment conformance

_ENV_ASYNC_METHODS = {"capacity": True, "provision": True, "configure": True, "collect": True,
                      "teardown": True, "program_ingress": True}
_ENV_SYNC_METHODS = {"resolve_spec": False, "attacker_spec": False, "defender_spec": False,
                     "attacker_setup_access": False, "defender_setup_access": False,
                     "attacker_credential": False, "defender_credential": False,
                     "defender_box": False, "provides_defender_box": False}


@pytest.mark.parametrize("name", _real_plugins(EnvironmentPlugin._registry), ids=lambda n: n)
def test_environment_plugin_conforms(name):
    """Every registered environment meets the shared EnvironmentPlugin contract. (The deep security
    invariants — scoped keys, adversary-safe specs — are parametrized over the registry in
    test_arena_contract.py; this covers construction, ui_schema, and the lifecycle surface.)"""
    problems: list[str] = []
    try:
        instance = build_environment({"environment_plugin": name, "environment_spec": "placeholder"})
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"[{name}] not buildable via build_environment(): {type(e).__name__}: {e}")
    if instance.type != name:
        problems.append(f"instance.type={instance.type!r} != registry key {name!r}")
    # environment plugins may declare required fields (environment_spec); ui_schema must expose them
    required_extra = [f for f, fi in type(instance).model_fields.items()
                      if f != "type" and fi.is_required()]
    problems += _ui_schema_problems(type(instance), name, required_extra)
    problems += _lifecycle_problems(instance, {**_ENV_ASYNC_METHODS, **_ENV_SYNC_METHODS})
    assert not problems, f"[{name}] environment conformance:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- declared runner contract

# The plugin↔runner contract as ONE data table: each plugin's REQUIRED_CONFIG_KEYS — the keys its runner
# reads that build_config() must always emit. This replaces scattered per-plugin `assert "foo" in built`
# presence checks: a new plugin declares its set here (and on the class), and the generic conformance
# tests above enforce build_config() honors it. (Per-plugin VALUE assertions — foothold_ip == the kali IP
# — stay in test_arena_contract.py; this table is about presence/shape only.)
_EXPECTED_ATTACKER_CONFIG_KEYS = {
    "incalmo_strategy": {"name", "strategy", "environment", "c2c_server", "agent_c2c_server", "blacklist_ips"},
    "incalmo_llm":      {"name", "strategy", "environment", "c2c_server", "agent_c2c_server", "blacklist_ips"},
    "cai_llm":          {"model", "objective", "foothold_ip"},
    "terminus_llm":     {"model", "objective", "foothold_ip", "max_turns"},
    "sliver_llm":       {"operator_cfg", "listener_addr", "model", "objective", "max_turns"},
    "openshell":        {"agent", "provider_type", "model", "policy", "objective", "foothold_ip", "agent_cmd_template"},
}
_EXPECTED_DEFENDER_CONFIG_KEYS = {
    "canary":           {"experiment_name", "checks", "fail_closed"},
    "llm_soc":          {"experiment_name", "strategy", "llm_model"},
    "llm_soc_box":      {"experiment_name", "strategy", "llm_model"},  # box-resident engine; same runner contract
    "deception":        {"experiment_name", "strategy"},
    "prompt_injection": {"experiment_name", "strategy"},
    "velociraptor":     {"experiment_name", "response_mode"},
}


@pytest.mark.parametrize("name", _real_plugins(AttackerPlugin._registry), ids=lambda n: n)
def test_attacker_declared_config_keys_match_table(name):
    """Every shipped attacker is in the contract table, and its class declaration matches it. A new
    attacker fails here until its REQUIRED_CONFIG_KEYS is recorded — forcing the contract to be explicit."""
    assert name in _EXPECTED_ATTACKER_CONFIG_KEYS, (
        f"attacker {name!r} has no entry in _EXPECTED_ATTACKER_CONFIG_KEYS — declare its runner contract")
    assert set(AttackerPlugin._registry[name].REQUIRED_CONFIG_KEYS) == _EXPECTED_ATTACKER_CONFIG_KEYS[name]


@pytest.mark.parametrize("name", _real_plugins(DefenderPlugin._registry), ids=lambda n: n)
def test_defender_declared_config_keys_match_table(name):
    """Every shipped defender is in the contract table, and its class declaration matches it."""
    assert name in _EXPECTED_DEFENDER_CONFIG_KEYS, (
        f"defender {name!r} has no entry in _EXPECTED_DEFENDER_CONFIG_KEYS — declare its runner contract")
    assert set(DefenderPlugin._registry[name].REQUIRED_CONFIG_KEYS) == _EXPECTED_DEFENDER_CONFIG_KEYS[name]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
