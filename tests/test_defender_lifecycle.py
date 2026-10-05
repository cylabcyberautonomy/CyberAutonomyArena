"""Defender lifecycle + readiness gate — the defender analog of test_attacker_lifecycle.py.

The arena drives the defender SETUP_STARTED -> (wait_until_ready) -> READY -> RUNNING -> STOPPING ->
STOPPED and gates the attacker on the readiness marker the runner writes once armed (see
DefenderPlugin.wait_until_ready). Unlike the attacker — whose plugin runs in the arena loop and emits
its own acks — the defender's arming is decided inside its runner subprocess, so the base's marker-gate
is the load-bearing piece. These are pure asyncio + a fake plugin/process; no cloud, no subprocess.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar, Literal, Optional

import pytest

from arena.defender.lifecycle import (
    DefenderLifecycle, DefenderSignal, DefenderCommand, DefenderLifecycleError, signal_recorder,
)
from arena.defender.env_spec import DefenderSetupAccess
from arena.defender.plugins.base import DefenderPlugin, PreparedDefender


class _PreparedBoxBaton(PreparedDefender):
    """A telemetry defender's opaque-baton subclass (base PreparedDefender is now an empty marker); for the
    tests that exercise box-baton fields flowing provision_box -> build_config."""
    es_url: Optional[str] = None
    falco_index: Optional[str] = None
from arena.defender.defender import run_defender
from arena.experiment.models import Experiment, ExperimentStatus


class _FakeDefender(DefenderPlugin, config_type="_fake_defender_test"):
    """Minimal valid defender (build_config + run), so the base lifecycle can be driven without a
    runner subprocess or cloud. Registered under a '_'-prefixed name the conformance suite skips."""
    type: str = "_fake_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_defender_test", "label": "fake", "fields": [], "cartesian_product": False}

    def build_config(self, experiment_name, env_spec=None, prepared=None):
        return {"experiment_name": experiment_name}

    async def run(self, config_path, experiment_name, cfg):
        return SimpleNamespace(returncode=None)


def _cfg(tmp_path: Path, timeout: float = 30.0):
    return SimpleNamespace(output_dir=tmp_path, defender_ready_timeout_seconds=timeout)


def _write_marker(experiment_name: str, cfg) -> Path:
    marker = DefenderPlugin.ready_marker_path(experiment_name, cfg)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("armed")
    return marker


# --------------------------------------------------------------------------- the full handshake

def test_full_defender_handshake(tmp_path):
    """Drive the arena's defender sequence end to end against the fake — NO readiness gate (it's deleted):
    SETUP_STARTED -> READY (run_setup emits it once setup() has ARMED) -> RUNNING (run_start) -> STOPPING ->
    STOPPED. Identical in shape to the attacker; setup() returning IS armed, so there is no marker/
    wait_until_ready. Assert the recorded history + that the persister stamped status/timestamps."""
    cfg = _cfg(tmp_path)
    exp = Experiment("def_handshake", ExperimentStatus.QUEUED,
                     {"environment_plugin": "mhbench", "environment_spec": "equifax_small"}, defender=None)
    lc = DefenderLifecycle(on_emit=signal_recorder(exp))

    async def drive():
        await lc.send(DefenderCommand.START_SETUP)
        await lc.emit(DefenderSignal.SETUP_STARTED)
        await lc.emit(DefenderSignal.READY)        # setup() armed; run_setup emits READY (no marker)
        await lc.send(DefenderCommand.START)
        await lc.emit(DefenderSignal.RUNNING)
        await lc.send(DefenderCommand.STOP)
        await lc.emit(DefenderSignal.STOPPING)
        await lc.emit(DefenderSignal.STOPPED)

    asyncio.run(drive())

    assert lc.history == [DefenderSignal.SETUP_STARTED, DefenderSignal.READY, DefenderSignal.RUNNING,
                          DefenderSignal.STOPPING, DefenderSignal.STOPPED]
    assert lc.commands == [DefenderCommand.START_SETUP, DefenderCommand.START, DefenderCommand.STOP]
    assert exp.defender_status == "Stopped"
    assert exp.defender_ready_at is not None and exp.defender_started_at is not None
    assert exp.defender_stopped_at is not None


def test_failed_short_circuits_a_pending_wait(tmp_path):
    """FAILED before the awaited signal raises DefenderLifecycleError carrying the error — a crashed
    defender must not leave the arena blocked waiting for READY forever."""
    exp = Experiment("def_failed", ExperimentStatus.QUEUED,
                     {"environment_plugin": "mhbench", "environment_spec": "equifax_small"}, defender=None)
    lc = DefenderLifecycle(on_emit=signal_recorder(exp))

    async def drive():
        await lc.emit(DefenderSignal.SETUP_STARTED)
        await lc.emit(DefenderSignal.FAILED, "arming crashed")
        with pytest.raises(DefenderLifecycleError, match="arming crashed"):
            await lc.wait(DefenderSignal.READY, timeout=1)

    asyncio.run(drive())
    assert exp.defender_status == "Failed"


# --------------------------------------------------------- the prepare phase (external arming, setup side)
#
# External arming (deploy decoys / plant honey-creds for a strategy that arms in setup) now runs in
# prepare(), which the arena drives BEFORE run() and blocks on — symmetric with the attacker's setup()
# producing a PreparedAttacker before start(). prepare() returns a PreparedDefender baton; the marker gate
# above still covers strategies that arm inside the run loop (llm_soc, prompt_injection, Reactive*).

_ORDER_CALLS: list[str] = []


class _OrderDefender(DefenderPlugin, config_type="_order_defender_test"):
    """Records the order run_setup drives setup() vs build_config() vs run(), and returns an 'armed in
    setup' baton — the mirror of the attacker (setup -> build_config -> run)."""
    type: str = "_order_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_order_defender_test", "label": "order", "fields": [], "cartesian_product": False}

    async def setup(self, experiment, cfg, bastion_ip=None, access=None):
        _ORDER_CALLS.append("setup")  # ARM (blocks until armed), then produce the baton build_config bakes
        return _PreparedBoxBaton(es_url="http://127.0.0.1:1")

    def build_config(self, experiment_name, env_spec=None, prepared=None):
        _ORDER_CALLS.append("build_config")
        # the setup() baton reaches build_config (then run_setup injects creds/routing afterward)
        assert prepared is not None and prepared.es_url == "http://127.0.0.1:1"
        return {"experiment_name": experiment_name}

    async def run(self, config_path, experiment_name, cfg):
        _ORDER_CALLS.append("run")
        return SimpleNamespace(returncode=None, pid=4321)


class _PrepareFailsDefender(DefenderPlugin, config_type="_prepare_fails_defender_test"):
    """setup() (ARMING — decoy/cred deploy) fails -> run_setup must raise and NEVER reach run()."""
    type: str = "_prepare_fails_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_prepare_fails_defender_test", "label": "pfail", "fields": [], "cartesian_product": False}

    async def setup(self, experiment, cfg, bastion_ip=None, access=None):
        raise RuntimeError("decoy deploy failed")

    def build_config(self, experiment_name, env_spec=None, prepared=None):
        return {"experiment_name": experiment_name}

    async def run(self, config_path, experiment_name, cfg):
        _ORDER_CALLS.append("run-should-not-run")
        return SimpleNamespace(returncode=None, pid=1)


def _run_cfg(tmp_path: Path):
    # the cfg attrs run_defender touches: output_dir, arena_host_ip, defender_ready_timeout_seconds.
    return SimpleNamespace(output_dir=tmp_path, deception_dir=tmp_path, arena_host_ip="10.0.0.1",
                           defender_ready_timeout_seconds=30.0)


def _run_exp(experiment_name: str):
    """A minimal fake Experiment carrying what run_defender reads off it — the arena attaches these before
    the call (deployed_environment + the env-produced _defender_env_spec / _defender_access / _bastion_ip),
    exactly as the attacker's _attacker_env_spec. No _env_dynamic => no env_action_socket is derived."""
    return SimpleNamespace(experiment_name=experiment_name, deployed_environment=None,
                           _defender_env_spec=None, _defender_access=None, _bastion_ip=None)


def test_base_setup_is_noop_baton(tmp_path):
    """The base setup() default ARMS nothing and returns an empty opaque baton — mirror of
    AttackerPlugin.setup's default. A defender with box state subclasses PreparedDefender on its own."""
    prepared = asyncio.run(DefenderPlugin.setup(_FakeDefender(), _run_exp("p"), _cfg(tmp_path)))
    assert isinstance(prepared, PreparedDefender)
    assert prepared.model_dump() == {}


def test_prepared_defender_baton_roundtrips():
    """The box baton round-trips as JSON (a Perry defender's prepare-mode runner writes it and
    _run_prepare_and_wait reads it back; provision_box likewise returns one build_config consumes)."""
    back = _PreparedBoxBaton.model_validate_json(
        _PreparedBoxBaton(es_url="http://127.0.0.1:9200", falco_index="falco").model_dump_json())
    assert back.es_url == "http://127.0.0.1:9200" and back.falco_index == "falco"


def test_run_setup_arms_via_setup_then_writes_config(tmp_path):
    """The mirror order: run_setup() runs setup() (ARM, blocking) BEFORE build_config(), then writes the
    config — the defender analog of the attacker's run_setup (setup -> build_config -> write). run_start then
    only launches the loop. No separate prepare()/provision_box, no readiness marker."""
    _ORDER_CALLS.clear()
    d, exp, cfg = _OrderDefender(), _run_exp("ord"), _run_cfg(tmp_path)
    async def _go():
        prepared = await d.run_setup(exp, cfg)             # SETUP phase: setup() arms -> build_config -> write
        return await run_defender(d, exp, cfg, prepared)   # RUN phase: run() launches the loop
    proc = asyncio.run(_go())
    assert _ORDER_CALLS == ["setup", "build_config", "run"]
    assert proc.pid == 4321


def test_run_setup_aborts_when_setup_arming_fails(tmp_path):
    """setup() (ARMING — decoy/cred deploy) failing must fail the experiment and NEVER launch the run loop:
    an undefended environment is never handed to the attacker (why setup() blocks and raises)."""
    _ORDER_CALLS.clear()
    d, exp, cfg = _PrepareFailsDefender(), _run_exp("ordfail"), _run_cfg(tmp_path)
    async def _go():
        prepared = await d.run_setup(exp, cfg)
        return await run_defender(d, exp, cfg, prepared)
    with pytest.raises(RuntimeError, match="decoy deploy failed"):
        asyncio.run(_go())
    assert "run-should-not-run" not in _ORDER_CALLS


# --------------------------------------------------------------------------- the stop path (run_stop)

def test_run_stop_emits_stopping_then_stopped(tmp_path):
    """DefenderPlugin.run_stop drives STOPPING -> STOPPED around stop(), mirroring AttackerPlugin.run_stop.
    stop() SIGTERMs experiment.defender_pid; None here so it is a no-op — no real process needed."""
    trace = []
    lc = DefenderLifecycle(on_emit=lambda sig, err: trace.append(sig))
    exp = SimpleNamespace(experiment_name="stp", _defender_lifecycle=lc, defender_pid=None)
    asyncio.run(_FakeDefender().run_stop(exp, _run_cfg(tmp_path)))
    assert trace == [DefenderSignal.STOPPING, DefenderSignal.STOPPED]


def test_run_stop_is_guarded_after_failed(tmp_path):
    """If the defender already reached terminal FAILED (arming crashed), run_stop must NOT emit
    STOPPING/STOPPED over it — the arena calls run_stop from the failure path too (main.py)."""
    trace = []
    lc = DefenderLifecycle(on_emit=lambda sig, err: trace.append(sig))
    exp = SimpleNamespace(experiment_name="stpf", _defender_lifecycle=lc, defender_pid=None)
    async def _go():
        await lc.emit(DefenderSignal.FAILED, "boom")
        await _FakeDefender().run_stop(exp, _run_cfg(tmp_path))
    asyncio.run(_go())
    assert trace == [DefenderSignal.FAILED]  # no STOPPING/STOPPED added over the terminal FAILED


# --------------------------------------------------------------------------- box execution (plugin-owned)
# The box-launch machinery is NOT on the base: base start() just calls run(); the box-resident plugins
# (canary = stdlib subset, llm_soc_box = full uv/engine + ssh -R tunnel) each carry their OWN copy and
# override start() to launch on the box. These tests pin that split + the PURE command builders.

def test_base_start_defaults_to_run(tmp_path):
    """The base start() just launches the local harness loop via run() — no box routing, no runs_on_box."""
    proc = asyncio.run(_FakeDefender().start(PreparedDefender(), tmp_path / "c.json", "p", _run_cfg(tmp_path)))
    assert proc.returncode is None  # _FakeDefender.run()'s SimpleNamespace, i.e. run() was used


def test_uses_env_actions_defaults_false():
    """The one keying classvar on the base: a plain defender issues no env actions, so the arena arms no
    env-action channel for it. (runs_on_box is gone entirely — see test_base_has_no_box_launch_machinery.)"""
    assert _FakeDefender.uses_env_actions is False


def test_base_has_no_box_launch_machinery():
    """Relocation guard (symmetric with the attacker's 'no _attacker_access on the base'): the box-launch
    unit + the old runs_on_box/box_python keying live ON THE PLUGINS now, never on DefenderPlugin."""
    for gone in ("runs_on_box", "box_python", "box_ships_engine", "box_engine_src", "_BOX_DIR",
                 "_launch_on_box", "_box_run_command", "_box_paths", "_box_runner_src", "_tty_ssh",
                 "_box_push", "_ship_engine_to_box", "_rewrite_access_keys", "_thread_box_credentials",
                 "_wait_box_ready", "box_pip_spec"):
        assert not hasattr(DefenderPlugin, gone), f"DefenderPlugin should not carry box machinery: {gone}"
    import inspect as _inspect
    from arena.defender.plugins import base as _base
    assert "runs_on_box" not in _inspect.getsource(_base)


def test_access_persist_load_roundtrip(tmp_path):
    """run_setup persists the scoped access LIST and the run_* wrappers load it back — unconditionally now
    (symmetric with the attacker; a box-resident start() threads it, a harness-run start() ignores it)."""
    cfg = _run_cfg(tmp_path)
    acc = [DefenderSetupAccess(user="u", host="10.0.0.9", ssh_key="/k"),
           DefenderSetupAccess(user="u", host="10.0.0.10")]
    d = _FakeDefender()
    d._persist_access("boxexp", cfg, acc)
    back = d._load_access("boxexp", cfg)
    assert back is not None and [a.host for a in back] == ["10.0.0.9", "10.0.0.10"]


def test_canary_overrides_start_and_routes_to_launch_on_box(tmp_path, monkeypatch):
    """canary runs ON THE BOX: it overrides start() to delegate to its OWN _launch_on_box (never the base's
    local run()). Monkeypatched so no real SSH happens."""
    from arena.defender.plugins.canary.canary import CanaryDefenderPlugin
    assert CanaryDefenderPlugin.start is not DefenderPlugin.start

    async def _fake_launch(self, prepared, config_path, experiment_name, cfg, access):
        return SimpleNamespace(pid=777, access=access)
    monkeypatch.setattr(CanaryDefenderPlugin, "_launch_on_box", _fake_launch)
    proc = asyncio.run(CanaryDefenderPlugin(type="canary").start(
        PreparedDefender(), tmp_path / "c.json", "p", _run_cfg(tmp_path), access=["acc"]))
    assert proc.pid == 777 and proc.access == ["acc"]


def test_canary_box_run_command_stdlib():
    """canary (box_python unset => stdlib) runs the shipped runner under the box's own python3, under
    _BOX_DIR, with no uv bootstrap. _box_run_command is PURE (no I/O)."""
    from arena.defender.plugins.canary.canary import CanaryDefenderPlugin
    cmd = CanaryDefenderPlugin(type="canary")._box_run_command()
    assert cmd.startswith("set -e; mkdir -p /opt/arena-defender /opt/arena-defender/logs")
    assert "exec python3 /opt/arena-defender/runner.py /opt/arena-defender/defender_config.json" in cmd
    assert "uv venv" not in cmd and "astral.sh" not in cmd


def test_llm_soc_box_run_command_ships_engine():
    """llm_soc_box (box_python=3.12 + box_ships_engine) installs uv + a standalone CPython venv (the Terminus
    pattern) + the engine's requirements.txt, with the egress preflight, and runs the runner with
    cwd/PYTHONPATH = the shipped engine. _box_run_command is PURE."""
    from arena.defender.plugins.llm_soc.llm_soc_box import LLMSOCBoxDefenderPlugin
    cmd = LLMSOCBoxDefenderPlugin(type="llm_soc_box", strategy="FalcoLLM")._box_run_command()
    assert "command -v uv" in cmd and "astral.sh/uv/install.sh" in cmd
    assert "uv venv /opt/arena-defender/venv --python 3.12" in cmd
    assert "uv pip install --python /opt/arena-defender/venv/bin/python -r /opt/arena-defender/engine/requirements.txt" in cmd
    assert "BOX EGRESS FAIL" in cmd  # the pypi reachability preflight guard
    assert "cd /opt/arena-defender/engine; exec env PYTHONPATH=/opt/arena-defender/engine" in cmd


def test_llm_soc_box_keying_flags():
    """llm_soc_box is a box-resident env-action defender: uses_env_actions True (it issues RestoreServer
    env-actions, reaching the env over its own ssh -R tunnel). executes_from_box is GONE — the base no longer
    keys on where a defender runs; the plugin picks its own env door in setup()."""
    from arena.defender.plugins.llm_soc.llm_soc_box import LLMSOCBoxDefenderPlugin
    assert LLMSOCBoxDefenderPlugin.uses_env_actions is True
    assert not hasattr(LLMSOCBoxDefenderPlugin, "executes_from_box")


def test_uses_env_actions_matrix():
    """uses_env_actions on the real plugins — the ONE env-action keying flag the base reads now
    (executes_from_box is gone). deception/prompt_injection/llm_soc/llm_soc_box issue env actions (serving
    window + channel); canary does not. No plugin declares executes_from_box any more."""
    from arena.defender.plugins.deception.deception import DeceptionDefenderPlugin
    from arena.defender.plugins.prompt_injection.prompt_injection import PromptInjectionDefenderPlugin
    from arena.defender.plugins.llm_soc.llm_soc import LLMSOCDefenderPlugin
    from arena.defender.plugins.llm_soc.llm_soc_box import LLMSOCBoxDefenderPlugin
    from arena.defender.plugins.canary.canary import CanaryDefenderPlugin
    assert DeceptionDefenderPlugin.uses_env_actions is True
    assert PromptInjectionDefenderPlugin.uses_env_actions is True
    assert LLMSOCDefenderPlugin.uses_env_actions is True
    assert LLMSOCBoxDefenderPlugin.uses_env_actions is True
    assert CanaryDefenderPlugin.uses_env_actions is False
    for cls in (DeceptionDefenderPlugin, PromptInjectionDefenderPlugin, LLMSOCDefenderPlugin,
                LLMSOCBoxDefenderPlugin, CanaryDefenderPlugin):
        assert not hasattr(cls, "executes_from_box")


def test_tty_ssh_inserts_tt():
    """_launch_on_box runs over `ssh -tt` so the local ssh pid proxies the remote runner (stop() SIGTERM
    propagates). _tty_ssh (on each box plugin now) inserts -tt right after `ssh`, before the opts/host."""
    from arena.defender.plugins.canary.canary import CanaryDefenderPlugin
    assert CanaryDefenderPlugin._tty_ssh(["ssh", "-i", "/k", "u@h"]) == ["ssh", "-tt", "-i", "/k", "u@h"]


def test_rewrite_access_keys_to_box_paths():
    """Credential threading (PURE part): a box-resident runner reaches victims with box-local keys, so both
    ssh_key AND the `-i <key>` inside the bastion ProxyCommand (ssh_common_args) are rewritten harness->box."""
    from arena.defender.plugins.canary.canary import CanaryDefenderPlugin
    harness_key = "/home/u/MHBench/keys/defender_key"
    box_key = "/opt/arena-defender/keys/defender_key"
    entries = [
        {"name": "v0", "host": "10.0.0.5", "ssh_key": harness_key,
         "ssh_common_args": f'-o IdentitiesOnly=yes -o ProxyCommand="ssh -W %h:%p -i {harness_key} root@bastion"'},
        {"name": "box", "host": "10.0.0.9", "ssh_key": harness_key, "ssh_common_args": ""},
    ]
    out = CanaryDefenderPlugin._rewrite_access_keys(entries, {harness_key: box_key})
    assert all(e["ssh_key"] == box_key for e in out)
    assert harness_key not in out[0]["ssh_common_args"] and box_key in out[0]["ssh_common_args"]
    assert out[1]["ssh_common_args"] == ""  # empty routing untouched
    # original entries not mutated
    assert entries[0]["ssh_key"] == harness_key


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
