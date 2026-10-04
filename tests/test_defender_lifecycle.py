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
from typing import Literal

import pytest

from arena.defender.lifecycle import (
    DefenderLifecycle, DefenderSignal, DefenderCommand, DefenderLifecycleError, signal_recorder,
)
from arena.defender.plugins.base import DefenderPlugin, PreparedDefender
from arena.defender.defender import run_defender
from arena.experiment.models import Experiment, ExperimentStatus


class _FakeDefender(DefenderPlugin, config_type="_fake_defender_test"):
    """Minimal valid defender (build_config + run), so the base lifecycle can be driven without a
    runner subprocess or cloud. Registered under a '_'-prefixed name the conformance suite skips."""
    type: str = "_fake_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_defender_test", "label": "fake", "fields": [], "cartesian_product": False}

    def build_config(self, experiment_name, environment, env_spec=None, prepared=None):
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


# --------------------------------------------------------------------------- the readiness gate

def test_wait_until_ready_returns_when_marker_present(tmp_path):
    """The happy path: the runner has written the marker, so the gate returns the arming duration."""
    cfg = _cfg(tmp_path)
    _write_marker("def_ready", cfg)
    process = SimpleNamespace(returncode=None)  # still running
    waited = asyncio.run(_FakeDefender.wait_until_ready("def_ready", cfg, process))
    assert waited >= 0.0


def test_wait_until_ready_raises_if_process_dies_before_arming(tmp_path):
    """A defender that crashes during initialize() must FAIL the experiment — never hand an undefended
    environment to the attacker. No marker + a dead process => RuntimeError naming the exit code."""
    cfg = _cfg(tmp_path)
    process = SimpleNamespace(returncode=1)  # exited, no marker written
    with pytest.raises(RuntimeError, match="code 1"):
        asyncio.run(_FakeDefender.wait_until_ready("def_crash", cfg, process))


def test_wait_until_ready_times_out(tmp_path, monkeypatch):
    """Arming that never completes (no marker, process alive) must raise TimeoutError past the deadline.
    asyncio.sleep is stubbed so the 2s poll doesn't make the test slow."""
    cfg = _cfg(tmp_path, timeout=0.05)
    process = SimpleNamespace(returncode=None)

    real_sleep = asyncio.sleep
    async def _fast_sleep(_delay):
        await real_sleep(0)  # yield without waiting the real poll interval
    monkeypatch.setattr(asyncio, "sleep", _fast_sleep)

    with pytest.raises(TimeoutError, match="did not finish arming"):
        asyncio.run(_FakeDefender.wait_until_ready("def_timeout", cfg, process))


def test_clear_ready_marker_removes_stale(tmp_path):
    """Re-running with overwrite reuses the output dir; a stale marker would make the gate pass instantly.
    clear_ready_marker removes it and is safe to call when none exists (missing_ok)."""
    cfg = _cfg(tmp_path)
    marker = _write_marker("def_stale", cfg)
    assert marker.exists()
    _FakeDefender.clear_ready_marker("def_stale", cfg)
    assert not marker.exists()
    _FakeDefender.clear_ready_marker("def_stale", cfg)  # idempotent, no raise


# --------------------------------------------------------------------------- the full handshake

def test_full_defender_handshake_with_readiness_gate(tmp_path):
    """Drive the arena's defender sequence end to end against the fake, integrating the readiness gate:
    SETUP_STARTED -> wait_until_ready (a concurrent 'runner' writes the marker) -> READY -> RUNNING ->
    STOPPING -> STOPPED. Assert the recorded history + that the persister stamped status/timestamps."""
    cfg = _cfg(tmp_path)
    exp = Experiment("def_handshake", ExperimentStatus.QUEUED,
                     {"environment_plugin": "mhbench", "environment_spec": "equifax_small"}, defender=None)
    lc = DefenderLifecycle(on_emit=signal_recorder(exp))
    process = SimpleNamespace(returncode=None)

    async def drive():
        _FakeDefender.clear_ready_marker("def_handshake", cfg)
        await lc.send(DefenderCommand.START_SETUP)
        await lc.emit(DefenderSignal.SETUP_STARTED)
        # the runner arms and writes the marker the arena is gating on; the gate then returns
        _write_marker("def_handshake", cfg)
        await _FakeDefender.wait_until_ready("def_handshake", cfg, process)
        await lc.emit(DefenderSignal.READY)
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
    """Records the order the arena drives prepare() vs run(), and returns an 'armed in setup' baton."""
    type: str = "_order_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_order_defender_test", "label": "order", "fields": [], "cartesian_product": False}

    async def provision_box(self, experiment_name, cfg, bastion_ip=None,
                            defender_env_spec=None, defender_access=None, needs_agent=False):
        _ORDER_CALLS.append("provision_box")  # Phase A: produce the baton BEFORE build_config
        return PreparedDefender(es_url="http://127.0.0.1:1")

    def build_config(self, experiment_name, environment, env_spec=None, prepared=None):
        _ORDER_CALLS.append("build_config")
        # the Phase-A baton reaches build_config (not patched into the written config afterward)
        assert prepared is not None and prepared.es_url == "http://127.0.0.1:1"
        return {"experiment_name": experiment_name}

    async def prepare(self, config_path, experiment_name, cfg):
        _ORDER_CALLS.append("prepare")
        return PreparedDefender(armed_in_setup=True)

    async def run(self, config_path, experiment_name, cfg):
        _ORDER_CALLS.append("run")
        return SimpleNamespace(returncode=None, pid=4321)


class _PrepareFailsDefender(DefenderPlugin, config_type="_prepare_fails_defender_test"):
    """prepare() (external arming) fails -> run_defender must raise and NEVER reach run()."""
    type: str = "_prepare_fails_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_prepare_fails_defender_test", "label": "pfail", "fields": [], "cartesian_product": False}

    def build_config(self, experiment_name, environment, env_spec=None, prepared=None):
        return {"experiment_name": experiment_name}

    async def prepare(self, config_path, experiment_name, cfg):
        raise RuntimeError("decoy deploy failed")

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


def test_base_prepare_is_noop_baton(tmp_path):
    """A defender with no external arming (the base default) returns an empty baton, armed_in_setup=False:
    its arming, if any, happens in the loop and still uses the readiness marker."""
    prepared = asyncio.run(_FakeDefender().prepare(tmp_path / "c.json", "p", _cfg(tmp_path)))
    assert isinstance(prepared, PreparedDefender)
    assert prepared.armed_in_setup is False


def test_prepared_defender_baton_roundtrips():
    """The baton crosses the prepare->run process boundary as JSON (the prepare-mode runner writes it,
    the arena reads it back in _run_prepare_and_wait)."""
    back = PreparedDefender.model_validate_json(PreparedDefender(armed_in_setup=True).model_dump_json())
    assert back.armed_in_setup is True


def test_run_defender_runs_prepare_before_run(tmp_path):
    """The external-arming contract: run_defender calls prepare() (deploy decoys / plant creds to
    completion) BEFORE run() launches the loop — the defender analog of the attacker's setup()->start()."""
    _ORDER_CALLS.clear()
    proc = asyncio.run(run_defender(_OrderDefender(), _run_exp("ord"), _run_cfg(tmp_path)))
    # the unified lifecycle: Phase A baton (provision_box) -> build_config(baton) -> Phase B arming
    # (prepare) -> run, mirroring the attacker's setup()->build_config(prepared)->start().
    assert _ORDER_CALLS == ["provision_box", "build_config", "prepare", "run"]
    assert proc.pid == 4321


def test_run_defender_aborts_when_prepare_fails(tmp_path):
    """Prepare (external arming) failing must fail the experiment and NEVER launch the run loop — an
    undefended environment is never handed to the attacker (why prepare() blocks and raises)."""
    _ORDER_CALLS.clear()
    with pytest.raises(RuntimeError, match="decoy deploy failed"):
        asyncio.run(run_defender(_PrepareFailsDefender(), _run_exp("ordfail"), _run_cfg(tmp_path)))
    assert "run-should-not-run" not in _ORDER_CALLS


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
