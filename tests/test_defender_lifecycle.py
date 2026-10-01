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
    DefenderLifecycle, DefenderSignal, DefenderCommand, DefenderLifecycleError, signal_persister,
)
from arena.defender.plugins.base import DefenderPlugin
from arena.experiment.models import Experiment, ExperimentStatus


class _FakeDefender(DefenderPlugin, config_type="_fake_defender_test"):
    """Minimal valid defender (build_config + run), so the base lifecycle can be driven without a
    runner subprocess or cloud. Registered under a '_'-prefixed name the conformance suite skips."""
    type: str = "_fake_defender_test"

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_defender_test", "label": "fake", "fields": [], "cartesian_product": False}

    def build_config(self, experiment_name, environment):
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
    exp = Experiment("def_handshake", ExperimentStatus.QUEUED, "equifax_small", defender=None)
    lc = DefenderLifecycle(on_emit=signal_persister(exp))
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
    exp = Experiment("def_failed", ExperimentStatus.QUEUED, "equifax_small", defender=None)
    lc = DefenderLifecycle(on_emit=signal_persister(exp))

    async def drive():
        await lc.emit(DefenderSignal.SETUP_STARTED)
        await lc.emit(DefenderSignal.FAILED, "arming crashed")
        with pytest.raises(DefenderLifecycleError, match="arming crashed"):
            await lc.wait(DefenderSignal.READY, timeout=1)

    asyncio.run(drive())
    assert exp.defender_status == "Failed"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
