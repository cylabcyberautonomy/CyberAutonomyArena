"""The run window (main._run_window): how an experiment's live phase ends, verified with fakes."""
from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import arena.main as m

_LOG = logging.getLogger("test_run_window")


def _exp(name, duration=None):
    return SimpleNamespace(experiment_name=name, run_duration_seconds=duration, pid=None)


class _FakeProcess:
    """An attacker or defender process whose exit the test controls."""

    def __init__(self):
        self.returncode = None
        self._exited = asyncio.Event()

    def exit(self, code):
        self.returncode = code
        self._exited.set()

    async def wait(self):
        await self._exited.wait()
        return self.returncode


def _cfg(monkeypatch, default=None):
    monkeypatch.setattr(m, "cfg", SimpleNamespace(default_run_duration_seconds=default, attacker_timeout_seconds=None),
                        raising=False)
    m._stop_requests.clear()


def test_window_ends_when_the_attacker_exits(monkeypatch):
    """With no duration cap the window lasts as long as the attacker, and reports its exit code."""
    _cfg(monkeypatch)

    async def go():
        attacker = _FakeProcess()
        asyncio.get_running_loop().call_later(0.01, attacker.exit, 3)
        return await m._run_window(_exp("rw_att"), attacker, _FakeProcess(), _LOG)

    assert asyncio.run(go()) == (3, "attacker_exited")


def test_window_ends_on_duration(monkeypatch):
    """A run_duration_seconds shorter than the attack closes the window first."""
    _cfg(monkeypatch)

    async def go():
        return await m._run_window(_exp("rw_dur", duration=0.05), _FakeProcess(), _FakeProcess(), _LOG)

    assert asyncio.run(go()) == (None, "duration")


def test_window_uses_default_duration_and_runs_without_defender(monkeypatch):
    """No per-experiment duration -> cfg.default_run_duration_seconds; an undefended run has no defender."""
    _cfg(monkeypatch, default=0.05)

    async def go():
        return await m._run_window(_exp("rw_default"), _FakeProcess(), None, _LOG)

    assert asyncio.run(go()) == (None, "duration")


def test_window_ends_on_manual_stop(monkeypatch):
    """Setting the experiment's stop event (what POST .../stop does) ends the window early."""
    _cfg(monkeypatch)

    async def go():
        async def stop_soon():
            await asyncio.sleep(0.01)
            m._stop_requests["rw_stop"].set()
        asyncio.get_running_loop().create_task(stop_soon())
        return await m._run_window(_exp("rw_stop", duration=10), _FakeProcess(), _FakeProcess(), _LOG)

    assert asyncio.run(go()) == (None, "manual")


def test_window_fails_when_defender_dies(monkeypatch):
    """A defender loop exiting nonzero mid-window ends it as defender_exited (the run is no longer defended)."""
    _cfg(monkeypatch)

    async def go():
        defender = _FakeProcess()
        asyncio.get_running_loop().call_later(0.01, defender.exit, 1)
        return await m._run_window(_exp("rw_dead", duration=10), _FakeProcess(), defender, _LOG)

    assert asyncio.run(go()) == (None, "defender_exited")


def test_clean_defender_exit_keeps_window_open(monkeypatch):
    """A defender that exits 0 has finished on its own: the window stays open until the attacker ends."""
    _cfg(monkeypatch)

    async def go():
        attacker, defender = _FakeProcess(), _FakeProcess()
        loop = asyncio.get_running_loop()
        loop.call_later(0.01, defender.exit, 0)
        loop.call_later(0.1, attacker.exit, 0)
        start = loop.time()
        result = await m._run_window(_exp("rw_clean"), attacker, defender, _LOG)
        return result, loop.time() - start

    result, elapsed = asyncio.run(go())
    assert result == (0, "attacker_exited")
    assert elapsed >= 0.09, f"window closed after {elapsed:.3f}s, before the attacker exited"


def test_stop_endpoint_only_stops_a_running_experiment(monkeypatch):
    """POST /experiments/{name}/stop sets the stop event for a Running experiment and refuses otherwise (409)."""
    import pytest
    from fastapi import HTTPException
    from arena.experiment.models import ExperimentStatus

    m._stop_requests.clear()
    store = {"running": SimpleNamespace(status=ExperimentStatus.RUNNING),
             "queued": SimpleNamespace(status=ExperimentStatus.QUEUED)}
    monkeypatch.setattr(m, "registry", SimpleNamespace(get=lambda n: store[n]), raising=False)

    out = asyncio.run(m.stop_experiment("running"))
    assert out["status"] == "stopping" and m._stop_requests["running"].is_set()

    with pytest.raises(HTTPException) as e:
        asyncio.run(m.stop_experiment("queued"))
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:
        asyncio.run(m.stop_experiment("missing"))
    assert e.value.status_code == 404
