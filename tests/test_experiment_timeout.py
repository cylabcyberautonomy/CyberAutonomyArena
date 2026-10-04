"""The overall experiment-timeout backstop (cfg.experiment_timeout_seconds).

Verifies the two halves of the mechanism with fakes — no cloud:
  - _run_experiment_gated cancels a hung run on the deadline and dispatches the handler (and does NOT
    when the run finishes in time, or when the cap is disabled);
  - _handle_experiment_timeout performs the cleanup contract: force-kill the orphaned attacker by pid,
    tear down (reclaim VMs + capacity), mark the terminal ExperimentTimedOut, and survive a teardown error.
"""
from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import arena.main as m
from arena.main import _run_experiment_gated, _handle_experiment_timeout
from arena.experiment.models import ExperimentStatus


def _exp(name="to_test", pid=None, priority=0):
    return SimpleNamespace(experiment_name=name, pid=pid, priority=priority,
                           status=ExperimentStatus.RUNNING, error=None)


# --------------------------------------------------------------- gated wrapper: cancel + dispatch

def test_timeout_cancels_hung_run_and_dispatches_handler(monkeypatch):
    """Past the deadline, the hung _run_experiment is cancelled and _handle_experiment_timeout fires."""
    monkeypatch.setattr(m, "cfg", SimpleNamespace(experiment_timeout_seconds=0.05), raising=False)
    cancelled = {"v": False}

    async def fake_run(exp):
        try:
            await asyncio.sleep(100)
        except asyncio.CancelledError:
            cancelled["v"] = True   # the deadline must actually cancel the run, not leave it orphaned
            raise

    handled = {"exp": None}

    async def fake_handler(exp):
        handled["exp"] = exp

    monkeypatch.setattr(m, "_run_experiment", fake_run)
    monkeypatch.setattr(m, "_handle_experiment_timeout", fake_handler)

    exp = _exp()
    asyncio.run(_run_experiment_gated(exp))
    assert cancelled["v"] is True, "a hung _run_experiment must be cancelled at the deadline"
    assert handled["exp"] is exp, "the timeout handler must be dispatched with the experiment"


def test_no_timeout_when_run_finishes_in_time(monkeypatch):
    """A run that completes within the cap returns normally; the handler never fires."""
    monkeypatch.setattr(m, "cfg", SimpleNamespace(experiment_timeout_seconds=5), raising=False)
    ran, called = {"v": False}, {"v": False}

    async def fake_run(exp):
        ran["v"] = True

    async def fake_handler(exp):
        called["v"] = True

    monkeypatch.setattr(m, "_run_experiment", fake_run)
    monkeypatch.setattr(m, "_handle_experiment_timeout", fake_handler)

    asyncio.run(_run_experiment_gated(_exp()))
    assert ran["v"] is True
    assert called["v"] is False, "handler must not fire when the run finishes within the cap"


def test_disabled_cap_runs_without_the_wrapper(monkeypatch):
    """cap=None (the default) runs _run_experiment directly, no deadline, no handler."""
    monkeypatch.setattr(m, "cfg", SimpleNamespace(experiment_timeout_seconds=None), raising=False)
    ran, called = {"v": False}, {"v": False}

    async def fake_run(exp):
        ran["v"] = True

    async def fake_handler(exp):
        called["v"] = True

    monkeypatch.setattr(m, "_run_experiment", fake_run)
    monkeypatch.setattr(m, "_handle_experiment_timeout", fake_handler)

    asyncio.run(_run_experiment_gated(_exp()))
    assert ran["v"] is True and called["v"] is False


# --------------------------------------------------------------- handler: the cleanup contract

def _patch_handler_deps(monkeypatch):
    """Stub the handler's module deps; return the recorders."""
    rec = {"torn": None, "killed": None, "updated": False, "wrote": False}

    async def fake_teardown(exp):
        rec["torn"] = exp
        return True

    async def fake_update(exp):
        rec["updated"] = True

    monkeypatch.setattr(m, "cfg", SimpleNamespace(experiment_timeout_seconds=1), raising=False)
    monkeypatch.setattr(m, "get_logger", lambda name: logging.getLogger("test-exp-timeout"))
    monkeypatch.setattr(m, "_teardown", fake_teardown)
    monkeypatch.setattr(m, "_force_kill_attacker", lambda pid, log: rec.__setitem__("killed", pid))
    monkeypatch.setattr(m, "registry", SimpleNamespace(update=fake_update), raising=False)
    monkeypatch.setattr(m, "_write_result", lambda exp: rec.__setitem__("wrote", True))
    return rec


def test_handler_tears_down_kills_attacker_and_marks_status(monkeypatch):
    rec = _patch_handler_deps(monkeypatch)
    exp = _exp(pid=4321)
    asyncio.run(_handle_experiment_timeout(exp))

    assert rec["torn"] is exp, "must tear down to reclaim VMs + capacity"
    assert rec["killed"] == 4321, "must force-kill the orphaned attacker by pid"
    assert exp.status == ExperimentStatus.EXPERIMENT_TIMEOUT
    assert exp.error and "overall wall-clock cap" in exp.error
    assert rec["updated"] and rec["wrote"], "must persist the terminal status + write the result"


def test_handler_skips_kill_when_no_attacker_pid(monkeypatch):
    rec = _patch_handler_deps(monkeypatch)
    exp = _exp(pid=None)  # attacker never started
    asyncio.run(_handle_experiment_timeout(exp))
    assert rec["killed"] is None and rec["torn"] is exp
    assert exp.status == ExperimentStatus.EXPERIMENT_TIMEOUT


def test_handler_marks_status_even_if_teardown_raises(monkeypatch):
    """A teardown failure during cleanup must not prevent the terminal status/result from being set."""
    rec = _patch_handler_deps(monkeypatch)

    async def boom_teardown(exp):
        raise RuntimeError("teardown blew up")

    monkeypatch.setattr(m, "_teardown", boom_teardown)
    exp = _exp(pid=1)
    asyncio.run(_handle_experiment_timeout(exp))
    assert exp.status == ExperimentStatus.EXPERIMENT_TIMEOUT
    assert rec["updated"] and rec["wrote"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
