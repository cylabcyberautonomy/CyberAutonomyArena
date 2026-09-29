"""Unit tests for the attacker lifecycle handshake (AttackerLifecycle + the run_setup/run_stop
templates). Pure asyncio, no cloud, no plugins beyond a fake attacker."""
from __future__ import annotations

import asyncio

import pytest

from experiment_manager.attacker.lifecycle import (
    AttackerLifecycle,
    AttackerLifecycleError,
    AttackerSignal,
)
from experiment_manager.attacker.plugins.base import AttackerPlugin, PreparedAttacker


class _FakeAttacker(AttackerPlugin, config_type="_fake_lifecycle_test"):
    """Minimal attacker: setup/stop just record and (optionally) fail, so we can drive the
    templates without a C2 or a cloud."""
    fail_setup: bool = False

    def build_config(self, experiment_name, env_spec, c2c_url):  # unused here
        return {}

    async def setup(self, experiment, cfg, mgmt_ip):
        await asyncio.sleep(0)  # yield, so a concurrent waiter can observe SETUP_STARTED first
        if self.fail_setup:
            raise RuntimeError("boom in setup")
        return PreparedAttacker()

    async def stop(self, experiment, cfg):
        await asyncio.sleep(0)


class _Exp:
    """Stand-in for Experiment: only needs to carry the lifecycle handle."""
    def __init__(self, lc):
        self._attacker_lifecycle = lc


def _record(seq):
    def _on_emit(sig, err):
        seq.append(sig)
    return _on_emit


@pytest.mark.asyncio
async def test_setup_run_stop_handshake_sequence():
    seq = []
    lc = AttackerLifecycle(on_emit=_record(seq))
    exp = _Exp(lc)
    atk = _FakeAttacker(type="_fake_lifecycle_test")  # type: ignore[call-arg]

    # send start_setup: run the template as a task, wait the ack, then wait ready
    task = asyncio.create_task(atk.run_setup(exp, cfg=None, mgmt_ip=None))
    await lc.wait(AttackerSignal.SETUP_STARTED, timeout=5)
    prepared = await task
    await lc.wait(AttackerSignal.READY, timeout=5)
    assert isinstance(prepared, PreparedAttacker)

    # running is emitted by the arena once the process is up
    await lc.emit(AttackerSignal.RUNNING)

    # send stop: STOPPING then STOPPED
    await atk.run_stop(exp, cfg=None)
    await lc.wait(AttackerSignal.STOPPED, timeout=5)

    assert seq == [
        AttackerSignal.SETUP_STARTED,
        AttackerSignal.READY,
        AttackerSignal.RUNNING,
        AttackerSignal.STOPPING,
        AttackerSignal.STOPPED,
    ]


@pytest.mark.asyncio
async def test_setup_failure_emits_failed_and_unblocks_ready_waiter():
    lc = AttackerLifecycle()
    exp = _Exp(lc)
    atk = _FakeAttacker(type="_fake_lifecycle_test", fail_setup=True)  # type: ignore[call-arg]

    task = asyncio.create_task(atk.run_setup(exp, cfg=None, mgmt_ip=None))
    # a waiter blocked on READY must be released with an error when setup fails, not hang
    with pytest.raises(AttackerLifecycleError):
        await lc.wait(AttackerSignal.READY, timeout=5)
    with pytest.raises(RuntimeError, match="boom in setup"):
        await task
    assert AttackerSignal.FAILED in lc.history


@pytest.mark.asyncio
async def test_wait_times_out_when_signal_never_arrives():
    lc = AttackerLifecycle()
    with pytest.raises(TimeoutError):
        await lc.wait(AttackerSignal.READY, timeout=0.2)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
