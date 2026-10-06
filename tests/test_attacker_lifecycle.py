"""Unit tests for the attacker lifecycle handshake (AttackerLifecycle + the run_setup/run_stop
templates). Pure asyncio, no cloud, no plugins beyond a fake attacker."""
from __future__ import annotations

import asyncio

import pytest

from arena.attacker.lifecycle import (
    AttackerLifecycle,
    AttackerLifecycleError,
    AttackerSignal,
    AttackerCommand,
)
from arena.attacker.plugins.base import AttackerPlugin, PreparedAttacker


class _FakeAttacker(AttackerPlugin, config_type="_fake_lifecycle_test"):
    """Minimal attacker: setup/stop just record and (optionally) fail, so we can drive the
    templates without a C2 or a cloud."""
    fail_setup: bool = False

    def build_config(self, experiment_name, env_spec, prepared):  # unused here
        return {}

    async def setup(self, experiment, cfg, bastion_ip, access=None):
        await asyncio.sleep(0)  # yield, so a concurrent waiter can observe SETUP_STARTED first
        if self.fail_setup:
            raise RuntimeError("boom in setup")
        return PreparedAttacker()

    async def start(self, prepared, config_path, experiment_name, cfg, access=None):
        await asyncio.sleep(0)
        return object()  # stand-in for the spawned process

    async def stop(self, experiment, cfg, access=None):
        await asyncio.sleep(0)


class _Exp:
    """Stand-in for Experiment: carries the lifecycle handle + a name (run_start needs it)."""
    def __init__(self, lc, name="lc_test"):
        self._attacker_lifecycle = lc
        self.experiment_name = name


def _record(seq):
    def _on_emit(sig, err):
        seq.append(sig)
    return _on_emit


@pytest.mark.asyncio
async def test_full_command_ack_handshake_sequence():
    """The arena SENDS commands (START_SETUP/START_RUN/STOP); the attacker EMITS acks
    (SETUP_STARTED/READY/RUNNING/STOPPING/STOPPED). Assert the full interleaved trace."""
    trace = []  # both directions, in order
    lc = AttackerLifecycle(
        on_emit=lambda sig, err: trace.append(("ack", sig)),
        on_command=lambda cmd: trace.append(("cmd", cmd)),
    )
    exp = _Exp(lc)
    atk = _FakeAttacker(type="_fake_lifecycle_test")  # type: ignore[call-arg]

    # arena -> START_SETUP; attacker acks SETUP_STARTED then READY
    await lc.send(AttackerCommand.START_SETUP)
    task = asyncio.create_task(atk.run_setup(exp, cfg=None, bastion_ip=None))
    await lc.wait(AttackerSignal.SETUP_STARTED, timeout=5)
    prepared = await task
    await lc.wait(AttackerSignal.READY, timeout=5)
    assert isinstance(prepared, PreparedAttacker)

    # arena -> START_RUN; attacker acks RUNNING (from run_start)
    await lc.send(AttackerCommand.START_RUN)
    proc = await atk.run_start(exp, prepared, config_path=None, cfg=None)
    await lc.wait(AttackerSignal.RUNNING, timeout=5)
    assert proc is not None

    # arena -> STOP; attacker acks STOPPING then STOPPED
    await lc.send(AttackerCommand.STOP)
    await atk.run_stop(exp, cfg=None)
    await lc.wait(AttackerSignal.STOPPED, timeout=5)

    assert trace == [
        ("cmd", AttackerCommand.START_SETUP),
        ("ack", AttackerSignal.SETUP_STARTED),
        ("ack", AttackerSignal.READY),
        ("cmd", AttackerCommand.START_RUN),
        ("ack", AttackerSignal.RUNNING),
        ("cmd", AttackerCommand.STOP),
        ("ack", AttackerSignal.STOPPING),
        ("ack", AttackerSignal.STOPPED),
    ]


@pytest.mark.asyncio
async def test_setup_failure_emits_failed_and_unblocks_ready_waiter():
    lc = AttackerLifecycle()
    exp = _Exp(lc)
    atk = _FakeAttacker(type="_fake_lifecycle_test", fail_setup=True)  # type: ignore[call-arg]

    task = asyncio.create_task(atk.run_setup(exp, cfg=None, bastion_ip=None))
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


@pytest.mark.asyncio
async def test_run_setup_threads_scoped_access_as_a_parameter():
    """Unified with the defender: the arena passes the scoped foothold SetupAccess to run_setup as a
    PARAMETER (not via an experiment._attacker_access attribute), and it reaches setup()."""
    from arena.attacker.env_spec import AttackerSetupAccess

    seen = {}
    class _Probe(AttackerPlugin, config_type="_probe_access_param"):
        def build_config(self, *a): return {}
        async def setup(self, experiment, cfg, bastion_ip, access=None):
            seen["access"] = access
            return PreparedAttacker()

    acc = [AttackerSetupAccess(name="kali", host="10.0.0.9", user="root", ssh_key="/scoped/k")]
    await _Probe(type="_probe_access_param").run_setup(_Exp(AttackerLifecycle()), cfg=None, bastion_ip=None, access=acc)
    assert seen["access"] is acc

    # and the base plugin no longer reads the old experiment._attacker_access side-channel
    import inspect
    from arena.attacker.plugins import base
    assert "_attacker_access" not in inspect.getsource(base)


def test_access_persist_load_roundtrips_as_list(tmp_path):
    """run_setup persists the scoped access LIST and the run_* wrappers load it back (symmetric with
    DefenderPlugin; supports an env that grants several footholds). primary_access() yields the first."""
    from types import SimpleNamespace
    from arena.attacker.env_spec import AttackerSetupAccess

    class _P(AttackerPlugin, config_type="_persist_roundtrip"):
        def build_config(self, *a): return {}

    cfg = SimpleNamespace(output_dir=tmp_path)
    acc = [AttackerSetupAccess(name="kali", host="10.0.0.9", user="root", ssh_key="/k"),
           AttackerSetupAccess(name="fh2", host="10.0.0.10", user="root", ssh_key="/k")]
    p = _P(type="_persist_roundtrip")
    p._persist_access("exp", cfg, acc)
    back = p._load_access("exp", cfg)
    assert back is not None and [a.host for a in back] == ["10.0.0.9", "10.0.0.10"]
    assert p.primary_access(back).host == "10.0.0.9"
