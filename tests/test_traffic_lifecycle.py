"""Traffic lifecycle + readiness gate — the background-traffic analog of test_defender_lifecycle.py.

Traffic now has FULL parity with the defender: the arena drives SETUP_STARTED -> (install, pre-rotation)
-> run the runner subprocess -> (wait_until_ready) -> READY -> RUNNING -> STOPPING -> STOPPED, gating the
attacker on the readiness marker the runner writes once the generators are up (see
TrafficPlugin.wait_until_ready). The base setup()/teardown() stay safe no-op coroutines (so a run WITHOUT
traffic, and a plugin that overrides nothing, is still valid); build_config()/run() are the contract a
real plugin implements. Pure asyncio + a fake plugin/process; no cloud, no subprocess.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from arena.traffic.lifecycle import (
    TrafficLifecycle, TrafficSignal, TrafficCommand, TrafficLifecycleError, signal_persister,
)
from arena.traffic.plugins.base import TrafficPlugin
from arena.traffic.traffic import run_traffic
from arena.traffic.env_spec import TrafficEnvSpec, TrafficHost
from arena.attacker.env_spec import SetupAccess


class _FakeTraffic(TrafficPlugin, config_type="_fake_traffic_test"):
    """Minimal valid traffic plugin (build_config + run), so the base lifecycle can be driven without a
    runner subprocess or cloud. Registered under a '_'-prefixed name the conformance suite skips."""
    type: str = "_fake_traffic_test"
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name"})

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_traffic_test", "label": "fake", "fields": [], "cartesian_product": False}

    def build_config(self, experiment_name, environment):
        return {"experiment_name": experiment_name}

    async def run(self, config_path, experiment_name, cfg):
        return SimpleNamespace(returncode=None, pid=4321)


def _cfg(tmp_path: Path, timeout: float = 30.0):
    return SimpleNamespace(output_dir=tmp_path, defender_ready_timeout_seconds=timeout,
                           arena_host_ip="10.0.0.1")


def _write_marker(experiment_name: str, cfg) -> Path:
    marker = TrafficPlugin.ready_marker_path(experiment_name, cfg)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("running")
    return marker


# --------------------------------------------------------------------------- base defaults stay no-op

def test_base_setup_and_teardown_are_noop_coroutines():
    """A plugin that implements only the abstract methods inherits safe no-op setup()/teardown() — a run
    WITHOUT traffic, and a minimal plugin, drive through them without error."""
    trf = _FakeTraffic()
    exp = SimpleNamespace(experiment_name="trf_base")

    async def drive():
        assert await trf.setup(exp, None, traffic_env_spec=None, traffic_access=None, bastion_ip="1.2.3.4") is None
        assert await trf.teardown(exp, None) is None

    asyncio.run(drive())


# --------------------------------------------------------------------------- the readiness gate

def test_wait_until_ready_returns_when_marker_present(tmp_path):
    """The happy path: the runner wrote the marker, so the gate returns the time spent."""
    cfg = _cfg(tmp_path)
    _write_marker("trf_ready", cfg)
    process = SimpleNamespace(returncode=None)  # still running
    waited = asyncio.run(_FakeTraffic.wait_until_ready("trf_ready", cfg, process))
    assert waited >= 0


def test_wait_until_ready_raises_if_runner_died(tmp_path):
    """A runner that exited before writing the marker must fail the run (not hand the attacker an
    un-noised environment), exactly like the defender."""
    cfg = _cfg(tmp_path)
    TrafficPlugin.clear_ready_marker("trf_dead", cfg)
    process = SimpleNamespace(returncode=1)  # exited, no marker
    with pytest.raises(RuntimeError):
        asyncio.run(_FakeTraffic.wait_until_ready("trf_dead", cfg, process))


def test_clear_ready_marker_removes_a_stale_marker(tmp_path):
    cfg = _cfg(tmp_path)
    marker = _write_marker("trf_stale", cfg)
    assert marker.exists()
    TrafficPlugin.clear_ready_marker("trf_stale", cfg)
    assert not marker.exists()


# --------------------------------------------------------------------------- the signal handshake

def test_signal_persister_records_each_phase_on_the_experiment():
    """signal_persister maps each traffic signal to its status + timestamp field, mirroring the defender."""
    exp = SimpleNamespace(
        traffic_status=None, traffic_setup_started_at=None, traffic_ready_at=None,
        traffic_started_at=None, traffic_stopping_at=None, traffic_stopped_at=None,
    )
    lc = TrafficLifecycle(on_emit=signal_persister(exp))

    async def drive():
        await lc.send(TrafficCommand.START_SETUP)
        await lc.emit(TrafficSignal.SETUP_STARTED)
        await lc.emit(TrafficSignal.READY)
        await lc.send(TrafficCommand.START)
        await lc.emit(TrafficSignal.RUNNING)
        await lc.emit(TrafficSignal.STOPPING)
        await lc.emit(TrafficSignal.STOPPED)

    asyncio.run(drive())
    assert exp.traffic_status == TrafficSignal.STOPPED.value
    for f in ("traffic_setup_started_at", "traffic_ready_at", "traffic_started_at",
              "traffic_stopping_at", "traffic_stopped_at"):
        assert getattr(exp, f) is not None, f


def test_wait_short_circuits_on_failed():
    """FAILED unblocks a pending wait with the underlying error, like the defender's."""
    lc = TrafficLifecycle()

    async def drive():
        await lc.emit(TrafficSignal.FAILED, "generator install blew up")
        with pytest.raises(TrafficLifecycleError):
            await lc.wait(TrafficSignal.READY)

    asyncio.run(drive())


# --------------------------------------------------------------------------- run_traffic injects spec+access

def test_run_traffic_injects_env_spec_and_access(tmp_path):
    """run_traffic (symmetric with run_defender) injects the env-produced TrafficEnvSpec + per-victim
    SetupAccess into the runner config file before spawning the runner."""
    cfg = _cfg(tmp_path)
    trf = _FakeTraffic()
    spec = TrafficEnvSpec(objective="noise", hosts=[TrafficHost(name="web0", ip="192.168.1.10")])
    access = [SetupAccess(name="web0", host="192.168.1.10", ssh_key="/keys/traffic_key",
                          ssh_common_args='-o ProxyCommand="ssh -W %h:%p root@1.2.3.4"')]

    proc = asyncio.run(run_traffic(trf, None, "trf_inject", cfg, "1.2.3.4",
                                   traffic_env_spec=spec, traffic_access=access))
    assert proc.returncode is None

    config_path = tmp_path / "trf_inject" / "traffic" / "traffic_config.json"
    built = json.loads(config_path.read_text())
    assert built["experiment_name"] == "trf_inject"
    assert built["traffic_env_spec"]["hosts"][0]["name"] == "web0"
    assert built["traffic_setup_access"][0]["ssh_key"] == "/keys/traffic_key"
    assert "ProxyCommand" in built["traffic_setup_access"][0]["ssh_common_args"]
    assert built["bastion_ip"] == "1.2.3.4"


if __name__ == "__main__":
    import pytest as _pytest
    raise SystemExit(_pytest.main([__file__, "-v"]))
