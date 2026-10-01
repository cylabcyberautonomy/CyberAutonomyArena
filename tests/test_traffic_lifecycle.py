"""Traffic lifecycle — the background-traffic analog of test_attacker_lifecycle.py.

Traffic has no signal handshake (the arena calls its methods directly in main.py, only when a traffic
config is present). So the contract to pin is: (1) the base methods are safe no-op COROUTINES, so a run
without traffic — and a plugin that overrides nothing — drives through the whole sequence without error;
(2) a real plugin's overrides are driven in the arena's order: setup (pre-rotation install) -> start
(post-rotation) -> stop -> collect_logs -> teardown. Pure asyncio; no cloud, no victim hosts.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from arena.traffic.plugins.base import TrafficPlugin


class _BareTraffic(TrafficPlugin):
    """Overrides nothing — exercises the base defaults. No config_type, so it never registers."""


class _FakeTraffic(TrafficPlugin, config_type="_fake_traffic_test"):
    """Records the order the arena drives its lifecycle. '_'-prefixed name is skipped by conformance."""
    type: str = "_fake_traffic_test"
    calls: list = []

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_traffic_test", "label": "fake", "fields": [], "cartesian_product": False}

    async def setup(self, experiment, cfg, mgmt_ip):
        self.calls.append("setup")

    async def start(self, experiment, cfg, mgmt_ip):
        self.calls.append("start")

    async def stop(self, experiment, cfg, mgmt_ip):
        self.calls.append("stop")

    async def collect_logs(self, experiment, cfg, dest, mgmt_ip):
        self.calls.append("collect_logs")

    async def teardown(self, experiment, cfg, mgmt_ip):
        self.calls.append("teardown")


def test_base_lifecycle_methods_are_noop_coroutines():
    """A plugin that overrides nothing can be driven through the full sequence; each default awaits to
    None. (This is what lets a run WITHOUT a traffic layer call these unconditionally and be safe.)"""
    trf = _BareTraffic()
    exp = SimpleNamespace(experiment_name="trf_base")

    async def drive():
        assert await trf.setup(exp, None, "1.2.3.4") is None
        assert await trf.start(exp, None, "1.2.3.4") is None
        assert await trf.stop(exp, None, "1.2.3.4") is None
        assert await trf.collect_logs(exp, None, Path("/tmp"), "1.2.3.4") is None
        assert await trf.teardown(exp, None, "1.2.3.4") is None

    asyncio.run(drive())


def test_fake_traffic_is_driven_in_arena_order():
    """The arena's drive order: setup (install, pre-rotation) -> start (post-rotation) -> stop ->
    collect_logs -> teardown. A plugin's overrides fire in exactly that sequence."""
    trf = _FakeTraffic()
    trf.calls = []
    exp = SimpleNamespace(experiment_name="trf_fake")

    async def drive():
        await trf.setup(exp, None, "1.2.3.4")
        await trf.start(exp, None, "1.2.3.4")
        await trf.stop(exp, None, "1.2.3.4")
        await trf.collect_logs(exp, None, Path("/tmp"), "1.2.3.4")
        await trf.teardown(exp, None, "1.2.3.4")

    asyncio.run(drive())
    assert trf.calls == ["setup", "start", "stop", "collect_logs", "teardown"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
