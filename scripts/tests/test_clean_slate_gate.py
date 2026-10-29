"""cfg.clean_slate gates the cloud-wide reset; with it off, shutdown touches only this manager's experiments."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import arena.main as m
from arena.experiment.models import ExperimentStatus


def _patch(monkeypatch, clean_slate, names):
    calls = {"clean_slate": 0, "cancelled": []}

    async def fake_clean_slate():
        calls["clean_slate"] += 1

    async def fake_cancel(name):
        calls["cancelled"].append(name)

    monkeypatch.setattr(m, "cfg", SimpleNamespace(clean_slate=clean_slate), raising=False)
    monkeypatch.setattr(m, "registry",
                        SimpleNamespace(load=lambda: [SimpleNamespace(experiment_name=n, status=st) for n, st in names]),
                        raising=False)
    monkeypatch.setattr(m, "_clean_slate", fake_clean_slate)
    monkeypatch.setattr(m, "_cancel_and_remove", fake_cancel)
    monkeypatch.setattr(m.logging, "shutdown", lambda: None)
    return calls


def test_shutdown_without_clean_slate_tears_down_only_own_experiments(monkeypatch):
    calls = _patch(monkeypatch, clean_slate=False, names=[("mine_a", ExperimentStatus.RUNNING),
                                                          ("mine_b", ExperimentStatus.DEPLOYING)])
    asyncio.run(m._shutdown_cleanup())
    assert calls["clean_slate"] == 0
    assert calls["cancelled"] == ["mine_a", "mine_b"]


def test_shutdown_with_clean_slate_runs_the_cloud_wide_reset(monkeypatch):
    calls = _patch(monkeypatch, clean_slate=True, names=[("mine_a", ExperimentStatus.RUNNING)])
    asyncio.run(m._shutdown_cleanup())
    assert calls["clean_slate"] == 1
    assert calls["cancelled"] == []


def test_shutdown_leaves_finished_and_kept_runs_alone(monkeypatch):
    """Terminal runs are already torn down (or deliberately kept with teardown=false), so shutdown skips them."""
    calls = _patch(monkeypatch, clean_slate=False, names=[("done", ExperimentStatus.FINISHED),
                                                          ("failed", ExperimentStatus.ERROR),
                                                          ("blocked", ExperimentStatus.BLOCKED),
                                                          ("live", ExperimentStatus.RUNNING)])
    asyncio.run(m._shutdown_cleanup())
    assert calls["cancelled"] == ["live"]


def test_clean_slate_is_off_by_default():
    from arena.config import ExperimentManagerConfig
    assert ExperimentManagerConfig.model_fields["clean_slate"].default is False


def test_mhbench_prepare_backend_sets_os_cloud_without_touching_the_cloud(monkeypatch):
    """OS_CLOUD must be set at startup even with clean_slate off (it used to be set only inside the wipe)."""
    import os
    from arena.environment.config import EnvBackendConfig
    from arena.environment.plugins.mhbench import clean_slate as cs
    from arena.environment.plugins.mhbench.mhbench import MHBenchEnvironment

    async def boom():
        raise AssertionError("prepare_backend must not wipe the cloud")

    monkeypatch.setattr(cs, "openstack_clean_slate", boom)
    monkeypatch.delenv("OS_CLOUD", raising=False)
    cfg = SimpleNamespace(env_backend=EnvBackendConfig(os_cloud="kolla-admin"))
    asyncio.run(MHBenchEnvironment.prepare_backend(cfg))
    assert os.environ["OS_CLOUD"] == "kolla-admin"
