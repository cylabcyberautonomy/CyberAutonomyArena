"""Traffic lifecycle tests — the traffic analog of test_defender_lifecycle.py, plus persona_traffic's profile logic."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

import arena.main as m
from arena.traffic.lifecycle import (
    TrafficLifecycle, TrafficSignal, TrafficCommand, TrafficLifecycleError, signal_recorder,
)
from arena.traffic.env_spec import TrafficEnvSpec, TrafficHost, TrafficSetupAccess
from arena.traffic.plugins.base import TrafficPlugin, PreparedTraffic
from arena.traffic.plugins.persona_traffic.persona_traffic import PersonaTraffic
from arena.experiment.models import Experiment, ExperimentStatus

ENV = {"environment_plugin": "mhbench", "environment_spec": "equifax_small"}


class _Prepared(PreparedTraffic):
    started_on: list[str] = []


_CALLS: list[str] = []


class _FakeTraffic(TrafficPlugin, config_type="_fake_traffic_test"):
    """Records the order the base drives setup/build_config/start/stop/collect/rearm."""
    type: str = "_fake_traffic_test"
    fail_setup: bool = False

    @classmethod
    def ui_schema(cls):
        return {"config_type": "_fake_traffic_test", "label": "fake", "fields": [], "cartesian_product": False}

    async def setup(self, experiment, cfg, bastion_ip=None, access=None):
        _CALLS.append("setup")
        if self.fail_setup:
            raise RuntimeError("generator would not start")
        return _Prepared(started_on=[a.name for a in access])

    def build_config(self, experiment_name, env_spec=None, prepared=None):
        _CALLS.append("build_config")
        return {"experiment_name": experiment_name, "hosts": prepared.started_on}

    async def stop(self, experiment, cfg, access=None):
        _CALLS.append(f"stop:{len(access or [])}")

    async def collect_logs(self, experiment, cfg, dest, access=None):
        _CALLS.append(f"collect:{len(access or [])}")

    async def rearm(self, experiment, cfg, access):
        _CALLS.append(f"rearm:{access.name}")


def _access():
    return [TrafficSetupAccess(name="webserver0", host="10.0.0.10", ssh_key="/keys/traffic_key",
                               ssh_common_args='-o ProxyCommand="ssh -W %h:%p root@1.2.3.4"'),
            TrafficSetupAccess(name="database0", host="10.0.1.10", ssh_key="/keys/traffic_key",
                               ssh_common_args='-o ProxyCommand="ssh -W %h:%p root@1.2.3.4"')]


def _experiment(name, traffic):
    exp = Experiment(name, ExperimentStatus.QUEUED, ENV, traffic=traffic)
    exp._traffic_lifecycle = TrafficLifecycle(on_emit=signal_recorder(exp))
    exp._traffic_access = _access()
    exp._traffic_env_spec = TrafficEnvSpec(objective="t", hosts=[
        TrafficHost(name="webserver0", ip="10.0.0.10", role="webserver"),
        TrafficHost(name="database0", ip="10.0.1.10", role="database")])
    exp._bastion_ip = "1.2.3.4"
    return exp


def test_full_traffic_handshake_and_config(tmp_path):
    """run_setup -> run_start -> run_stop drives SETUP_STARTED..STOPPED and writes a credential-free config."""
    _CALLS.clear()
    cfg = SimpleNamespace(output_dir=tmp_path)
    t = _FakeTraffic(type="_fake_traffic_test")
    exp = _experiment("tr_handshake", t)
    config_path = tmp_path / "tr_handshake" / "traffic" / "traffic_config.json"

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        proc = await t.run_start(exp, prepared, config_path, cfg)
        assert proc is None  # generators live on the hosts: nothing harness-side by default
        await t.run_stop(exp, cfg)
        await t.run_stop(exp, cfg)  # idempotent

    asyncio.run(drive())
    lc = exp._traffic_lifecycle
    assert lc.history == [TrafficSignal.SETUP_STARTED, TrafficSignal.READY, TrafficSignal.RUNNING,
                          TrafficSignal.STOPPING, TrafficSignal.STOPPED]
    assert _CALLS == ["setup", "build_config", "stop:2"]
    assert exp.traffic_status == "Stopped" and exp.traffic_ready_at and exp.traffic_stopped_at

    written = json.loads(config_path.read_text())
    assert written["hosts"] == ["webserver0", "database0"]
    assert written["traffic_env_spec"]["hosts"][0]["role"] == "webserver"
    text = config_path.read_text()
    assert "traffic_key" not in text and "ProxyCommand" not in text  # scoped access stays out of the record


def test_setup_failure_emits_failed_and_raises(tmp_path):
    """A traffic system that cannot start must fail loudly (FAILED), never yield a quiet run."""
    cfg = SimpleNamespace(output_dir=tmp_path)
    t = _FakeTraffic(type="_fake_traffic_test", fail_setup=True)
    exp = _experiment("tr_fail", t)

    async def drive():
        with pytest.raises(RuntimeError, match="would not start"):
            await t.run_setup(exp, cfg)
        with pytest.raises(TrafficLifecycleError, match="would not start"):
            await exp._traffic_lifecycle.wait(TrafficSignal.READY, timeout=1)

    asyncio.run(drive())
    assert exp.traffic_status == "Failed"


def test_rearm_only_while_running_and_only_known_hosts(tmp_path):
    """run_rearm targets one host by name, only while traffic is RUNNING, and never raises."""
    _CALLS.clear()
    cfg = SimpleNamespace(output_dir=tmp_path)
    t = _FakeTraffic(type="_fake_traffic_test")
    exp = _experiment("tr_rearm", t)

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        await t.run_rearm(exp, cfg, "webserver0")       # READY, not RUNNING: ignored
        await t.run_start(exp, prepared, tmp_path / "c.json", cfg)
        await t.run_rearm(exp, cfg, "webserver0")
        await t.run_rearm(exp, cfg, "defender")         # not a traffic host: ignored
        await t.run_stop(exp, cfg)
        await t.run_rearm(exp, cfg, "database0")        # stopped: ignored

    asyncio.run(drive())
    assert [c for c in _CALLS if c.startswith("rearm")] == ["rearm:webserver0"]


def test_teardown_stops_then_collects_traffic_before_host_logs(tmp_path, monkeypatch):
    """The arena's _teardown stops traffic and pulls its activity logs while the hosts are still up."""
    _CALLS.clear()
    order: list[str] = []
    cfg = SimpleNamespace(output_dir=tmp_path)
    t = _FakeTraffic(type="_fake_traffic_test")
    exp = _experiment("tr_teardown", t)

    async def fake_update(e):
        pass

    async def env_collect(e, c):
        order.append("env_collect")

    async def env_teardown(e, c, lc=None):
        order.append("env_teardown")

    env = SimpleNamespace(collect=env_collect, teardown=env_teardown)
    monkeypatch.setattr(m, "cfg", cfg, raising=False)
    monkeypatch.setattr(m, "registry", SimpleNamespace(update=fake_update), raising=False)
    monkeypatch.setattr(m, "_collect_lock", asyncio.Semaphore(1), raising=False)
    monkeypatch.setattr(m, "_capacity", SimpleNamespace(release=lambda name: None), raising=False)
    monkeypatch.setattr(m, "_env_lc", lambda e, c=None: None)
    monkeypatch.setattr(m, "get_logger", lambda name: logging.getLogger("test-traffic"))
    monkeypatch.setattr(Experiment, "environment", property(lambda self: env))

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        await t.run_start(exp, prepared, tmp_path / "c.json", cfg)
        _CALLS.clear()
        _orig_stop, _orig_collect = t.stop, t.collect_logs

        async def stop(e, c, access=None):
            order.append("traffic_stop")

        async def collect(e, c, dest, access=None):
            order.append("traffic_collect")

        object.__setattr__(t, "stop", stop)
        object.__setattr__(t, "collect_logs", collect)
        assert await m._teardown(exp) is True

    asyncio.run(drive())
    assert order == ["traffic_stop", "traffic_collect", "env_collect", "env_teardown"]
    assert exp.traffic_status == "Stopped" and exp.traffic_finished_at is not None


# --------------------------------------------------------------------------- persona_traffic

def _fake_repo(tmp_path: Path) -> Path:
    """A stand-in persona-traffic checkout: just enough for persona validation."""
    repo = tmp_path / "chtr"
    pkg = repo / "persona_traffic"
    (pkg / "personas").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "persona.py").write_text(
        "class _P:\n"
        "    def __init__(self, d): self.name = d['name']; self.activities = [type('A', (), {'workflow': a['workflow']}) for a in d['activities']]\n"
        "class Persona:\n"
        "    @staticmethod\n"
        "    def from_dict(d): return _P(d)\n")
    (pkg / "workflows.py").write_text(
        "def check_persona_runnable(names, allow_browser=False, allow_gui=False):\n"
        "    return [f'{n} needs a browser' for n in names if n == 'WebBrowser' and not allow_browser]\n")
    (pkg / "personas" / "office_worker.json").write_text(json.dumps(
        {"name": "office_worker", "activities": [{"workflow": "ExecuteCommand"}]}))
    return repo


@pytest.fixture
def chtr(tmp_path, monkeypatch):
    """A persona_traffic setup harness: fake repo, recorded ansible plays."""
    import sys
    repo = _fake_repo(tmp_path)
    for mod in [k for k in sys.modules if k.startswith("persona_traffic")]:
        monkeypatch.delitem(sys.modules, mod)
    monkeypatch.syspath_prepend(str(repo))
    plays: list[tuple] = []

    async def fake_play(self, cfg, experiment_name, action, access, extravars, hostvars=None):
        plays.append((action, sorted(a.name for a in access), hostvars or {}))

    monkeypatch.setattr(PersonaTraffic, "_play", fake_play)
    cfg = SimpleNamespace(output_dir=tmp_path / "out", persona_traffic_dir=repo,
                          plugin_dir=lambda field: repo)
    return cfg, plays


def test_persona_traffic_assigns_personas_by_role(chtr):
    """A role profile maps roles to personas (bundled or inline); a null role gets no traffic."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "default": "office_worker",
        "roles": {"webserver": {"name": "web_admin", "activities": [{"workflow": "ExecuteCommand"}]},
                  "database": None}})
    exp = _experiment("ch_roles", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"webserver0": "web_admin"}
    assert [p[0] for p in plays] == ["install", "start"]
    assert all(p[1] == ["webserver0"] for p in plays)  # the database role was opted out
    persona_file = Path(plays[0][2]["webserver0"]["bgtraffic_persona_src"])
    assert json.loads(persona_file.read_text())["name"] == "web_admin"
    built = json.loads((cfg.output_dir / "ch_roles" / "traffic" / "traffic_config.json").read_text())
    assert built["assignments"] == {"webserver0": "web_admin"}


def test_persona_traffic_shipped_profile_resolves(chtr):
    """The shipped equifax_office profile resolves by name and covers both equifax roles."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile="equifax_office")
    exp = _experiment("ch_shipped", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"webserver0": "web_admin", "database0": "office_worker"}


def test_persona_traffic_rejects_unrunnable_persona(chtr):
    """A persona that needs a browser on headless victims fails setup before anything is installed."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "default": {"name": "browser", "activities": [{"workflow": "WebBrowser"}]}})
    exp = _experiment("ch_browser", t)
    with pytest.raises(RuntimeError, match="needs a browser"):
        asyncio.run(t.run_setup(exp, cfg))
    assert plays == []
    assert exp.traffic_status == "Failed"


def test_persona_traffic_stop_collect_and_rearm_touch_only_covered_hosts(chtr):
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={"roles": {"database": None}})
    exp = _experiment("ch_cover", t)

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        await t.run_start(exp, prepared, Path("unused"), cfg)
        plays.clear()
        await t.run_rearm(exp, cfg, "database0")   # not covered: nothing to rearm
        await t.run_rearm(exp, cfg, "webserver0")
        await t.run_stop(exp, cfg)
        await t.run_collect_logs(exp, cfg, cfg.output_dir / "ch_cover" / "traffic")

    asyncio.run(drive())
    assert [(p[0], p[1]) for p in plays] == [
        ("install", ["webserver0"]), ("start", ["webserver0"]),
        ("stop", ["webserver0"]), ("collect", ["webserver0"])]


def test_env_action_rebuild_triggers_traffic_rearm(monkeypatch):
    """A successful RebuildHost makes the env re-grant traffic access, then traffic rearms that host."""
    from arena import env_action_server as eas
    from arena.environment import EnvActionKind, EnvActionResult
    calls: list[str] = []

    async def handle_env_request(exp, deployed, req, cfg):
        return EnvActionResult(kind=req.kind, ok=True, name=req.target)

    async def restore_traffic_access(exp, deployed, host, cfg):
        calls.append(f"restore:{host}")

    async def run_rearm(exp, cfg, host):
        calls.append(f"rearm:{host}")

    exp = SimpleNamespace(
        experiment_name="e", _env_serving=True, deployed_environment=None,
        environment=SimpleNamespace(handle_env_request=handle_env_request,
                                    restore_traffic_access=restore_traffic_access),
        traffic=SimpleNamespace(run_rearm=run_rearm))
    registry = SimpleNamespace(get=lambda name: exp)

    async def drive():
        out = await eas.handle_env_action(
            {"experiment_name": "e", "action": {"kind": EnvActionKind.REBUILD_HOST.value, "target": "webserver0"}},
            registry=registry, cfg=None)
        assert out["ok"] is True
        await asyncio.gather(*list(eas._rearm_tasks))

    asyncio.run(drive())
    assert calls == ["restore:webserver0", "rearm:webserver0"]


# --------------------------------------------------------------------------- run order

class _LooseExp(SimpleNamespace):
    """An experiment stand-in: attributes the run sets are stored; ones it only reads default to None."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return None

    def config_json(self):
        return "{}"


def test_run_order_is_environment_traffic_defender_attacker(tmp_path, monkeypatch):
    """The defender arms only after traffic is up, and the attacker sets up only after the defender is armed."""
    from arena.attacker.lifecycle import AttackerSignal
    order: list[str] = []

    async def rec(step, value=None):
        order.append(step)
        return value

    async def configure(e, bastion_ip, c2, cfg, lc=None):
        order.append("env_configure")

    env = SimpleNamespace(
        resolve_spec=lambda cfg: "fake_topology",
        capacity=lambda e, cfg: rec("env_capacity", []),
        provision=lambda e, x, cfg, lc=None: rec("env_provision", (None, "10.0.0.1")),
        configure=configure,
        provides_defender_box=lambda d, cfg: True,
        supports_dynamic_topology=lambda: False,
        traffic_spec=lambda d, cfg: None, traffic_setup_access=lambda d, ip, cfg: [],
        defender_spec=lambda d, cfg: None, defender_setup_access=lambda d, ip, cfg: [],
        attacker_spec=lambda d, cfg: None, attacker_setup_access=lambda d, ip, cfg: [],
    )
    traffic = SimpleNamespace(warmup_seconds=0, run_setup=lambda e, cfg: rec("traffic_setup"))
    defender = SimpleNamespace(run_setup=lambda e, cfg: rec("defender_setup"))

    async def attacker_setup(e, cfg, bastion_ip, access):
        order.append("attacker_setup")
        await e._attacker_lifecycle.emit(AttackerSignal.READY)

    attacker = SimpleNamespace(run_setup=attacker_setup)
    exp = _LooseExp(experiment_name="order", environment=env, traffic=traffic, defender=defender,
                    attacker=attacker, priority=0)

    async def run_traffic(t, e, cfg, prepared):
        order.append("traffic_start")

    async def run_defender(d, e, cfg, prepared):
        order.append("defender_start")
        return SimpleNamespace(pid=1)

    async def run_attacker(a, e, cfg, prepared):
        order.append("attacker_start")
        raise RuntimeError("stop the run here")

    async def stop_defender(e, p, cfg):
        order.append("defender_stop")

    async def handle_failure(e, reason=None):
        order.append("failure")

    async def noop(*a, **k):
        return None

    class _Capacity:
        async def reserve(self, specs, name, on_admit=None, priority=0):
            return None

    monkeypatch.setattr(m, "cfg", SimpleNamespace(output_dir=tmp_path, attacker_setup_started_timeout_seconds=1),
                        raising=False)
    monkeypatch.setattr(m, "registry", SimpleNamespace(update=noop), raising=False)
    monkeypatch.setattr(m, "init_logger", lambda name, root: logging.getLogger("test-order"))
    monkeypatch.setattr(m, "_capacity", _Capacity(), raising=False)
    monkeypatch.setattr(m, "_env_lc", lambda e, c=None: None)
    monkeypatch.setattr(m, "run_traffic", run_traffic)
    monkeypatch.setattr(m, "run_defender", run_defender)
    monkeypatch.setattr(m, "run_attacker", run_attacker)
    monkeypatch.setattr(m, "_stop_defender_process", stop_defender)
    monkeypatch.setattr(m, "_handle_failure", handle_failure)

    async def drive():
        monkeypatch.setattr(m, "_deploy_buffer", asyncio.Semaphore(1), raising=False)
        for lock in ("_openstack_lock", "_configure_lock", "_attacker_setup_lock"):
            monkeypatch.setattr(m, lock, m._PriorityLock(1), raising=False)
        await m._run_experiment(exp)

    asyncio.run(drive())
    assert order == ["env_capacity", "env_provision", "env_configure",
                     "traffic_setup", "traffic_start",
                     "defender_setup", "defender_start",
                     "attacker_setup", "attacker_start",
                     "defender_stop", "failure"]
