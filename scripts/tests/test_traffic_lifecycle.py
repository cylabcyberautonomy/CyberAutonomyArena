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
    (repo / "vendor").mkdir()
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


def _gens(hostvars: dict, host: str) -> dict[str, dict]:
    """The per-generator vars the play loops over, keyed by generator name."""
    return {g["name"]: g for g in hostvars[host]["bgtraffic_generators"]}


def _spec_file(hostvars: dict, host: str, name: str, rel: str) -> dict:
    """The rendered control-node file shipped to <dir>/<rel> for generator `name` on `host`."""
    want = f"/opt/bgtraffic/{name}/{rel}"
    src = next(f["src"] for f in hostvars[host]["bgtraffic_files"] if f["dest"] == want)
    return json.loads(Path(src).read_text())


_ANALYST = {"generator": "script", "name": "analyst", "user": "ubuntu", "entry": "ssh", "events_per_hour": 3,
            "seed": 1, "groups": [{"label": "inspect", "weight": 2, "commands": ["ls -la ~", "wc -c ~/*.json"]}]}
_EXTRACT = {"generator": "script", "name": "extract", "user": "tomcat", "events_per_hour": 1,
            "scale_by_role": "database", "vars": {"TARGET": "{{hosts:database}}", "IP": "{{ips:database}}"},
            "groups": [{"commands": ["ssh ${TARGET}_ubuntu 'ls ~'"]}]}


def test_persona_traffic_assigns_personas_by_role(chtr):
    """A role profile maps roles to personas (bundled or inline); a null role gets no traffic."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "default": "office_worker",
        "roles": {"webserver": {"name": "web_admin", "activities": [{"workflow": "ExecuteCommand"}]},
                  "database": None}})
    exp = _experiment("ch_roles", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"webserver0": ["web_admin"]}
    assert prepared.kinds == {"web_admin": "persona"}
    assert [p[0] for p in plays] == ["install", "start"]
    assert all(p[1] == ["webserver0"] for p in plays)  # the database role was opted out
    g = _gens(plays[0][2], "webserver0")["web_admin"]
    assert g["unit"] == "bgtraffic-web_admin.service" and g["user"] == "ubuntu"
    assert "persona_traffic.daemon" in g["exec_start"] and "--check" in g["check_cmd"]
    assert _spec_file(plays[0][2], "webserver0", "web_admin", "persona.json")["name"] == "web_admin"
    built = json.loads((cfg.output_dir / "ch_roles" / "traffic" / "traffic_config.json").read_text())
    assert built["assignments"] == {"webserver0": ["web_admin"]}
    assert built["generator_kinds"] == {"web_admin": "persona"}


def test_persona_traffic_shipped_profile_resolves(chtr):
    """The shipped equifax_office profile resolves by name and covers both equifax roles."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile="equifax_office")
    exp = _experiment("ch_shipped", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"webserver0": ["web_admin"], "database0": ["office_worker"]}


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


def test_persona_traffic_mixes_generators_per_role_and_host(chtr):
    """A role can list several generators of different kinds, and a host gets extras on top of its role."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "roles": {"database": ["office_worker", _ANALYST], "webserver": None},
        "hosts": {"webserver0": _EXTRACT}})
    exp = _experiment("ch_mix", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"database0": ["office_worker", "analyst"], "webserver0": ["extract"]}
    assert prepared.kinds == {"office_worker": "persona", "analyst": "script", "extract": "script"}
    hv = plays[0][2]
    db = _gens(hv, "database0")
    assert set(db) == {"office_worker", "analyst"}
    # entry: ssh -> the unit runs as root, logs into the actor through sshd, and the key is authorised
    assert db["analyst"]["user"] == "root" and "--ssh-key" in db["analyst"]["exec_start"]
    assert hv["database0"]["bgtraffic_ssh_users"] == ["ubuntu"]
    assert hv["webserver0"]["bgtraffic_ssh_users"] == []
    # a per-host extra: its targets resolve against the run's inventory, and its rate scales per peer
    spec = _spec_file(hv, "webserver0", "extract", "spec.json")
    assert spec["vars"] == {"TARGET": ["database0"], "IP": ["10.0.1.10"]}
    assert spec["events_per_hour"] == 1.0 and "scale_by_role" not in spec
    assert _gens(hv, "webserver0")["extract"]["user"] == "tomcat"
    # each generator owns a log the collect phase fetches
    assert {l["name"] for l in hv["database0"]["bgtraffic_logs"]} == {"office_worker", "analyst"}
    # the script runner itself is shipped as the generator's payload
    assert any(p["src"].endswith("script_runner.py") for p in hv["database0"]["bgtraffic_payloads"])


def test_persona_traffic_rearm_reinstalls_every_generator_on_the_host(chtr):
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={"roles": {"database": ["office_worker", _ANALYST]}})
    exp = _experiment("ch_rearm", t)

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        await t.run_start(exp, prepared, Path("unused"), cfg)
        plays.clear()
        await t.run_rearm(exp, cfg, "database0")

    asyncio.run(drive())
    assert [(p[0], p[1]) for p in plays] == [("install", ["database0"]), ("start", ["database0"])]
    assert set(_gens(plays[0][2], "database0")) == {"office_worker", "analyst"}


def test_persona_traffic_rejects_duplicate_generator_names(chtr):
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "roles": {"database": [_ANALYST, {**_ANALYST, "seed": 2}]}})
    with pytest.raises(RuntimeError, match="two generators named 'analyst'"):
        asyncio.run(t.run_setup(_experiment("ch_dup", t), cfg))
    assert plays == []


def test_persona_traffic_rejects_bad_script_spec_and_unknown_kind(chtr):
    cfg, plays = chtr
    bad = {**_ANALYST, "events_per_hour": 0, "groups": []}
    t = PersonaTraffic(type="persona_traffic", profile={"default": bad})
    with pytest.raises(RuntimeError, match="events_per_hour must be a number > 0; groups must be"):
        asyncio.run(t.run_setup(_experiment("ch_bad", t), cfg))
    t = PersonaTraffic(type="persona_traffic", profile={"default": {"generator": "nope"}})
    with pytest.raises(RuntimeError, match="unknown traffic generator 'nope'"):
        asyncio.run(t.run_setup(_experiment("ch_kind", t), cfg))
    t = PersonaTraffic(type="persona_traffic", profile={"default": {**_EXTRACT, "scale_by_role": "printer"}})
    with pytest.raises(RuntimeError, match="matches no host"):
        asyncio.run(t.run_setup(_experiment("ch_scale", t), cfg))
    assert plays == []


def test_persona_traffic_ghosts_lite_generator(chtr):
    """GHOSTS Lite: timeline + application shipped as config files, the binary fetched at install, journal collected."""
    cfg, plays = chtr
    tl = {"Status": "Run", "TimeLineHandlers": [{"HandlerType": "Command", "Loop": True, "TimeLineEvents": [
        {"Command": "/bin/bash", "CommandArgs": ["-c", "curl -s http://{{ips:webserver}}:8080/"], "DelayAfter": 60000}]}]}
    t = PersonaTraffic(type="persona_traffic", profile={
        "roles": {"webserver": None, "database": {"generator": "ghosts_lite", "name": "ghosts", "timeline": tl}}})
    exp = _experiment("ch_ghosts", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.kinds == {"ghosts": "ghosts_lite"}
    hv = plays[0][2]
    g = _gens(hv, "database0")["ghosts"]
    assert g["exec_start"] == "/opt/bgtraffic/ghosts/ghosts" and g["user"] == "root"
    assert g["log"] == "" and g["journal_log"] == "/var/log/bgtraffic/ghosts.journal.jsonl"
    assert hv["database0"]["bgtraffic_archives"][0]["dir"] == "/opt/bgtraffic/ghosts"
    assert hv["database0"]["bgtraffic_logs"] == [{"name": "ghosts", "src": "/var/log/bgtraffic/ghosts.journal.jsonl"}]
    assert _spec_file(hv, "database0", "ghosts", "config/application.json")["Name"] == "ghosts"
    assert _spec_file(hv, "database0", "ghosts", "config/timeline.json")["TimeLineHandlers"][0]["TimeLineEvents"][0]["CommandArgs"] == ["-c", "curl -s http://{{ips:webserver}}:8080/"]


def test_shipped_equifax_workload_profile_resolves(chtr):
    """The equifax_workload profile realises the workload model's actors on the right hosts."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile="equifax_workload")
    exp = _experiment("ch_workload", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"database0": ["office_worker", "analyst", "web_user"],
                                    "webserver0": ["web_ops", "extract_refresh"]}
    hv = plays[0][2]
    assert hv["database0"]["bgtraffic_ssh_users"] == ["ubuntu"] and hv["webserver0"]["bgtraffic_ssh_users"] == ["ubuntu"]
    assert _spec_file(hv, "database0", "web_user", "spec.json")["vars"]["WEB"] == ["10.0.0.10"]
    extract = _spec_file(hv, "webserver0", "extract_refresh", "spec.json")
    assert extract["user"] == "tomcat" and extract["vars"]["TARGET"] == ["database0"]
    assert extract["events_per_hour"] == 1.0   # 1/h per corporate host; this run has one


def test_script_runner_checks_and_fires_one_event(tmp_path):
    """The host-side runner (stdlib only) validates a spec and logs one JSON line per command."""
    import subprocess, sys
    from arena.traffic.plugins.persona_traffic import generators
    runner = generators._AUX / "script_runner.py"
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"name": "t", "user": "x", "events_per_hour": 60, "seed": 7, "think_seconds": 0.2,
                                "vars": {"X": ["a", "b"]},
                                "groups": [{"label": "g", "commands": ["echo ${X}", "false"]}]}))
    log = tmp_path / "log.jsonl"
    assert subprocess.run([sys.executable, "-I", str(runner), "--spec", str(spec), "--check"]).returncode == 0
    assert subprocess.run([sys.executable, "-I", str(runner), "--spec", str(spec), "--once", "--log", str(log)],
                          timeout=30).returncode == 0
    lines = [json.loads(l) for l in log.read_text().splitlines()]
    assert [(l["label"], l["rc"]) for l in lines] == [("g", 0), ("g", 1)]
    assert lines[0]["command"] in ("echo a", "echo b") and lines[0]["entry"] == "direct"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "t", "entry": "ssh", "events_per_hour": 0, "groups": []}))
    res = subprocess.run([sys.executable, "-I", str(runner), "--spec", str(bad), "--check"], capture_output=True, text=True)
    assert res.returncode == 2 and "needs --ssh-key" in res.stderr


# --------------------------------------------------------------------------- computer_use (harness-side)

def _load_driver():
    import importlib.util
    from arena.traffic.plugins.persona_traffic import generators
    spec = importlib.util.spec_from_file_location("cu_driver_under_test", generators._AUX / "computer_use_driver.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _experiment_with_workstation(name, traffic):
    exp = _experiment(name, traffic)
    exp._traffic_access.append(TrafficSetupAccess(name="workstation0", host="10.0.1.20", ssh_key="/keys/traffic_key",
                                                  ssh_common_args='-o ProxyCommand="ssh -W %h:%p root@1.2.3.4"'))
    exp._traffic_env_spec.hosts.append(TrafficHost(name="workstation0", ip="10.0.1.20", role="workstation"))
    return exp


_DESKTOP = {"generator": "computer_use", "name": "desk", "sessions_per_hour": 2, "seed": 5,
            "persona": "You are an analyst on your workstation.", "vars": {"WEB": "{{ips:webserver}}"},
            "tasks": ["Read http://${WEB}:8080/ in the browser and write a note."]}


def test_computer_use_generator_is_harness_side(chtr):
    """A computer_use ref renders harness-side: nothing is shipped to the host and no unit is made, while the
    spec resolves peers and the allowed estate from the run's inventory."""
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile={
        "roles": {"workstation": _DESKTOP, "database": "office_worker", "webserver": None}})
    exp = _experiment_with_workstation("cu_render", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments == {"database0": ["office_worker"], "workstation0": ["desk"]}
    assert prepared.kinds == {"office_worker": "persona", "desk": "computer_use"}
    assert [(p[0], p[1]) for p in plays] == [("install", ["database0"]), ("start", ["database0"])]
    rendered = json.loads((cfg.output_dir / "cu_render" / "traffic" / "assignments.json").read_text())
    g = rendered["workstation0"][0]
    assert g["side"] == "harness" and g["kind"] == "computer_use" and g["exec_start"] == ""
    spec = json.loads(Path(g["files"]["spec.json"]).read_text())
    assert spec["model"] == "claude-opus-5-5" and spec["display"] == ":1" and spec["max_steps"] == 30
    assert spec["vars"] == {"WEB": ["10.0.0.10"]}
    assert spec["allowed_hosts"] == ["10.0.0.10", "10.0.1.10", "10.0.1.20"]
    assert spec["deny_patterns"]


def test_computer_use_rejects_bad_spec(chtr):
    cfg, plays = chtr
    bad = {**_DESKTOP, "persona": "", "tasks": [], "sessions_per_hour": 0, "effort": "turbo"}
    t = PersonaTraffic(type="persona_traffic", profile={"roles": {"workstation": bad}})
    with pytest.raises(RuntimeError, match="persona must be a non-empty string.*tasks must be.*"
                                           "sessions_per_hour must be.*effort must be one of"):
        asyncio.run(t.run_setup(_experiment_with_workstation("cu_bad", t), cfg))
    assert plays == []


def test_computer_use_driver_is_launched_and_stopped_by_the_plugin(chtr, monkeypatch):
    """start() launches ONE driver with the scoped access of every computer_use host and writes its config
    beside the traffic output; stop() signals the driver before stopping the host units."""
    cfg, plays = chtr
    launched: list[tuple] = []
    killed: list[tuple] = []

    class _Proc:
        pid = 4242

    async def fake_exec(*argv, **kw):
        launched.append(argv)
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr("arena.traffic.plugins.persona_traffic.persona_traffic.os.kill",
                        lambda pid, sig: killed.append((pid, sig)))
    t = PersonaTraffic(type="persona_traffic", computer_use_env_file="/tmp/llm.env", profile={
        "roles": {"workstation": _DESKTOP, "database": "office_worker", "webserver": None}})
    exp = _experiment_with_workstation("cu_start", t)

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        proc = await t.run_start(exp, prepared, Path("unused"), cfg)
        exp.traffic_pid = proc.pid
        plays.clear()
        await t.run_stop(exp, cfg)
        await t.run_collect_logs(exp, cfg, cfg.output_dir / "cu_start" / "traffic")

    asyncio.run(drive())
    assert len(launched) == 1
    argv = launched[0]
    assert argv[1].endswith("computer_use_driver.py") and argv[2] == "--config"
    driver_cfg = json.loads(Path(argv[3]).read_text())
    assert driver_cfg["env_file"] == "/tmp/llm.env"
    assert [h["name"] for h in driver_cfg["hosts"]] == ["workstation0"]
    assert driver_cfg["hosts"][0]["ssh_key"] == "/keys/traffic_key"   # the scoped traffic key, nothing broader
    assert driver_cfg["hosts"][0]["generators"][0].endswith("spec.json")
    assert killed == [(4242, 15)]
    assert [(p[0], p[1]) for p in plays] == [("stop", ["database0"]), ("collect", ["database0"])]


def test_computer_use_plugin_without_desktop_hosts_launches_nothing(chtr):
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile="equifax_office")
    exp = _experiment("cu_none", t)

    async def drive():
        prepared = await t.run_setup(exp, cfg)
        return await t.run_start(exp, prepared, Path("unused"), cfg)

    assert asyncio.run(drive()) is None


def test_shipped_equifax_workload_profile_covers_workstations(chtr):
    cfg, plays = chtr
    t = PersonaTraffic(type="persona_traffic", profile="equifax_workload")
    exp = _experiment_with_workstation("cu_profile", t)
    prepared = asyncio.run(t.run_setup(exp, cfg))
    assert prepared.assignments["workstation0"] == ["desktop_user"]
    assert prepared.kinds["desktop_user"] == "computer_use"


def test_driver_maps_toolset_members_to_xdotool():
    d = _load_driver()
    assert d.xdotool_argv("left_click", {"coordinate": [10, 20]}) == [
        "mousemove", "10", "20", "click", "--repeat", "1", "--delay", "80", "1"]
    assert d.xdotool_argv("right_click", {}) == ["click", "--repeat", "1", "--delay", "80", "3"]
    assert d.xdotool_argv("double_click", {"coordinate": [1, 2], "text": "ctrl+shift"}) == [
        "mousemove", "1", "2", "keydown", "ctrl", "keydown", "shift", "click", "--repeat", "2", "--delay", "80", "1",
        "keyup", "shift", "keyup", "ctrl"]
    assert d.xdotool_argv("scroll", {"coordinate": [5, 5], "scroll_direction": "up", "scroll_amount": 3}) == [
        "mousemove", "5", "5", "click", "--repeat", "3", "--delay", "40", "4"]
    assert d.xdotool_argv("key", {"text": "ctrl+s"}) == ["key", "--repeat", "1", "--delay", "60", "--", "ctrl+s"]
    assert d.xdotool_argv("hold_key", {"text": "shift", "duration": 2}) == ["keydown", "shift", "sleep", "2.0", "keyup", "shift"]
    assert d.xdotool_argv("screenshot", {}) is None and d.xdotool_argv("type", {"text": "x"}) is None


def test_driver_policy_applies_to_typed_text_only():
    d = _load_driver()
    pol = d.Policy([r"\bforbidden\b"], ["10.0.0.10"])
    assert "pattern" in pol.check("type", {"text": "this is forbidden text"})
    assert "outside the estate" in pol.check("type", {"text": "open 10.0.9.9 please"})
    assert pol.check("type", {"text": "open 10.0.0.10 please"}) is None
    assert pol.check("left_click", {"coordinate": [1, 1]}) is None


class _FakeDesktop:
    def __init__(self):
        self.calls: list[tuple] = []

    def screenshot(self, region=None):
        return b"\x89PNG\r\n\x1a\nfake"

    def act(self, member, inp):
        self.calls.append((member, inp))
        if member in ("screenshot", "zoom"):
            return {"image": self.screenshot()}
        if member == "wobble":
            raise ValueError("unknown computer toolset member 'wobble'")
        return {"text": "OK"}


def _block(name, inp, bid):
    return SimpleNamespace(type="tool_use", name=name, input=inp, id=bid, toolset_name="computer")


def _fake_client(responses):
    calls = []

    def create(**kw):
        calls.append(kw)
        return responses.pop(0)

    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), calls


def test_driver_session_executes_batches_in_order_and_stops_at_first_failure(tmp_path):
    d = _load_driver()
    turn1 = SimpleNamespace(stop_reason="tool_use", content=[
        _block("left_click", {"coordinate": [3, 4]}, "t1"),
        _block("type", {"text": "this is forbidden text"}, "t2"),
        _block("screenshot", {}, "t3")])
    turn2 = SimpleNamespace(stop_reason="tool_use", content=[_block("screenshot", {}, "t4")])
    turn3 = SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="done")])
    client, calls = _fake_client([turn1, turn2, turn3])
    desk = _FakeDesktop()
    log = d.ActionLog(tmp_path / "log.jsonl")
    spec = {"name": "desk", "model": "claude-opus-5-5", "persona": "p", "effort": "low", "max_steps": 10}
    summary = d.run_session(client, desk, spec, "do the thing", d.Policy([r"\bforbidden\b"], []), log, "ws0", "s1")

    assert summary["stop_reason"] == "end_turn" and summary["steps"] == 3 and summary["actions"] == 2
    assert desk.calls == [("left_click", {"coordinate": [3, 4]}), ("screenshot", {})]
    # request shape: the toolset entry, the fallback opt-in, the persona as system prompt, append-only history
    first = calls[0]
    assert first["tools"] == [{"type": "computer_toolset_20260801"}] and first["fallbacks"] == "default"
    assert first["betas"] == ["server-side-fallback-2026-07-01"] and first["system"].startswith("p")
    assert first["messages"][0]["content"][1]["type"] == "image"
    results = calls[1]["messages"][2]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2", "t3"]
    assert all(r["toolset_name"] == "computer" for r in results)
    assert results[0]["content"] == "OK"
    assert results[1]["is_error"] and "pattern" in results[1]["content"]
    assert results[2]["is_error"] and results[2]["content"].startswith("Not executed")
    assert calls[2]["messages"][4]["content"][0]["content"][0]["type"] == "image"   # screenshot result carries an image
    lines = [json.loads(l) for l in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert lines[0]["event"] == "session_start" and lines[-1]["event"] == "session_end"
    assert [l["member"] for l in lines if "member" in l] == ["left_click", "type", "screenshot"]


def test_driver_session_ends_on_refusal_and_replays_a_recorded_log(tmp_path):
    d = _load_driver()
    client, _ = _fake_client([SimpleNamespace(stop_reason="refusal", content=[])])
    log = d.ActionLog(tmp_path / "a.jsonl")
    spec = {"name": "desk", "model": "claude-opus-5-5", "persona": "p"}
    assert d.run_session(client, _FakeDesktop(), spec, "t", d.Policy([], []), log, "ws0", "s1")["stop_reason"] == "refusal"

    recorded = tmp_path / "rec.jsonl"
    recorded.write_text("\n".join(json.dumps(x) for x in [
        {"ts": "2026-10-29T00:00:00+00:00", "host": "ws0", "session": "a", "member": "left_click", "input": {"coordinate": [1, 1]}, "ok": True},
        {"ts": "2026-10-29T00:00:00.5+00:00", "host": "ws0", "session": "a", "member": "type", "input": {"text": "hi"}, "ok": False},
        {"ts": "2026-10-29T00:00:01+00:00", "host": "ws0", "session": "a", "member": "key", "input": {"text": "Return"}, "ok": True},
        {"ts": "2026-10-29T00:00:02+00:00", "host": "other", "session": "b", "member": "key", "input": {"text": "x"}, "ok": True},
    ]) + "\n")
    sessions = d.load_recorded_sessions(recorded, "ws0")
    assert [[a["member"] for a in s] for s in sessions] == [["left_click", "key"]]   # only successful ws0 actions
    desk = _FakeDesktop()
    summary = d.replay_session(desk, spec, sessions[0], d.ActionLog(tmp_path / "b.jsonl"), "ws0", "r1")
    assert summary["actions"] == 2 and desk.calls == [("left_click", {"coordinate": [1, 1]}), ("key", {"text": "Return"})]


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
