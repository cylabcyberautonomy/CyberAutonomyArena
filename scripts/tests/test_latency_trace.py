"""Latency instrumentation on the arena side: env-action stamps, their persistence, and the ES ingest stamp."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from arena.env_action_server import handle_env_action
from arena.environment import EnvActionKind, EnvActionRequest, EnvActionResult
from arena.environment.lifecycle import EnvironmentLifecycle


class _Reg:
    def __init__(self, exp):
        self._exp = exp

    def get(self, name):
        if name != self._exp.experiment_name:
            raise KeyError(name)
        return self._exp


class _Env:
    async def handle_env_request(self, exp, deployed, req: EnvActionRequest, cfg):
        await asyncio.sleep(0.01)  # actuation takes time; finished_ts must come after ts
        return EnvActionResult(kind=req.kind, ok=True, name=req.target)


def _serving_exp(recorded: list):
    lc = EnvironmentLifecycle(on_request=recorded.append)
    return SimpleNamespace(experiment_name="e", _env_serving=True, _env_action_token=None,
                           environment=_Env(), deployed_environment=None, _env_lifecycle=lc, traffic=None)


def test_env_action_trace_is_stamped_received_and_finished():
    recorded: list = []
    exp = _serving_exp(recorded)
    payload = {"experiment_name": "e", "action": {"kind": "RebuildHost", "target": "database0"}}
    res = asyncio.run(handle_env_action(payload, registry=_Reg(exp), cfg=None, trusted_transport=True))
    assert res["ok"] and res["status"] == 200
    assert len(recorded) == 1
    row = recorded[0]
    assert row["hop"] == "env_received" and row["kind"] == "RebuildHost" and row["target"] == "database0"
    assert row["ts"] < row["finished_ts"]
    assert row["ts"].endswith("+00:00")


def test_persist_env_request_appends_jsonl(tmp_path, monkeypatch):
    from arena import main
    monkeypatch.setattr(main, "cfg", SimpleNamespace(output_dir=tmp_path), raising=False)
    exp = SimpleNamespace(experiment_name="e")
    main._persist_env_request(exp, {"hop": "env_received", "kind": "RebuildHost", "ts": "t1", "finished_ts": "t2"})
    main._persist_env_request(exp, {"hop": "env_received", "kind": "RemoveHost", "ts": "t3", "finished_ts": "t4"})
    rows = [json.loads(l) for l in (tmp_path / "e" / "experiment" / "env_actions.jsonl").read_text().splitlines()]
    assert [r["kind"] for r in rows] == ["RebuildHost", "RemoveHost"]


def test_env_lc_wires_request_persistence(tmp_path, monkeypatch):
    from arena import main
    monkeypatch.setattr(main, "cfg", SimpleNamespace(output_dir=tmp_path), raising=False)
    exp = SimpleNamespace(experiment_name="e")
    lc = main._env_lc(exp)
    lc.record_request({"hop": "env_received", "kind": "AddHost", "ts": "t", "finished_ts": "t"})
    assert (tmp_path / "e" / "experiment" / "env_actions.jsonl").exists()


def test_persist_env_request_without_cfg_is_a_noop(monkeypatch):
    from arena import main
    monkeypatch.setattr(main, "cfg", None, raising=False)
    main._persist_env_request(SimpleNamespace(experiment_name="e"), {"hop": "x"})  # must not raise


def test_box_es_stamp_script_installs_pipeline_and_template():
    script = (Path("arena/defender/plugins/llm_soc/box_es_stamp.sh")).read_text()
    assert "_ingest/pipeline/arena_ingest_stamp" in script
    assert '"arena.ingest_ts"' in script and "{{_ingest.timestamp}}" in script
    assert '"index_patterns": ["sysflow*", "falco*"]' in script
    assert '"index.default_pipeline": "arena_ingest_stamp"' in script
    # Existing indices are switched in place too, so a sensor that shipped early is still stamped.
    assert "_settings" in script


def test_llm_soc_collects_the_box_action_trace():
    from arena.defender.plugins.llm_soc import LLMSOCDefenderPlugin
    assert "box_actions.jsonl" in LLMSOCDefenderPlugin.BOX_LOG_FILES
    assert "box_agent.log" in LLMSOCDefenderPlugin.BOX_LOG_FILES


# ---------------------------------------------------------------- LLMDetectionAndResponse wiring

def test_llm_soc_passes_strategy_options_through():
    from arena.defender.plugins.llm_soc import LLMSOCDefenderPlugin
    from arena.defender.plugins.llm_soc.llm_soc import PreparedLLMSOC
    plug = LLMSOCDefenderPlugin(type="llm_soc", strategy="LLMDetectionAndResponse", llm_model="endpoint/FAST/x",
                                strategy_options={"telemetry": "store", "agents": "single"})
    built = plug.build_config("e", None, PreparedLLMSOC())
    assert built["strategy"] == "LLMDetectionAndResponse" and built["strategy_options"] == {"telemetry": "store", "agents": "single"}
    assert LLMSOCDefenderPlugin(type="llm_soc", strategy="FalcoLLM").build_config("e", None, PreparedLLMSOC())["strategy_options"] == {}


def test_llm_soc_opens_the_stream_forward_only_in_stream_mode():
    from arena.defender.plugins.llm_soc import LLMSOCDefenderPlugin
    store = LLMSOCDefenderPlugin(type="llm_soc", strategy="LLMDetectionAndResponse", strategy_options={"telemetry": "store"})
    assert store.box_ingress() == {"telemetry": [9200]}
    stream = LLMSOCDefenderPlugin(type="llm_soc", strategy="LLMDetectionAndResponse", strategy_options={"telemetry": "stream"})
    assert stream.box_ingress() == {"telemetry": [9200], "forward": [5140]}
    custom = LLMSOCDefenderPlugin(type="llm_soc", strategy="LLMDetectionAndResponse",
                                  strategy_options={"telemetry": "stream", "stream_port": 6000})
    assert custom.box_ingress()["forward"] == [6000]
    assert LLMSOCDefenderPlugin(type="llm_soc", strategy="FalcoLLM").box_ingress() == {"telemetry": [9200]}


def test_llm_soc_box_installs_the_ingest_stamp_too():
    src = Path("arena/defender/plugins/llm_soc/llm_soc_box.py").read_text()
    assert "box_es_stamp.sh" in src


def test_runner_registers_llm_detection_and_response():
    src = Path("arena/defender/plugins/llm_soc/runner.py").read_text()
    assert '"LLMDetectionAndResponse": LLMDetectionAndResponse' in src and '"LLMDetectionAndResponse": PassiveTelemetry' in src
    assert "strategy_options" in src and "setup_access" in src
