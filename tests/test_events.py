import json

import pytest

from src.events import EVENT_TYPES, EventWriter, redact


def test_redact_nested_and_case_insensitive():
    data = {
        "Authorization": "Bearer abc",
        "nested": {"session_token": "xyz", "session_id": "keep-me"},
        "Cookie": "a=1",
        "api_key": "sk-1",
        "plain": "untouched",
    }
    out = redact(data)
    assert out["Authorization"] == "***"
    assert out["nested"]["session_token"] == "***"
    assert out["nested"]["session_id"] == "keep-me"   # 本地会话标识不是凭据，不脱敏
    assert out["Cookie"] == "***"
    assert out["api_key"] == "***"
    assert out["plain"] == "untouched"


def test_redact_list():
    assert redact([{"token": "t"}, "s"]) == [{"token": "***"}, "s"]


def test_event_types_registry_has_design_set():
    for t in ("run_start", "run_end", "session_start", "session_end", "heartbeat",
              "fact_added", "immune_added", "claim_submitted", "claim_verdict",
              "gate_pass", "gate_fail", "finding_confirmed", "stoploss_trigger",
              "handoff_harvested", "surface_parse_fail"):
        assert t in EVENT_TYPES


def test_writer_appends_jsonl_and_redacts(tmp_path):
    w = EventWriter(str(tmp_path / "state" / "auto-log.jsonl"))
    w.emit("run_start", {"target": "x", "api_key": "sk-secret"})
    w.emit("fact_added", {"tool": "Read", "cookie": "sid=1"}, round_=2)
    w.emit("session_end", {"session_id": "sess-9", "total_cost_usd": 0.01}, round_=2)
    w.close()

    lines = (tmp_path / "state" / "auto-log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    rows = [json.loads(l) for l in lines]
    assert rows[0]["type"] == "run_start"
    assert rows[0]["data"]["api_key"] == "***"
    assert rows[1]["type"] == "fact_added"
    assert rows[1]["round"] == 2
    assert rows[2]["data"]["session_id"] == "sess-9"      # 不被脱敏
    assert rows[2]["data"]["total_cost_usd"] == 0.01
    assert all({"ts", "type", "round", "data"} == set(r) for r in rows)


def test_writer_rejects_unknown_type(tmp_path):
    w = EventWriter(str(tmp_path / "log.jsonl"))
    with pytest.raises(ValueError):
        w.emit("not_a_real_event", {})
    w.close()
