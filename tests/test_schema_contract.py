"""活契约测试（治理批#5）：board.py 快照 ↔ blackboard.schema.json 的永久同步锁。

满配黑板（每对象每枚举值各一）save → jsonschema.validate 必须过；
三个负例（conf 复活 / status 非法 / rel 非法）必须红。
改字段必须 board.py 与 blackboard.schema.json 同 commit——本文件就是那把锁。
"""

import json

import jsonschema
import pytest

from src.board import Blackboard

SCHEMA = json.load(open("blackboard.schema.json", encoding="utf-8"))


def _full_board() -> Blackboard:
    """满配：facts 七 kind 全、confidence 双值、chain 三 rel；immune 两档；
    findings 四 assessment；directions 四 status 双 source；chains 三 rel。"""
    b = Blackboard()
    for i, kind in enumerate(("endpoint", "credential", "kv_secret", "fingerprint",
                              "unclassified")):
        b.add_fact(kind, f"passive-{kind}-{i}", confidence="observed",
                   provenance=f"round1 Bash: cmd{i}")
    b.ingest_facts([
        '{"kind":"identity_model","value":"身份靠 cticket 派生","confidence":"observed","evidence":"e1"}',
        '{"kind":"business_context","value":"电商平台","confidence":"inferred","evidence":"e2"}',
    ], round_=1)
    b.add_immune("/api/obs", round_=1, status="403", confidence="observed")
    b.add_immune("/api/inf", round_=1, status="403", confidence="inferred")
    for i, (assess, sev) in enumerate([("confirmed", "high"), ("likely_false_positive", None),
                                       ("uncertain", "medium"), ("duplicate", "low")]):
        b.add_finding({"id": f"F-00{i+1}", "endpoint": f"/api/f{i}", "summary": "s",
                       "assessment": assess, "severity": sev, "reason": "r",
                       "evidence": f"evidence/f{i}.md", "round": 1})
    for i, status in enumerate(("open", "in_progress", "blocked", "done")):
        d = {"id": f"D-00{i+1}", "goal": f"方向{i}", "status": status, "round": 1}
        if status == "blocked":
            d["blocked_reason"] = "缺 CSRF 头"
        b.add_direction(d, source=("observer" if i % 2 else "worker"), round_=1)
    b.set_direction_comment("D-001", "批注")
    b.add_chains([
        {"rel": "derived_from", "refs": ["F-001", "F-002"], "note": "派生"},
        {"rel": "combines", "refs": ["F-003", "D-001"], "note": "组合"},
        {"rel": "same_root", "refs": ["F-001", "D-002"], "note": "同根因"},
    ], origin="observer", round_=2)
    b.update_session_intel({"coverage_gaps": [], "effective_patterns": [],
                            "notable_attempts": [], "intel_summary": "i",
                            "direction_comments": [], "immune_reviews": [], "round": 2})
    b.record_handoff("已完成 x", "model")
    b.goal["stage"] = "exploit"
    return b


def test_full_board_snapshot_validates(tmp_path):
    b = _full_board()
    b.path = str(tmp_path / "bb.json")
    b.save()
    snap = json.load(open(b.path, encoding="utf-8"))
    jsonschema.validate(snap, SCHEMA)               # 不抛 = 契约成立


def test_negative_conf_revival_rejected(tmp_path):
    """B-2 锁：conf 浮点复活 → 契约红。"""
    b = _full_board()
    snap = {"facts": [{"kind": "endpoint", "value": "/x", "confidence": "observed",
                       "conf": 0.9, "ts": "t", "round": 1, "provenance": "p"}],
            "immune": [], "findings": [], "directions": [], "chains": [],
            "session_intel": {}, "handoff": "", "goal": {}, "ledger": {},
            "verified": {"confirmed": 0, "tentative": 0}, "config": {}, "offsets": {}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)


def test_negative_bad_direction_status_rejected(tmp_path):
    snap = {"facts": [], "immune": [], "findings": [],
            "directions": [{"id": "D-001", "goal": "g", "status": "archived",
                            "source": "worker", "round": 1, "comment": ""}],
            "chains": [], "session_intel": {}, "handoff": "", "goal": {}, "ledger": {},
            "verified": {"confirmed": 0, "tentative": 0}, "config": {}, "offsets": {}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)


def test_negative_invented_chain_rel_rejected(tmp_path):
    snap = {"facts": [], "immune": [], "findings": [], "directions": [],
            "chains": [{"rel": "invented", "refs": ["F-001"], "origin": "observer", "round": 1}],
            "session_intel": {}, "handoff": "", "goal": {}, "ledger": {},
            "verified": {"confirmed": 0, "tentative": 0}, "config": {}, "offsets": {}}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)
