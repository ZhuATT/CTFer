"""活契约测试 v3（治理批#5 惯例）：board.py 快照 ↔ blackboard.schema.json 的永久同步锁。

满配黑板（三 kind 全状态、六动词边、bookkeeping 全字段）save → jsonschema.validate
必须过；负例（非法 finding state / v2 遗形动词 / payload 多余键 / v2 容器）必须红。
改字段必须 board.py 与 blackboard.schema.json 同 commit——本文件就是那把锁。
"""

import json

import jsonschema
import pytest

from src.board import Blackboard

SCHEMA = json.load(open("blackboard.schema.json", encoding="utf-8"))


def _full_board() -> Blackboard:
    """满配：intent 四态/finding 三态/fact 四态、origin 四值、边六动词、bookkeeping 全键。"""
    b = Blackboard()
    d = b.create_node("intent", {"goal": "方向", "note": "n", "comment": "c",
                                 "blocked_reason": "br"}, endpoint="h:1",
                      origin="observer", round=1)
    b.update_node(d, state="blocked")
    d2 = b.create_node("intent", {"goal": "方向2"}, origin="worker", round=1)
    b.update_node(d2, state="in_progress")
    d3 = b.create_node("intent", {"goal": "方向3"}, origin="user", round=0)
    b.update_node(d3, state="done")
    d4 = b.create_node("intent", {"goal": "方向4"}, origin="controller", round=1)
    f = b.create_node("finding", {"summary": "发现", "report": "reports/F-001.md",
                                  "evidence": "e", "severity": "high", "reason": "r"},
                      endpoint="h:2", origin="worker", round=1)
    b.update_node(f, state="confirmed")
    f2 = b.create_node("finding", {"summary": "发现2", "severity": "none"},
                       origin="worker", round=2)
    b.update_node(f2, state="dismissed")
    f3 = b.create_node("finding", {"summary": "发现3", "severity": "low"},
                       endpoint="h:3", origin="observer", round=2)      # proposed
    t = b.create_node("fact", {"value": "事实", "evidence": "ev"},
                      origin="user", round=0)
    b.update_node(t, state="confirmed")
    t2 = b.create_node("fact", {"value": "事实2"}, origin="worker", round=1)
    b.update_node(t2, state="confirmed")
    b.update_node(t2, state="superseded")
    t3 = b.create_node("fact", {"value": "事实3"}, origin="controller", round=2)  # proposed
    for rel, src, dst in (("sources", t3, d), ("yields", d, f), ("derived_from", f, f3),
                          ("spawns", f, d4), ("same_root", f3, f), ("supersedes", t2, t)):
        b.add_edge(src, rel, dst, origin="observer", note="n", round=2)
    b.set_goal("目标", round=2)
    b.record_handoff("交接")
    b.add_intel("证词", 2)
    b.bookkeeping["guide"] = {"round": 2, "text": "主攻 /search；备选 /admin；自由探索照常"}
    b.offsets["facts"] = 5
    b.bookkeeping["config"]["endpoint_n"] = 15
    return b


def test_full_board_snapshot_validates(tmp_path):
    b = _full_board()
    b.path = str(tmp_path / "bb.json")
    b.save()
    snap = json.load(open(b.path, encoding="utf-8"))
    jsonschema.validate(snap, SCHEMA)                    # 不抛 = 契约成立


def _bare() -> dict:
    return {"graph": {"nodes": [], "edges": []},
            "bookkeeping": {"offsets": {}, "goal": {"text": "", "updated_round": 0},
                            "handoff": "", "config": {}, "intel": []}}


def test_negative_bad_finding_state_rejected():
    snap = _bare()
    snap["graph"]["nodes"].append({"id": "F-001", "kind": "finding", "state": "killed",
                                   "payload": {"summary": "s"}, "endpoint": "h",
                                   "origin": "worker", "round": 1, "updated_at": "t"})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)


def test_negative_v2_rel_combines_rejected():
    """v2 combines 已死（schema §4.1 六动词）——复活即契约红。"""
    snap = _bare()
    snap["graph"]["edges"].append({"src": "F-001", "rel": "combines", "dst": "D-001",
                                   "origin": "worker", "round": 1})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)


def test_negative_extra_payload_key_rejected():
    """v3 砍掉的字段（confidence 等）进 payload 即契约红。"""
    snap = _bare()
    snap["graph"]["nodes"].append({"id": "T-001", "kind": "fact", "state": "proposed",
                                   "payload": {"value": "v", "confidence": "observed"},
                                   "endpoint": "global", "origin": "worker",
                                   "round": 1, "updated_at": "t"})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)


def test_negative_v2_container_rejected():
    """v2 容器（facts/immune 顶层键）不再满足契约。"""
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"facts": [], "immune": [], "findings": []}, SCHEMA)


def test_negative_wrong_id_prefix_rejected():
    snap = _bare()
    snap["graph"]["nodes"].append({"id": "X-001", "kind": "fact", "state": "proposed",
                                   "payload": {"value": "v"}, "endpoint": "global",
                                   "origin": "worker", "round": 1, "updated_at": "t"})
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(snap, SCHEMA)
