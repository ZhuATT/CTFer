"""observer_harvest v2 单测（批3fix F6）：判断书执行器——五操作/拒收矩阵/幂等/receipts。

协议=contracts/OBSERVER-INTERFACE.md。图唯一写手=观察者（经本执行器），
入图即终态（R2）：finding 终态写死、fact 仅 confirmed→superseded。
"""

import json

import pytest

from src import observer_harvest as oh
from src.board import Blackboard


def _apply(bb, ops, *, round=1, noreport_rejects=()):
    doc = {"round": round, "operations": ops}
    return oh.apply_judgment(bb, doc, round=round, root=None,
                             noreport_rejects=set(noreport_rejects))


def test_add_fact_basic_and_fields():
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_fact", "summary": "身份锚是 customsid session",
                     "evidence": "facts/auth.md", "endpoint": "/api/login"}])
    assert r["applied"] == 1 and r["rejects"] == []
    n = bb.node("T-001")
    assert n["state"] == "confirmed" and n["origin"] == "observer"
    assert n["payload"]["value"] == "身份锚是 customsid session"
    assert n["payload"]["evidence"] == "facts/auth.md"


def test_add_fact_missing_required_rejected():
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_fact", "summary": "没证据"},
                    {"op": "add_fact", "evidence": "e"}])
    assert r["applied"] == 0
    assert len(r["rejects"]) == 2                     # 缺 summary/evidence 各一
    assert bb.nodes("fact") == []


def test_add_fact_dangling_ref_is_advisory():
    """ref 是建议性连线——指向不存在的节点不拒收，只是不连边（与强制字段区分）。"""
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_fact", "summary": "x", "evidence": "e",
                     "ref": "T-999"}])
    assert r["applied"] == 1 and r["rejects"] == []
    assert bb.graph["edges"] == []


def test_add_fact_dedup_existing_idempotent():
    bb = Blackboard()
    r1 = _apply(bb, [{"op": "add_fact", "summary": "WAF=宝塔", "evidence": "e"}])
    r2 = _apply(bb, [{"op": "add_fact", "summary": "  waf=宝塔  ", "evidence": "e2"}])
    assert r1["applied"] == 1
    assert r2["counts"]["dedup_existing"] == 1        # 幂等：返回已有 id
    assert len(bb.nodes("fact")) == 1


def test_add_fact_picture_prefix_auto_supersede():
    bb = Blackboard()
    _apply(bb, [{"op": "add_fact", "summary": "目标画像：旧版画像", "evidence": "e"}])
    r = _apply(bb, [{"op": "add_fact", "summary": "目标画像：新版画像", "evidence": "e2"}])
    assert r["applied"] == 1
    states = {n["payload"]["value"]: n["state"] for n in bb.nodes("fact")}
    assert states["目标画像：旧版画像"] == "superseded"
    assert states["目标画像：新版画像"] == "confirmed"
    assert any(e["rel"] == "supersedes" for e in bb.graph["edges"])


def test_add_finding_requires_report_and_reason():
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_finding", "summary": "s"}])            # 缺 report/severity/reason
    assert r["applied"] == 0 and len(r["rejects"]) == 1
    r2 = _apply(bb, [{"op": "add_finding", "summary": "越权读取",
                      "report": "findings/idor.md", "severity": "high",
                      "reason": "IDOR 实证"}])
    assert r2["applied"] == 1
    n = bb.node("F-001")
    assert n["state"] == "confirmed"                   # result 默认 confirmed
    assert n["payload"]["report"] == "findings/idor.md"


def test_add_finding_dismissed_goes_negative():
    bb = Blackboard()
    _apply(bb, [{"op": "add_finding", "summary": "疑似 sourcemap",
                 "report": "findings/sm.md", "severity": "low",
                 "reason": "形状即现象", "result": "dismissed"}])
    assert bb.node("F-001")["state"] == "dismissed"
    assert any(r["id"] == "F-001" for r in bb.negative_view())


def test_add_finding_noreport_reject():
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_finding", "summary": "sourcemap 可下载",
                     "report": "findings/main.js.map.md", "severity": "low",
                     "reason": "x"}], noreport_rejects=("findings/main.js.map.md",))
    assert r["applied"] == 0 and len(r["rejects"]) == 1
    assert "noreport" in r["rejects"][0]["error"]


def test_add_intent_and_set_state_lifecycle():
    bb = Blackboard()
    r = _apply(bb, [
        {"op": "add_intent", "goal": "验证 authc 面越权", "note": "F-001 同型", "ref": None},
        {"op": "set_state", "id": "D-001", "state": "in_progress", "reason": "开工"},
        {"op": "set_state", "id": "D-001", "state": "blocked", "reason": "若获得 admin 凭证可重试"},
    ])
    assert r["applied"] == 3
    d = bb.node("D-001")
    assert d["state"] == "blocked" and d["payload"]["blocked_reason"]
    # fact 终态写死：set_state 对 fact 拒收
    _apply(bb, [{"op": "add_fact", "summary": "x", "evidence": "e"}])
    r2 = _apply(bb, [{"op": "set_state", "id": "T-001", "state": "done", "reason": "r"}])
    assert r2["applied"] == 0


def test_set_state_blocked_requires_condition():
    bb = Blackboard()
    _apply(bb, [{"op": "add_intent", "goal": "g"}])
    r = _apply(bb, [{"op": "set_state", "id": "D-001", "state": "blocked", "reason": ""}])
    assert r["applied"] == 0 and "可检验" in r["rejects"][0]["error"]


def test_add_edge_six_verbs_and_dedup():
    bb = Blackboard()
    _apply(bb, [
        {"op": "add_fact", "summary": "线索 A", "evidence": "e"},
        {"op": "add_fact", "summary": "线索 B", "evidence": "e2"},
        {"op": "add_intent", "goal": "组合打点"},
    ])
    r = _apply(bb, [
        {"op": "add_edge", "src": "T-001", "rel": "sources", "dst": "D-001", "note": "支撑"},
        {"op": "add_edge", "src": "T-001", "rel": "sources", "dst": "D-001", "note": "重复"},
    ])
    assert r["applied"] == 1 and r["counts"]["dedup_existing"] == 1   # 重复边幂等吸收
    assert len(bb.graph["edges"]) == 1
    bad = _apply(bb, [{"op": "add_edge", "src": "T-001", "rel": "combines",
                       "dst": "D-001", "note": "v2 死动词"}])
    assert bad["applied"] == 0 and "rel 非法" in bad["rejects"][0]["error"]


def test_ref_auto_edge_semantics():
    """ref 连线语义表：fact→intent = sources；intent→finding = spawns。"""
    bb = Blackboard()
    _apply(bb, [{"op": "add_intent", "goal": "authc 越权面"}])                 # D-001
    _apply(bb, [{"op": "add_fact", "summary": "roles 无归属校验",
                 "evidence": "facts/roles.md", "ref": "D-001"}])              # D-001 yields T-001
    assert any(e["src"] == "D-001" and e["rel"] == "yields" and e["dst"] == "T-001"
               for e in bb.graph["edges"])
    _apply(bb, [{"op": "add_finding", "summary": "越权读取", "report": "findings/x.md",
                 "severity": "high", "reason": "r"}])                          # F-001
    _apply(bb, [{"op": "add_intent", "goal": "同型端点排查", "ref": "F-001"}])  # D-002 spawns 自 F-001
    assert any(e["src"] == "F-001" and e["rel"] == "spawns" and e["dst"] == "D-002"
               for e in bb.graph["edges"])


def test_judgment_book_malformed_tolerated():
    bb = Blackboard()
    r = oh.apply_judgment(bb, {"round": 1}, round=1, root=None)          # 无 operations
    assert r["applied"] == 0 and r["rejects"]
    r2 = oh.apply_judgment(bb, "not a dict", round=1, root=None)
    assert r2["applied"] == 0


def test_receipts_written(tmp_path):
    bb = Blackboard()
    r = _apply(bb, [{"op": "add_fact", "summary": "x", "evidence": "e"}], round=3)
    r["receipts"] and oh._write_receipts(tmp_path, r["receipts"])
    log = tmp_path / ".at1" / "interface_log.jsonl"
    rows = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert rows and rows[0]["op"] == "add_fact" and rows[0]["status"] == "applied"


def test_write_rejects_appends(tmp_path):
    oh.write_rejects(tmp_path, [{"index": 0, "error": "x"}], round=2)
    oh.write_rejects(tmp_path, [{"index": 1, "error": "y"}], round=3)
    p = tmp_path / ".observer" / "OBSERVER.rejects"
    lines = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2 and {r["round"] for r in lines} == {2, 3}
