"""观察层 v3：观察者 verdict → finding 节点状态迁移（driver 翻译层）。

v2 的 findings/session_intel/verified 存储、business_context 等 fact_kind、
stage 判停已死（A12/A13/A16/A17/A19）——旧用例随结构报废。
P5 观察者 -p 重写后本文件扩为 OBSERVER 七类行契约测试（T6.2）。
"""

from src import driver as driver_mod
from src.board import Blackboard


def _mk_with_finding():
    b = Blackboard()
    b.create_node("finding", {"summary": "批量读他人订单"}, origin="worker",
                  round=1, id="F-001")
    return b


def test_verdict_confirms_proposed():
    b = _mk_with_finding()
    ok, nid = driver_mod._apply_verdict(
        b, {"id": "F-001", "assessment": "confirmed", "severity": "high",
            "reason": "越权读取成立"})
    assert ok and nid == "F-001"
    n = b.node("F-001")
    assert n["state"] == "confirmed"
    assert n["payload"]["severity"] == "high"
    assert "越权" in n["payload"]["reason"]
    assert len(b.confirmed_findings()) == 1


def test_verdict_dismissed_and_duplicate_map_to_dismissed():
    b = _mk_with_finding()
    ok, _ = driver_mod._apply_verdict(
        b, {"id": "F-001", "assessment": "likely_false_positive",
            "reason": "buyer=userA 属设计内"})
    assert ok and b.node("F-001")["state"] == "dismissed"
    assert any(r["id"] == "F-001" for r in b.negative_view())   # 落阴性视图

    b2 = _mk_with_finding()
    b2.create_node("finding", {"summary": "同根因第二条"}, origin="worker",
                   round=2, id="F-002")
    driver_mod._apply_verdict(b2, {"id": "F-002", "assessment": "duplicate",
                                   "reason": "并入 F-001"})
    assert b2.node("F-002")["state"] == "dismissed"


def test_verdict_uncertain_keeps_proposed():
    b = _mk_with_finding()
    ok, _ = driver_mod._apply_verdict(
        b, {"id": "F-001", "assessment": "uncertain", "reason": "证据不足"})
    assert ok
    assert b.node("F-001")["state"] == "proposed"               # 只补 reason 不迁移
    assert b.node("F-001")["payload"]["reason"] == "证据不足"


def test_verdict_cannot_flip_confirmed():
    """不变量 3：confirmed 不可被观察者翻案（历史修正走 superseded/人工）。"""
    b = _mk_with_finding()
    driver_mod._apply_verdict(b, {"id": "F-001", "assessment": "confirmed"})
    ok, _ = driver_mod._apply_verdict(
        b, {"id": "F-001", "assessment": "likely_false_positive", "reason": "翻案尝试"})
    assert ok is False
    assert b.node("F-001")["state"] == "confirmed"


def test_verdict_missing_node_is_noop():
    b = Blackboard()
    ok, _ = driver_mod._apply_verdict(
        b, {"id": "F-999", "assessment": "confirmed", "reason": "r"})
    assert ok is False
