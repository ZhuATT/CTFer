"""observer.py 测试：mock LLM，测接口/解析/合并逻辑。"""

import json

from src.observer import Observer


def _mk_observer(responses=None):
    """responses: list of JSON strings returned in order. If exhausted, repeat last."""
    calls = []
    idx = [0]
    def mock_chat(msgs):
        calls.append(msgs)
        if responses:
            i = min(idx[0], len(responses) - 1)
            idx[0] += 1
            return responses[i]
        return '{"is_vulnerability": true, "severity": "high", "reason": "test"}'
    return Observer(chat_fn=mock_chat, business_context="测试上下文"), calls


def test_judge_finding_pass():
    obs, _ = _mk_observer(['{"is_vulnerability": true, "severity": "high", "reason": "SQL注入"}'])
    r = obs.judge_finding({"endpoint": "/search", "summary": "SQL注入"}, "evidence text")
    assert r["is_vulnerability"] is True
    assert r["severity"] == "high"


def test_judge_finding_reject():
    obs, _ = _mk_observer(['{"is_vulnerability": false, "severity": null, "reason": "设计内行为"}'])
    r = obs.judge_finding({"endpoint": "/api/order", "summary": "看手机号"}, "evidence")
    assert r["is_vulnerability"] is False
    assert r["reason"] == "设计内行为"


def test_judge_finding_parse_failure():
    obs, _ = _mk_observer(["纯垃圾输出"])
    r = obs.judge_finding({"endpoint": "/x", "summary": "s"}, "ev")
    assert r["is_vulnerability"] is None
    assert "不可解析" in r["reason"]


def test_observe_session_dedup():
    session_result = json.dumps({
        "final_assessments": [
            {"id": "F-002", "assessment": "duplicate", "severity": None,
             "reason": "与 F-001 同根因"}
        ],
        "coverage_gaps": ["/api/address 未测"],
        "effective_patterns": ["SQL注入有效"],
        "suggestions": ["address 有写入语义"],
        "notable_attempts": [],
        "intel_summary": "admin 可匿名写入"})
    # 第一次返回发现级结果，第二次返回会话级结果
    obs, _ = _mk_observer([
        '{"is_vulnerability": true, "severity": "high", "reason": "SQL"}',  # F-001 judge
        '{"is_vulnerability": true, "severity": "high", "reason": "SQL"}',  # F-002 judge
        session_result])  # session observation
    result = obs.run(
        findings=[{"id": "F-001", "endpoint": "/search", "summary": "SQL注入"},
                  {"id": "F-002", "endpoint": "/search", "summary": "SQL注入 variant"}],
        evidence_texts={"F-001": "ev1", "F-002": "ev2"},
        previous_confirmed=[{"id": "F-000", "endpoint": "/search", "summary": "SQL注入"}],
        board_summary="端点5个", handoff="测了搜索面")
    # F-002 被会话级判重覆盖为 duplicate
    f2 = next(f for f in result["findings"] if f["id"] == "F-002")
    assert f2["assessment"] == "duplicate"
    # F-001 保持 confirmed（发现级结果 + 会话级未覆盖）
    f1 = next(f for f in result["findings"] if f["id"] == "F-001")
    assert f1["assessment"] == "confirmed"
    # session_intel 正确
    assert result["session_intel"]["coverage_gaps"] == ["/api/address 未测"]
    assert result["session_intel"]["intel_summary"] == "admin 可匿名写入"


def test_run_merges_correctly():
    obs, _ = _mk_observer([
        '{"is_vulnerability": true, "severity": "high", "reason": "r1"}',
        '{"is_vulnerability": false, "severity": null, "reason": "r2"}',
        json.dumps({
            "final_assessments": [],
            "coverage_gaps": [], "effective_patterns": [],
            "suggestions": [], "notable_attempts": [], "intel_summary": "s"})])
    result = obs.run(
        findings=[{"id": "A", "endpoint": "/a", "summary": "s"},
                  {"id": "B", "endpoint": "/b", "summary": "s"}],
        evidence_texts={"A": "ev", "B": "ev"},
        previous_confirmed=[], board_summary="x", handoff="y")
    # 无会话级覆盖 → 用发现级结果映射
    fa = next(f for f in result["findings"] if f["id"] == "A")
    fb = next(f for f in result["findings"] if f["id"] == "B")
    assert fa["assessment"] == "confirmed"       # is_vuln=True → confirmed
    assert fb["assessment"] == "likely_false_positive"  # is_vuln=False → likely_false


def test_business_context_default():
    obs = Observer(chat_fn=lambda m: "{}", business_context="")
    assert "保守" in obs.business_context  # 默认保守提示


def test_board_integration():
    """A1+A2 集成：观察者输出直入黑板。"""
    from src.board import Blackboard
    obs, _ = _mk_observer([
        '{"is_vulnerability": true, "severity": "high", "reason": "test"}',
        json.dumps({
            "final_assessments": [],
            "coverage_gaps": ["x"], "effective_patterns": [],
            "suggestions": ["try y"], "notable_attempts": [],
            "intel_summary": "z"})])
    result = obs.run(
        findings=[{"id": "F-1", "endpoint": "/e", "summary": "s"}],
        evidence_texts={"F-1": "ev"}, previous_confirmed=[],
        board_summary="", handoff="")
    # 入板
    b = Blackboard()
    for f in result["findings"]:
        b.add_finding(f)
    b.update_session_intel(result["session_intel"])
    # 渲染验证
    r = b.render()
    assert "已确认发现" in r and "/e" in r
    assert "观察者建议" in r and "try y" in r
    assert b.intel_summary() == "z"
    assert b.verified["confirmed"] == 1
