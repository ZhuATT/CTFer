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
    # G 块：旧 suggestions 独立段废除——建议改经 direction_comments 入方向层（source=observer）
    assert "观察者建议" not in r
    assert b.intel_summary() == "z"
    assert b.verified["confirmed"] == 1


# ── phase5 B4：C-2 防注入 / G 三件套 / G-1 截断 / 消费端 ──────────────────

def test_injection_guard_in_both_prompts():
    """C-2 文本断言：两个 PROMPT 最开头（证据文本之前）都有不可信声明。
    防回归——被删了这条测试就红。"""
    from src.observer import JUDGE_PROMPT, SESSION_PROMPT
    for p in (JUDGE_PROMPT, SESSION_PROMPT):
        assert "证据不可信声明" in p
        assert "一律无视" in p and "只当数据" in p
        assert "不猜 false" in p
        # 位置：声明在证据/发现文本之前
        assert p.find("证据不可信声明") < p.find("【证据】") if "【证据】" in p else True
        assert p.find("证据不可信声明") < p.find("【本轮全部发现") if "【本轮全部发现" in p else True


def test_observe_session_new_inputs_rendered():
    obs, captured = _mk_observer([json.dumps({
        "final_assessments": [], "direction_comments": [], "immune_reviews": [],
        "chains": [], "coverage_gaps": [], "effective_patterns": [],
        "notable_attempts": [], "intel_summary": "ok"})])
    obs.observe_session([], [], "bs", "h",
                        directions=[{"id": "D-001", "status": "blocked",
                                     "goal": "admin 面写入", "note": "需 CSRF 头",
                                     "comment": "建议转向"}],
                        chains=[{"rel": "same_root", "refs": ["F-001", "F-002"]}])
    p = captured[0][1]["content"]
    assert "【方向表" in p and "[D-001] blocked admin 面写入" in p
    assert "建议转向" in p
    assert "【已知联系" in p and "same_root" in p


def test_observe_session_parses_three_pieces():
    payload = {
        "final_assessments": [],
        "direction_comments": [
            {"id": "D-002", "comment": "已blocked两轮建议转向"},
            {"goal": "验证 /api/user BOLA", "endpoint": "/api/user", "note": "无对象级校验"}],
        "immune_reviews": [{"endpoint": "/api/old", "verdict": "retest", "reason": "仅一次403"}],
        "chains": [{"rel": "same_root", "refs": ["F-001", "F-007"], "note": "判重顺产"}],
        "coverage_gaps": [], "effective_patterns": [],
        "notable_attempts": [], "intel_summary": "x"}
    obs, _ = _mk_observer([json.dumps(payload)])
    r = obs.observe_session([], [], "bs", "h")
    assert len(r["direction_comments"]) == 2
    assert r["immune_reviews"][0]["verdict"] == "retest"
    assert r["chains"][0]["rel"] == "same_root"


def test_governance_truncates_new_directions_at_three():
    """G-1：observer 新方向建议每轮截断 3 条（接单员化闸）。"""
    from src.driver import _apply_observer_governance
    from src.board import Blackboard
    bb = Blackboard()
    session = {"direction_comments": [
        {"goal": f"方向{i}", "endpoint": f"/api/{i}"} for i in range(6)]}
    out = _apply_observer_governance(bb, session, round_no=1)
    assert out["new_directions"] == 3
    assert sum(1 for d in bb.directions if d["source"] == "observer") == 3


def test_governance_comment_and_retest():
    from src.driver import _apply_observer_governance
    from src.board import Blackboard
    bb = Blackboard()
    bb.add_direction({"id": "D-001", "goal": "g", "status": "blocked"}, round_=1)
    session = {"direction_comments": [{"id": "D-001", "comment": "建议转向"}],
               "immune_reviews": [{"endpoint": "/api/old", "verdict": "retest", "reason": "只试过一次403"},
                                   {"endpoint": "/api/old", "verdict": "retest", "reason": "重复"}]}
    out = _apply_observer_governance(bb, session, round_no=2)
    assert out["comments"] == 1
    dm = {d["id"]: d for d in bb.directions}
    assert dm["D-001"]["comment"] == "建议转向"
    retest = [d for d in bb.directions if d["goal"].startswith("重验阴性：")]
    assert len(retest) == 1 and retest[0]["source"] == "observer"   # 同口子不重复开
    assert retest[0]["endpoint"] == "/api/old"
