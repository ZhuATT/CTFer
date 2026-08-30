"""A1 黑板观察层测试：findings/session_intel/business_context 存储渲染 + goal 链新判据。"""

from src.board import Blackboard, KINDS
from src.prompt import render_round_prompt


def _mk_finding(id="F-001", endpoint="/search", summary="SQL注入",
                assessment="confirmed", severity="high", reason="...", round=1):
    return {"id": id, "endpoint": endpoint, "summary": summary,
            "assessment": assessment, "severity": severity,
            "reason": reason, "evidence": "evidence/x.md", "round": round}


def test_business_context_in_kinds():
    assert "business_context" in KINDS


def test_add_finding_and_confirmed_render():
    b = Blackboard()
    b.add_finding(_mk_finding())
    assert len(b.findings) == 1
    assert b.confirmed_findings()[0]["id"] == "F-001"
    # verified 计数自动同步
    assert b.verified["confirmed"] == 1
    r = b.render()
    assert "已确认发现" in r and "/search" in r and "SQL注入" in r and "high" in r


def test_add_finding_overwrite_same_id():
    b = Blackboard()
    b.add_finding(_mk_finding(assessment="confirmed"))
    b.add_finding(_mk_finding(assessment="uncertain"))    # 重新评估 → 覆盖
    assert len(b.findings) == 1                            # 不重复
    assert b.verified["confirmed"] == 0                    # 计数更新
    assert b.verified["tentative"] == 1


def test_false_positive_render():
    b = Blackboard()
    b.add_finding(_mk_finding(id="F-002", assessment="likely_false_positive",
                              severity=None, reason="buyer=userA 属设计内"))
    r = b.render()
    assert "已否决模式" in r and "buyer=userA" in r
    assert b.false_positive_findings()[0]["id"] == "F-002"


def test_duplicate_assessment():
    b = Blackboard()
    b.add_finding(_mk_finding(id="F-001", assessment="confirmed"))
    b.add_finding(_mk_finding(id="F-005", assessment="duplicate",
                              reason="与 F-001 同根因"))
    assert len(b.confirmed_findings()) == 1               # duplicate 不算 confirmed
    assert len(b.false_positive_findings()) == 1          # duplicate 进已否决段
    assert b.verified["confirmed"] == 1


def test_session_intel_suggestions_render():
    b = Blackboard()
    b.update_session_intel({
        "coverage_gaps": ["/api/order/detail 未测"],
        "effective_patterns": ["id 遍历有效"],
        "suggestions": ["address/update 有写入语义值得关注"],
        "notable_attempts": ["试了路径穿越但只试了 /etc/passwd"],
        "intel_summary": "目标对 id 遍历无防护",
        "round": 2})
    r = b.render()
    # B1 选法 b：观察者建议独立段（与机械未测面分开）
    assert "观察者建议" in r and "address/update" in r
    assert "未测面" not in r.split("观察者建议")[0].split("阴性记录")[0]  # 两者分开
    # intel_summary 在交接段
    assert b.intel_summary() == "目标对 id 遍历无防护"


def test_intel_summary_in_prompt_relay():
    b = Blackboard()
    b.record_handoff("我测了搜索面", "model")
    b.update_session_intel({"intel_summary": "admin 可匿名写入", "round": 1})
    p = render_round_prompt(b)
    assert "我测了搜索面" in p and "观察者情报" in p and "admin 可匿名写入" in p


def test_goal_chain_reads_findings():
    b = Blackboard()
    b.goal["stage"] = "exploit"
    assert b.check_goal() != "report"                     # 无 confirmed → 不推进
    b.add_finding(_mk_finding(assessment="confirmed"))
    assert b.check_goal() == "report"                     # 有 confirmed → 推进


def test_session_intel_roundtrip():
    b = Blackboard("/tmp/test_board_obs.json")
    b.add_finding(_mk_finding())
    b.update_session_intel({"suggestions": ["x"], "intel_summary": "y", "round": 1})
    b.save()
    b2 = Blackboard("/tmp/test_board_obs.json")
    assert len(b2.findings) == 1 and b2.findings[0]["assessment"] == "confirmed"
    assert b2.session_intel.get("suggestions") == ["x"]
    assert b2.verified["confirmed"] == 1                  # 派生计数也恢复了
