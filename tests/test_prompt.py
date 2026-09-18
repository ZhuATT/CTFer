"""prompt 单测（批 1 残版）：三段顺序 / 内容来源 / directive 开关。

终态三块（引导/运行提示/简报）= T4.1/P4；本批断言残版契约：
摘要（board.summarize）+ 路由提示（全图 fact 值扫描，S4）+ 人工指示。
v2 已死段不再出现：序言/阶段手册/指令/交接/重复命令告警/后台任务。
"""

from pathlib import Path

from src.board import Blackboard
from src.prompt import _SEGMENT_MARKS, render_round_prompt

_SKILL = Path(__file__).parent / "../../.claude/skills/recon-methodology/SKILL.md"


def _board():
    b = Blackboard()
    b.create_node("fact", {"value": "nginx/1.18.0 反代"}, origin="worker", round=1)
    b.create_node("fact", {"value": "身份由 cticket 派生"}, origin="worker", round=1)
    d = b.create_node("intent", {"goal": "验证 idor", "note": "下一步换 A 重放"},
                      endpoint="/api/o", origin="worker", round=1)
    assert d == "D-001"
    b.record_handoff("已完成侦察首屏")
    return b


def test_three_segments_in_fixed_order():
    p = render_round_prompt(_board(), round_=2)
    pos = [p.find(m + "\n") for m in _SEGMENT_MARKS]
    assert all(x >= 0 for x in pos), pos
    assert pos == sorted(pos)                       # 顺序固定


def test_segment_sources():
    b = _board()
    p = render_round_prompt(b, round_=2)
    # 段1 = 状态摘要（board.summarize：轮次/计数/待接方向/引读 STATE.md）
    assert "第 2 轮" in p and "待接方向" in p and "D-001" in p
    assert "STATE.md" in p
    # 段2 = 路由提示（全图 fact 值扫描——nginx fact 命中 web-advanced 行）
    assert "nginx" in p.split("【提示】")[1].split("【人工指示】")[0]
    # 段3 = 人工指示（无 directive → 占位）
    assert p.rstrip().endswith("（无）")


def test_dead_segments_absent():
    """v3 砍掉的段（A6/A12/A15/A19/A20/A21）不得复活。"""
    p = render_round_prompt(_board(), round_=2)
    for dead in ("【序言】", "【阶段手册】", "【指令】", "【上一轮交接】",
                 "【重复命令告警】", "【后台任务】", "阶段=", "出口判据"):
        assert dead not in p


def test_directive_reaches_segment_three():
    p = render_round_prompt(_board(), directive="重点看支付回调", round_=3)
    assert "重点看支付回调" in p.split("【人工指示】")[1]


def test_handoff_not_in_stdin():
    """A19：Handoff 住 STATE.md，不进 stdin。"""
    p = render_round_prompt(_board(), round_=2)
    assert "已完成侦察首屏" not in p


def test_route_scans_all_fact_values():
    """S4/A13：路由燃料=全图 fact 值扫描（不再按 kind=fingerprint 查）。"""
    b = Blackboard()
    b.create_node("fact", {"value": "识别为 tomcat 容器"}, origin="worker", round=1)
    p = render_round_prompt(b, round_=1)
    assert "injection-sqli" in p                    # 非 fingerprint kind 也命中


def test_wait_for_mcp_teaching_lives_in_skill():
    """P-7 回归：手册①死后，WaitForMcpServers 教学必须迁进 recon-methodology
    skill（T0.3）——丢了它浏览器侦察就废。skill 不在仓库内,缺席即跳过。"""
    if not _SKILL.is_file():
        import pytest
        pytest.skip("recon-methodology skill 不在本机（P0 迁移后生效）")
    txt = _SKILL.read_text(encoding="utf-8")
    assert "WaitForMcpServers" in txt
    assert "30000" in txt
