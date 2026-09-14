"""prompt 单测：9 段顺序 / 内容来源 / directive 开关。"""

from src.board import Blackboard
from src.prompt import _SEGMENT_MARKS, render_round_prompt


def _board():
    b = Blackboard()
    b.add_fact("endpoint", "/api/x")
    b.add_fact("fingerprint", "nginx/1.18.0")
    b.observe("Bash", {"command": "curl -s https://t/a"}, "GET https://t/a 200", round_=1)
    b.observe("Bash", {"command": "curl -s https://t/a"}, "x", round_=1)
    b.observe("Bash", {"command": "curl -s https://t/a"}, "x", round_=1)
    b.record_handoff("已完成侦察首屏；未竟：POST 类接口", "model")
    return b


def test_nine_segments_in_fixed_order():
    p = render_round_prompt(_board(), round_=2)
    # 段头 = 标记+换行（正文里提到标记词不算——手册 v2 曾撞过）
    pos = [p.find(m + "\n") for m in _SEGMENT_MARKS]
    assert all(x >= 0 for x in pos), pos
    assert pos == sorted(pos)                       # 顺序固定


def test_segment_sources():
    b = _board()
    p = render_round_prompt(b, round_=2)
    # 段2 = 当前阶段手册（recon）
    assert "侦察拓面" in p.split("【指令】")[0]
    # 段3 = plan_directive（阶段/出口/轮次）
    assert "阶段=recon" in p and "第 2 轮" in p
    # 段4 = 状态摘要（DEC-9/E：紧凑摘要 + 引导读 STATE.md；事实全量不在 prompt）
    assert "untrusted_data" in p and "状态摘要" in p
    assert "STATE.md" in p
    assert "未测面 1 个（目标：清零）" in p
    # 段5 = 上一轮交接
    assert "已完成侦察首屏" in p
    # 段6 = tried≥3 告警
    assert "已 ×3" in p and "勿重跑" in p
    # 段8 = 指纹提示
    assert "nginx" in p.split("【提示】")[1].split("【人工指示】")[0]
    # 段9 无 directive
    assert p.rstrip().endswith("（无）")


def test_directive_reaches_segment_nine():
    p = render_round_prompt(_board(), directive="重点看支付回调", round_=3)
    assert "重点看支付回调" in p.split("【人工指示】")[1]


def test_stage_switches_manual():
    b = _board()
    b.goal["stage"] = "identity"
    p = render_round_prompt(b)
    assert "身份模型" in p and "侦察拓面" not in p


def test_first_round_no_handoff():
    b = Blackboard()
    p = render_round_prompt(b)
    assert "（首轮，无上一轮交接）" in p


def test_recon_manual_waits_for_mcp():
    """P-7 回归（2026-09-14 实测根因）：-p 模式 MCP 异步启动，模型不调
    WaitForMcpServers 就永远见不到 browser_* 工具——手册必须教这一步。"""
    from src.board import Blackboard
    p = render_round_prompt(Blackboard(), round_=1)
    assert "WaitForMcpServers" in p                 # 等待指令在侦察手册
    assert "30000" in p                             # timeout 给够
    assert "curl 起步" in p                         # 失败降级路径明确
