"""prompt 单测（v3 三块终态）：恰三块 / guide 注入 / 空块消失 / 判层指路。

【引导】观察者 guide 原文注入（批 2 收割落簿记）；【运行提示】人工指示独占
（空则整块消失，N3-2）；【简报】常驻（元信息+判层指路，去"发现即提交"旧教义）。
"""

from pathlib import Path

from src.board import Blackboard
from src.prompt import _SEGMENT_MARKS, extract_guide, render_round_prompt

_SKILL = Path(__file__).parent / "../../.claude/skills/recon-methodology/SKILL.md"


def _board() -> Blackboard:
    b = Blackboard()
    b.create_node("intent", {"goal": "验证 idor", "note": "下一步换 A 重放"},
                  endpoint="/api/o", origin="worker", round=1, id="D-001")
    return b


def test_three_blocks_when_guide_present():
    p = render_round_prompt(_board(), guide="主攻 idor；备选注入",
                            directive="优先复查登录口令", round_=2)
    pos = [p.find(m + "\n") for m in _SEGMENT_MARKS]
    assert all(x >= 0 for x in pos), pos
    assert pos == sorted(pos)                        # 顺序固定：引导→运行提示→简报
    assert "主攻 idor" in p.split("【引导】")[1].split("【运行提示】")[0]
    assert "优先复查登录口令" in p.split("【运行提示】")[1].split("【简报】")[0]


def test_guide_block_absent_when_no_guide():
    """无 guide（图空冷启动/观察者未产出）→ 引导块整块消失。"""
    p = render_round_prompt(Blackboard(), round_=1)
    assert "【引导】" not in p
    assert "【简报】" in p


# ── 引导来源（批3fix）：STATE.md 的"## 下轮建议"节抽取 ──────────────────

def test_extract_guide_from_state_md():
    md = ("# STATE｜节点3\n\n## 任务概要\n- 目标：x\n\n"
          "## 下轮建议\n- 主攻 authc 面（roles 无归属校验）\n- 备选：邮件票据链\n"
          "- 自由探索照常\n\n## 发现\n- [F-001] 越权\n")
    g = extract_guide(md)
    assert "主攻 authc 面" in g and "备选：邮件票据链" in g
    assert "任务概要" not in g and "发现" not in g       # 只取该节，不吃邻节
    assert extract_guide("") == ""
    assert extract_guide("# STATE\n\n## 发现\n- x\n") == ""   # 无锚点 → 空


def test_extract_guide_stops_at_next_section():
    md = "## 下轮建议\n- A\n\n## 其他\n- B\n"
    assert extract_guide(md) == "- A"


def test_directive_block_absent_when_empty():
    """N3-2：运行提示=人工指示独占，无指示整块消失。"""
    p = render_round_prompt(Blackboard(), round_=1)
    assert "【运行提示】" not in p
    p2 = render_round_prompt(Blackboard(), directive="重点看支付回调", round_=1)
    assert "重点看支付回调" in p2.split("【运行提示】")[1]


def test_brief_meta_and_layer_pointer():
    """简报=元信息+写盘指路（批3fix：FORMATS 退役，指路改文件夹化写盘面）。"""
    b = Blackboard()
    b.bookkeeping["hint"] = "证书自签记得 -k"         # hint 渲染在手册，不进 stdin
    p = render_round_prompt(b, round_=2, brief="目标 https://x.com。剩余预算 100s，时间盒 60s。")
    assert "目标 https://x.com" in p and "100s" in p
    assert "facts//findings//evidence/" in p and "CLAUDE.md" in p
    assert "FORMATS.md" not in p
    assert "发现即提交" not in p
    assert "证书自签" not in p                        # 手册槽内容不重复进 stdin


def test_no_dead_segments():
    """已死段/死机制不得复活（A6/A12/A15/A16/A19/A20/A21/09-19 路由取消）。"""
    p = render_round_prompt(_board(), round_=2)
    for dead in ("【序言】", "【阶段手册】", "【指令】", "【状态摘要】", "【上一轮交接】",
                 "【重复命令告警】", "【后台任务】", "【提示】", "阶段=", "出口判据",
                 "加载 injection-sqli skill", "injection-deser"):
        assert dead not in p


def test_deterministic():
    b = _board()
    assert (render_round_prompt(b, guide="主攻 X", round_=2)
            == render_round_prompt(b, guide="主攻 X", round_=2))
    assert (render_round_prompt(b, round_=2)
            == render_round_prompt(b, round_=2))


def test_wait_for_mcp_teaching_lives_in_skill():
    """P-7 回归：手册死后 WaitForMcpServers 教学必须迁进 recon-methodology
    skill（T0.3）。skill 不在仓库内，缺席即跳过。"""
    if not _SKILL.is_file():
        import pytest
        pytest.skip("recon-methodology skill 不在本机（P0 迁移后生效）")
    txt = _SKILL.read_text(encoding="utf-8")
    assert "WaitForMcpServers" in txt
    assert "30000" in txt
