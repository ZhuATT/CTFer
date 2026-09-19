"""AT1 prompt —— 每轮 stdin 三块终态（汇编 §二；批3fix 修订）。

【引导】来源=**STATE.md 的"## 下轮建议"固定节**（观察者写，driver 机械抽取后传入；
块缺席=无事）——**是建议不是命令**（worker 手册 §1 同款教学）。
【运行提示】人工指示独占（hints 队列聚合/CONTROL directive；空则整块消失，N3-2）。
【简报】轮次/预算/时间盒/身份 + 写盘指路——常驻。

已死段不再出现：序言(A6)/阶段手册(A12)/指令(A15)/状态摘要(A16)/交接(A19)/
重复命令告警(A20)/后台任务块(A21)/路由提示(09-19 裁)。
批3fix 退役：bookkeeping.guide（set_guide 操作已裁，引导改由 STATE.md 承载）。
"""

from __future__ import annotations

from typing import Optional

_SEGMENT_MARKS = ("【引导】", "【运行提示】", "【简报】")
_GUIDE_ANCHOR = "## 下轮建议"


def extract_guide(state_md_text: str) -> str:
    """从 STATE.md 抽"## 下轮建议"节正文（到下一个 ## 或文末）。
    纯函数（可单测）：无锚点/空节 → 空串（引导块整块消失）。"""
    if not state_md_text or _GUIDE_ANCHOR not in state_md_text:
        return ""
    out: list[str] = []
    inside = False
    for ln in state_md_text.splitlines():
        s = ln.strip()
        if s.startswith("##"):
            inside = s == _GUIDE_ANCHOR
            continue
        if inside:
            out.append(ln.rstrip())
    return "\n".join(out).strip()[:2000]


def render_round_prompt(board, directive: Optional[str] = None, *,
                        guide: str = "", round_: int = 0, brief: str = "") -> str:
    """stdin 三块装配。guide/directive 缺席各自整块消失；简报常驻。
    guide=观察者 STATE.md 抽取物（driver 传入）；brief 正文由 driver 组装。
    确定性：同输入两次调用逐字节相同。"""
    segs: list[str] = []
    if (guide or "").strip():
        segs.append(f"【引导】\n{guide.strip()}")
    if directive:
        segs.append(f"【运行提示】\n{directive}")
    tail = "写盘面 facts//findings//evidence/（一条一文件，格式自由）；判层与纪律见 CLAUDE.md。"
    segs.append(f"【简报】\n{(brief or f'第 {round_} 轮').strip()}\n{tail}")
    return "\n\n".join(segs)
