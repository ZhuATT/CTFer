"""AT1 prompt —— 每轮 stdin 三块终态（汇编 §二；T4.1/T4.3 定稿）。

【引导】观察者 guide 原文（bookkeeping.guide，批 2 收割落簿记；块缺席=无事）——
**是建议不是命令**（worker 手册 §1 同款教学）。
【运行提示】人工指示独占（hints 队列聚合/CONTROL directive；空则整块消失，N3-2）。
【简报】轮次/预算/时间盒/身份 + 判层指路——常驻。

已死段不再出现：序言(A6)/阶段手册(A12)/指令(A15)/状态摘要(A16)/交接(A19)/
重复命令告警(A20)/后台任务块(A21)/路由提示(09-19 裁：A7 原生发现，关键词表取消)。
防注入唯一战线=STATE.md（A19/A20）。
"""

from __future__ import annotations

from typing import Optional

_SEGMENT_MARKS = ("【引导】", "【运行提示】", "【简报】")


def render_round_prompt(board, directive: Optional[str] = None, *,
                        round_: int = 0, brief: str = "") -> str:
    """stdin 三块装配。guide/directive 缺席各自整块消失；简报常驻。
    brief 正文由 driver 组装（预算/时间盒/身份是运行期数据），本函数只加块壳
    与判层指路。确定性：同输入两次调用逐字节相同。"""
    segs: list[str] = []
    guide = (board.bookkeeping.get("guide") or {}).get("text", "").strip()
    if guide:
        segs.append(f"【引导】\n{guide}")
    if directive:
        segs.append(f"【运行提示】\n{directive}")
    tail = "判层规则见 CLAUDE.md §2，输出格式见 FORMATS.md——写盘前必读。"
    segs.append(f"【简报】\n{(brief or f'第 {round_} 轮').strip()}\n{tail}")
    return "\n\n".join(segs)
