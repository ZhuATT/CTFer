"""AT1 harvest —— 轮末收割：FINDINGS/FACTS 增量 diff + Handoff 代码合成兜底。

设计§3.6 ④：会话结束后 driver 用 diff_new_lines 取新增行（offset 记在黑板），
被杀会话没有模型版 <Handoff> 时用 synthesize_handoff 拼降级交接（origin=synthesized）。
"""

from __future__ import annotations

import os
from typing import Optional


def diff_new_lines(path: str, offset: int = 0) -> tuple[list[str], int]:
    """从字节 offset 起读新增的完整行（不完整行留给下次）。返回 (行列表, 新 offset)。

    幂等：两次调用同一 offset 结果一致；文件不存在 → ([], offset)。
    """
    if not os.path.isfile(path):
        return [], offset
    size = os.path.getsize(path)
    if size <= offset:
        return [], offset
    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read()
    # 只消费到最后一个换行——半行（写入中）留给下一次
    last_nl = raw.rfind(b"\n")
    if last_nl < 0:
        return [], offset
    consumed = raw[:last_nl + 1]
    text = consumed.decode("utf-8", errors="replace")
    lines = [l.rstrip("\r") for l in text.split("\n")]     # Windows CRLF
    lines = [l for l in lines if l.strip()]
    return lines, offset + last_nl + 1


def synthesize_handoff(board, tool_events_tail: Optional[list] = None) -> str:
    """被杀会话的代码合成交接（降级品：只有磁盘状态能告诉下一轮的东西）。

    素材：最近事实（按 ts 尾部）+ tried 高频命令 + 未完成后台任务。
    不含任何"我本想干什么"——那是模型版 Handoff 独有的，合成版诚实承认没有。
    """
    parts: list[str] = ["【代码合成交接——会话未正常结束，以下由控制器从磁盘状态拼出】"]

    recent = board.query()[-6:] if board.query() else []
    if recent:
        parts.append("最近入库事实：\n" + "\n".join(
            f"- [{f['kind']}] {f['value'][:100]}" for f in recent))
    else:
        parts.append("黑板无新事实（会话可能死在起步阶段）。")

    tried = sorted(board.ledger.get("tried", {}).items(), key=lambda x: -x[1])[:5]
    if tried:
        parts.append("高频命令（≥2 次的可能已有结论，勿盲目重跑）：\n" + "\n".join(
            f"- {cmd[:100]}（×{n}）" for cmd, n in tried if n >= 2))

    pending = [b for b in board.ledger.get("background", []) if b.get("status") != "done"]
    if pending:
        parts.append("未完成后台任务（开工先检查）：\n" + "\n".join(
            f"- #{b.get('id')} {b.get('desc', '')}" for b in pending))

    if tool_events_tail:
        # 尾部调用带输出摘录——被杀前最后看到的观测是下一轮最需要的东西
        #（实测教训：只记命令不记输出，marker 这类活在下落里的信息就接不上力）
        parts.append("会话尾部工具调用（最后 3 次，含输出摘录）：\n" + "\n".join(
            f"- {t.tool} {str(t.args.get('command') or t.args)[:60]} → {t.output[:160]}"
            for t in tool_events_tail[-3:]))

    parts.append("注意：本交接不含原会话意图——发现与上述状态冲突时以磁盘为准，谨慎重做。")
    return "\n\n".join(parts)
