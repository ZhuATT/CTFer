"""AT1 phase 账本 —— .at1/phase.json（批4fix S5：关键簿记即时落盘）。

唯一写者=当前 run 进程（run.lock 保证独占——文件本身无需锁）。每个阶段转换
即时落盘：session_start→working、观察者 spawn→auditing、轮末入图完成→working
（下轮）、stop 退出路径→补一次。进程启动读到残留=上次中断于何处（S12 的
接力触发条件）——中断可诊断，不再靠猜。

账本归属（09-21 讨论定稿）：M5 大进程收编后写它的手和写点纪律原样平移，
账本从"状态唯一载体"降级为"大进程的崩溃恢复日志"——大进程也是进程也会死，
"从哪接着来"的记忆只有账本承载。不换 SQLite：单任务下 JSON 人眼可读依旧最优。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

VALID_PHASES = ("working", "auditing")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def path(root) -> Path:
    return Path(root) / ".at1" / "phase.json"


def write(root, phase: str, round_: int, **extra) -> None:
    """阶段转换即时落盘。extra=S12 的 session_id/role 等扩展字段。
    写失败不阻塞主流程（盘面真相另有 blackboard/facts 承载，账本只是恢复日志）。"""
    try:
        p = path(root)
        p.parent.mkdir(parents=True, exist_ok=True)
        doc = {"phase": phase, "round": round_,
               "updated_at": _now_iso(), **extra}
        p.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def read(root) -> dict | None:
    """读账本。无文件/坏 JSON→None。"""
    try:
        doc = json.loads(path(root).read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def clear(root) -> None:
    """干净收尾时清账——残留=未干净收尾（stop/崩溃/断电），是 S12 接力的触发条件。
    写失败不阻塞（残留的代价只是下次 run 多一次 interrupted_phase 记账）。"""
    try:
        path(root).unlink(missing_ok=True)
    except OSError:
        pass
