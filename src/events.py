"""AT1 events —— 控制器事件流（只追加 JSONL，工作台/回放的唯一消费源）。

设计§4.1：每行 {"ts","type","round","data"}；secret 字段脱敏后入日志。
与 state/log.jsonl（worker 手写的测试记录）分工：本文件是"控制器判了什么"。
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

# 设计§4.1 事件类型全集（新增类型须先登记在这里，emit 会校验）
EVENT_TYPES = frozenset({
    "run_start", "run_end",
    "session_start", "session_end",
    "heartbeat",
    "fact_added", "immune_added",
    "phase_enter",
    "claim_submitted", "claim_verdict",
    "gate_pass", "gate_fail",
    "stoploss_trigger",
    "handoff_harvested",
    "finding_confirmed",
    "goal_eval_start", "goal_eval_end",
    "surface_parse_fail",
})

# 脱敏键名匹配：cookie/token/secret/authorization/credential/password/api_key。
# 刻意不含裸 "session"——session_id 是本地会话标识不是凭据，DoD 要求它可见。
_REDACT_KEY_RX = re.compile(
    r"cookie|token|secret|authorization|credential|password|api[_-]?key",
    re.IGNORECASE,
)
_REDACTED = "***"


def redact(obj: Any) -> Any:
    """递归脱敏：键名命中正则的值替换为 ***。"""
    if isinstance(obj, dict):
        return {
            k: (_REDACTED if _REDACT_KEY_RX.search(str(k)) else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventWriter:
    """只追加的 JSONL 事件写入器。每行写后 flush——kill 后磁盘留有已写部分。"""

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # append 模式：断点续跑/多次 run 共用同一份日志
        self._f = open(path, "a", encoding="utf-8")

    def emit(self, type_: str, data: dict | None = None, round_: int | None = None) -> None:
        if type_ not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {type_!r}（先登记进 EVENT_TYPES）")
        row = {
            "ts": _now_iso(),
            "type": type_,
            "round": round_,
            "data": redact(data or {}),
        }
        self._f.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self) -> None:
        self._f.close()
