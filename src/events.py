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
    "phase_enter", "phase_check",
    "claim_submitted", "claim_verdict",
    "gate_pass", "gate_fail",
    "stoploss_trigger",
    "handoff_harvested",
    "finding_confirmed",
    "goal_eval_start", "goal_eval_end",
    # M4 新增（driver）
    "guard_violation",        # guard 实时检测命中（kind: scope/controller_zone/self_destruct）
    "directive_injected",     # CONTROL directive 已注入下一轮 prompt
    "observer_error",         # 观察者 LLM 故障（降级 uncertain，不阻塞收割）
    # phase5 新增（schema v2.1 方向层/观察者 v2）
    "directions_merged",      # DIRECTIONS 轮末收割合并（changed 行数）
    "directions_from_handoff",  # 旧格式 Handoff 未竟段提取为方向（added 条数）
    "preflight",              # 启动预检结果（claude/mcp 可用性，2026-09-14）
    "observer_governance",    # 观察者治理消费（comments/new_directions/retests/chains 计数）
    "facts_verified",         # 被动事实轮窗复现抽验（checked/downgraded/restored，治理批#2）
    # 批 2 新增（v3 配方 2/判停三角/A24 控制面）
    "worker_stop",            # worker <Stop> 有效终判（kind: achieved/exhausted + refs）
    "stop_invalid",           # <Stop> 无效（无引证/引证不存在）——继续下一轮
    "resume",                 # 续跑（启动时黑板非空，offsets 续收）
    "hard_rejected",          # noreport 检察官硬拒（节点建即 dismissed，T2.6）
    "hint_injected",          # 留言队列收割注入【人工指示】（T2.8/A24）
    "guide_injected",         # 【引导】块注入（来源=STATE.md“## 下轮建议”节抽取，批3fix）
    "observer_parse_fail",    # OBSERVER 非法行进隔离区（schema §7）
    "board_legacy_archived",  # v2 旧板归档改名（已裁 09-18：不做内容迁移）
    "observer_applied",       # 执行器入图计数（五操作各条数+dedup_existing）
    "observer_session_end",   # 观察者 -p 会话结束（计量：tokens/cost/turns）
    "observer_empty_retry",   # 空产出防线：判断书缺失/坏/空 → 重试一次（stage: retry/exhausted）
    "state_fallback",         # 观察者未写 STATE.md → controller 兜底极简计数（R6）
    "scope_missing",          # engagement 无授权清单——guard 目标拦截停用（禁区/自毁保留）
})

# 脱敏键名匹配：cookie/token/secret/authorization/credential/password/api_key。
# 刻意不含裸 "session"——session_id 是本地会话标识不是凭据，DoD 要求它可见。
# "token" 用负向前瞻排除 tokens/thinking_tokens_est——用量字段不是凭据
# （实测：session_end 的 tokens 被打成 ***，watch 输出失去用量可观测性）。
_REDACT_KEY_RX = re.compile(
    r"cookie|token(?!s)|secret|authorization|credential|password|api[_-]?key",
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
