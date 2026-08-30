"""AT1 stoploss —— 四维止损（P4.3，设计§3.7/§7 默认值）。

四维（§7 默认，全可调）：
  ① 会话上限    max_rounds（默认 6：时间盒阶梯 600/1200/1800 三档×2 循环的合理封顶）
  ② 活跃预算    budget_left_s ≤ 0（driver 每轮递减）
  ③ 无新事实连击 no_new_facts_streak ≥ 3（连续 N 轮 facts_delta == 0）
  ④ 不可达连击  unreachable_streak ≥ 3（连续 N 轮 worker 会话 error 且零收割）

纯判定无副作用：driver 轮末调用 should_stop → (bool, reason)；
触发由 driver 记 stoploss_trigger 事件并走终止 B。
连击计数由本类内部维护（record_round），恢复自动清零。
"""

from __future__ import annotations


class Stoploss:
    def __init__(self, *, max_rounds: int = 6,
                 no_new_facts: int = 3, unreachable: int = 3):
        self.max_rounds = max_rounds
        self.no_new_facts_limit = no_new_facts
        self.unreachable_limit = unreachable
        self.no_new_facts_streak = 0
        self.unreachable_streak = 0

    def record_round(self, *, facts_delta: int, session_ok: bool) -> None:
        """每轮末记账：新事实清零连击；会话异常累计不可达连击。"""
        if facts_delta > 0:
            self.no_new_facts_streak = 0
        else:
            self.no_new_facts_streak += 1
        if session_ok:
            self.unreachable_streak = 0
        else:
            self.unreachable_streak += 1

    def should_stop(self, round_no: int, budget_left_s: float) -> tuple[bool, str]:
        """四维判定（driver 轮末调用）。返回 (停否, 维度+连击数描述)。"""
        if round_no >= self.max_rounds:
            return True, f"会话上限：第 {round_no} 轮 ≥ {self.max_rounds}"
        if budget_left_s <= 0:
            return True, f"预算耗尽：剩余 {budget_left_s:.0f}s"
        if self.no_new_facts_streak >= self.no_new_facts_limit:
            return True, (f"无新事实连击：{self.no_new_facts_streak} 轮"
                          f" ≥ {self.no_new_facts_limit}")
        if self.unreachable_streak >= self.unreachable_limit:
            return True, (f"不可达连击：{self.unreachable_streak} 轮"
                          f" ≥ {self.unreachable_limit}")
        return False, ""
