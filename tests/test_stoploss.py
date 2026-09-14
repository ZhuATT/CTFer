"""stoploss 单测（P4.3）：四维触发边界 + 连击恢复。"""

from src.stoploss import Stoploss


def test_all_clear_by_default():
    sl = Stoploss()
    assert sl.should_stop(1, 3600.0) == (False, "")


def test_round_cap():
    sl = Stoploss(max_rounds=3)
    ok, why = sl.should_stop(3, 9999.0)
    assert ok and "会话上限" in why


def test_budget_exhausted():
    sl = Stoploss()
    ok, why = sl.should_stop(1, 0.0)
    assert ok and "预算" in why
    ok2, _ = sl.should_stop(1, -5.0)
    assert ok2


def test_no_new_facts_streak_and_recovery():
    sl = Stoploss(no_new_facts=3)
    sl.record_round(facts_delta=0, session_ok=True)   # 1
    sl.record_round(facts_delta=0, session_ok=True)   # 2
    ok, why = sl.should_stop(3, 3600.0)
    assert not ok                                    # 连击 2 < 3
    sl.record_round(facts_delta=0, session_ok=True)   # 3
    ok, why = sl.should_stop(4, 3600.0)
    assert ok and "无新事实连击" in why
    # 恢复：新事实清零连击
    sl2 = Stoploss(no_new_facts=3)
    sl2.record_round(facts_delta=0, session_ok=True)
    sl2.record_round(facts_delta=5, session_ok=True)  # 清零
    sl2.record_round(facts_delta=0, session_ok=True)  # 又 1
    ok, _ = sl2.should_stop(4, 3600.0)
    assert not ok


def test_unreachable_streak():
    sl = Stoploss(unreachable=3)
    for _ in range(2):
        sl.record_round(facts_delta=10, session_ok=False)   # 有事实但会话 error
    ok, _ = sl.should_stop(3, 3600.0)
    assert not ok
    sl.record_round(facts_delta=0, session_ok=False)        # 第 3 次
    ok, why = sl.should_stop(4, 3600.0)
    assert ok and "不可达连击" in why
    # 恢复（facts_delta>0 防误触无新事实连击——那是另一维）
    sl2 = Stoploss(unreachable=3)
    sl2.record_round(facts_delta=1, session_ok=False)
    sl2.record_round(facts_delta=1, session_ok=True)
    sl2.record_round(facts_delta=1, session_ok=False)
    ok, _ = sl2.should_stop(4, 3600.0)
    assert not ok


def test_round_cap_dominates_order():
    # 四维同时满足时返回第一个命中的维度（顺序即优先级）
    sl = Stoploss(max_rounds=2)
    sl.record_round(facts_delta=0, session_ok=False)
    sl.record_round(facts_delta=0, session_ok=False)
    ok, why = sl.should_stop(2, 0.0)
    assert ok and "会话上限" in why


def test_round_cap_unlimited_by_default():
    """2026-09-04 拍板：轮上限默认不限——预算是主约束，轮数不封顶。"""
    sl = Stoploss()                                   # max_rounds=None
    ok, why = sl.should_stop(50, 3600.0)              # 第 50 轮、预算充足 → 不停
    assert not ok
    # 预算耗尽仍在轮数很大时生效
    ok2, why2 = sl.should_stop(50, 0.0)
    assert ok2 and "预算" in why2
