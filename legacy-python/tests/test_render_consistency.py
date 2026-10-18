"""render 一致性单测（批3fix）：STATE 兜底投影（R6——观察者产物为主，兜底极简计数）。"""

from src.board import Blackboard
from src.driver import _render_state_minimal


def test_minimal_state_counts_and_pending_directions():
    bb = Blackboard()
    d = bb.create_node("intent", {"goal": "idor 验证", "note": "差一步"},
                       endpoint="/api/o", origin="observer", round=1)
    bb.create_node("finding", {"summary": "越权读取"}, endpoint="/api/o",
                   origin="observer", round=1)
    bb.create_node("fact", {"value": "目标画像：JVM 厂站"}, origin="worker", round=1)
    md = _render_state_minimal(bb)
    assert md.startswith("# STATE｜")
    assert "发现 确认1" in md
    assert f"[{d}]" in md and "idor 验证" in md                # 待接方向带 id
    assert ".at1/blackboard.json" in md                        # 指路：全文读图本体


def test_minimal_state_deterministic_and_slim():
    bb = Blackboard()
    for i in range(5):
        bb.create_node("fact", {"value": f"事实{i}"}, origin="worker", round=1)
    s1, s2 = _render_state_minimal(bb), _render_state_minimal(bb)
    assert s1 == s2                                            # 确定性
    assert len(s1.splitlines()) <= 8                           # 极简：无逐条正文
