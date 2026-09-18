"""未测面视图单测（schema §5：出现过的 endpoint − 有 intent/finding 覆盖的 endpoint）。"""

from src.board import Blackboard


def test_untested_basic():
    b = Blackboard()
    b.create_node("fact", {"value": "v1"}, endpoint="/api/a", origin="worker", round=1)
    b.create_node("fact", {"value": "v2"}, endpoint="/api/b", origin="worker", round=1)
    b.create_node("intent", {"goal": "测 search"}, endpoint="/search", origin="worker", round=1)
    assert set(b.untested_surface()) == {"/api/a", "/api/b"}


def test_untested_finding_counts_as_covered():
    b = Blackboard()
    b.create_node("fact", {"value": "v"}, endpoint="/api/c", origin="worker", round=1)
    b.create_node("finding", {"summary": "s"}, endpoint="/api/c", origin="worker", round=2)
    assert b.untested_surface() == []


def test_untested_dismissed_finding_still_covers():
    """dismissed finding 也是"测过"——不回未测面（回阴性视图）。"""
    b = Blackboard()
    b.create_node("fact", {"value": "v"}, endpoint="/api/d", origin="worker", round=1)
    f = b.create_node("finding", {"summary": "s", "reason": "r"}, endpoint="/api/d",
                      origin="worker", round=2)
    b.update_node(f, state="dismissed")
    assert b.untested_surface() == []
    assert any(r["id"] == f for r in b.negative_view())


def test_global_bucket_not_in_surface():
    b = Blackboard()
    b.create_node("fact", {"value": "目标画像：xx"}, origin="worker", round=1)
    assert b.untested_surface() == []


def test_endpoint_normalized_dedupe():
    """同 endpoint 多节点只出现一次。"""
    b = Blackboard()
    b.create_node("fact", {"value": "v1"}, endpoint="/api/e", origin="worker", round=1)
    b.create_node("fact", {"value": "v2"}, endpoint="/api/e", origin="worker", round=2)
    assert b.untested_surface() == ["/api/e"]
