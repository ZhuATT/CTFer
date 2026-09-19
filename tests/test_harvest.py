"""harvest 单测：diff 幂等 + 配方 1 代写（账本行→节点/声明照抄/endpoint 兜底）。"""

from src.board import Blackboard
from src.harvest import (auto_link, diff_new_lines, facts_to_nodes,
                         finding_to_node)


def test_diff_idempotent_and_incremental(tmp_path):
    p = tmp_path / "FINDINGS"
    p.write_text('{"a":1}\n{"a":2}\n', encoding="utf-8")
    lines1, off1 = diff_new_lines(str(p), 0)
    assert lines1 == ['{"a":1}', '{"a":2}']
    # 同 offset 重读：结果一致（幂等）
    lines_again, off_again = diff_new_lines(str(p), off1)
    assert lines_again == [] and off_again == off1
    # 追加后只读新增
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"a":3}\n{"a":4}')          # 最后一个是半行（无换行）
    lines2, off2 = diff_new_lines(str(p), off1)
    assert lines2 == ['{"a":3}']
    assert off2 > off1
    # 半行等换行到了再消费
    with open(p, "a", encoding="utf-8") as f:
        f.write("\n")
    lines3, _ = diff_new_lines(str(p), off2)
    assert lines3 == ['{"a":4}']


def test_diff_missing_file():
    assert diff_new_lines("Z:/nope/F", 0) == ([], 0)


def test_facts_to_nodes_basic_and_tolerant():
    """FACTS 行 → fact 节点（配方 1）：BOM/坏行宽容；fact_kind 字段丢弃；计数只算新建。"""
    b = Blackboard()
    lines = [
        '﻿{"value":"身份由 cticket 派生","evidence":"ev1","kind":"identity_model"}',  # BOM + v2 kind 丢弃
        "垃圾行",
        '{"value":"目标无 WAF","endpoint":"/api/x"}',
        '{"value":"目标无 WAF","endpoint":"/api/x"}',          # 重复 → 去重不计数
        '{"evidence":"没值"}',
    ]
    n = facts_to_nodes(b, lines, round_=3)
    assert n == 2
    vals = sorted(b.fact_values())
    assert vals == ["目标无 WAF", "身份由 cticket 派生"]
    assert b.nodes("fact")[0]["payload"].get("kind") is None   # fact_kind 不入 v3


def test_finding_to_node_and_chain_declaration():
    """FINDINGS 行 → finding 节点：report 指针透传；worker chain 声明照抄成边。"""
    b = Blackboard()
    d = b.create_node("intent", {"goal": "打 registry"}, endpoint="h:5000",
                      origin="worker", round=1)
    row = {"id": "F-001", "endpoint": "h:5000/v2/_catalog", "evidence": "evidence/r.md",
           "summary": "匿名枚举", "report": "reports/F-001.md",
           "chain": {"rel": "derived_from", "refs": ["D-001"], "note": "由方向派生"}}
    nid = finding_to_node(b, row, round_=2)
    assert nid == "F-001"
    node = b.node(nid)
    assert node["state"] == "proposed"
    assert node["payload"]["report"] == "reports/F-001.md"
    edges = b.edges(src=nid)
    assert len(edges) == 1 and edges[0]["rel"] == "derived_from" and edges[0]["dst"] == d
    assert edges[0]["origin"] == "worker"                       # 声明优先


def test_auto_link_endpoint_fallback_only_when_undeclared():
    """兜底只在无人声明时（不变量 4）：有声明边的节点不补线。"""
    b = Blackboard()
    d = b.create_node("intent", {"goal": "9098 面"}, endpoint="h:9098",
                      origin="worker", round=1)
    # 无声明 fact → 兜底 sources
    t = b.create_node("fact", {"value": "Shiro 站点"}, endpoint="h:9098/api",
                      origin="worker", round=2)
    assert auto_link(b, t, round_=2) == 1
    assert b.edges(src=t)[0]["rel"] == "sources" and b.edges(src=t)[0]["dst"] == d
    # 有声明 finding → 不补
    f = b.create_node("finding", {"summary": "未授权"}, endpoint="h:9098/admin",
                      origin="worker", round=2)
    b.add_edge(d, "yields", f, origin="worker", round=2)
    assert auto_link(b, f, round_=2) == 0
    assert len(b.edges(dst=f)) == 1                             # 只有声明边
    # done 方向不接兜底
    b.update_node(d, state="done")
    t2 = b.create_node("fact", {"value": "新线索"}, endpoint="h:9098/x",
                       origin="worker", round=3)
    assert auto_link(b, t2, round_=3) == 0


def test_synthesize_handoff_gone():
    """A19：合成交接机制死——模块不再提供 synthesize_handoff。"""
    import src.harvest as h
    assert not hasattr(h, "synthesize_handoff")


def test_chain_three_verbs_directions():
    """FORMATS 三动词方向（schema §4.1）：derived_from 本条→ref；sources 本条(F/T)→D；
    yields D→本条（翻边）；same_root 判重归观察者——worker 声明不受理。"""
    bb = Blackboard()
    d = bb.create_node("intent", {"goal": "打 registry"}, endpoint="h:5000",
                       origin="worker", round=1)
    row1 = {"id": "F-001", "endpoint": "h:5000/v2", "evidence": "e1.md", "summary": "匿名枚举",
            "chain": {"rel": "sources", "refs": ["D-001"], "note": "线索支撑方向"}}
    nid1 = finding_to_node(bb, row1, round_=2)
    e1 = bb.edges(src=nid1, rel="sources")
    assert e1 and e1[0]["dst"] == "D-001" and e1[0]["origin"] == "worker"
    row2 = {"id": "F-002", "endpoint": "h:5000/v2/x", "evidence": "e2.md", "summary": "拉取镜像",
            "chain": {"rel": "yields", "refs": ["D-001"]}}
    nid2 = finding_to_node(bb, row2, round_=3)
    e2 = bb.edges(rel="yields", dst=nid2)
    assert e2 and e2[0]["src"] == "D-001"                # yields 翻边：D→F
    row3 = {"id": "F-003", "endpoint": "h:5000/v2/y", "evidence": "e3.md", "summary": "同根因",
            "chain": {"rel": "same_root", "refs": ["F-001"]}}
    nid3 = finding_to_node(bb, row3, round_=3)
    assert not bb.edges(src=nid3, rel="same_root") and not bb.edges(dst=nid3, rel="same_root")
    assert bb.node(nid3)["state"] == "proposed"      # 声明不受理；auto_link 兜底边另行存在是合法的
