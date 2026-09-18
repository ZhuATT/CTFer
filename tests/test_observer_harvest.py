"""配方 2 单测:OBSERVER 七类行 → 图(schema §7/§6.2)。"""

import json

from src.board import Blackboard
from src.observer_harvest import apply_observer_lines


def _mk_graph() -> Blackboard:
    bb = Blackboard()
    bb.create_node("intent", {"goal": "打 registry"}, endpoint="h:5000",
                   origin="worker", round=1, id="D-001")
    bb.create_node("finding", {"summary": "未授权枚举"},
                   endpoint="h:5000/v2/_catalog", origin="worker", round=2, id="F-001")
    bb.create_node("finding", {"summary": "匿名拉取"},
                   endpoint="h:5000/v2", origin="worker", round=2, id="F-002")
    return bb


def _lines(*objs) -> list[str]:
    return [json.dumps(o, ensure_ascii=False) for o in objs]


def test_verdict_confirms_and_dismisses():
    bb = _mk_graph()
    r = apply_observer_lines(bb, _lines(
        {"t": "verdict", "id": "F-001", "state": "confirmed", "severity": "high", "reason": "成立"},
        {"t": "verdict", "id": "F-002", "state": "dismissed", "reason": "并入 F-001"}), round=3)
    assert bb.node("F-001")["state"] == "confirmed"
    assert bb.node("F-001")["payload"]["severity"] == "high"
    assert bb.node("F-002")["state"] == "dismissed"
    assert r["counts"]["verdict"] == 2


def test_verdict_skip_hard_rejected_and_no_flip():
    """硬拒 id 不受理(T2.6 前置);confirmed 不可翻案(不变量 3)。"""
    bb = _mk_graph()
    bb.update_node("F-001", state="confirmed")
    r = apply_observer_lines(bb, _lines(
        {"t": "verdict", "id": "F-002", "state": "confirmed", "reason": "x"},
        {"t": "verdict", "id": "F-001", "state": "dismissed", "reason": "翻案尝试"}), round=3,
        rejected_ids={"F-002"})
    assert r["counts"]["verdict_skip_rejected"] == 1
    assert bb.node("F-002")["state"] == "proposed"          # 不受理=不动
    assert bb.node("F-001")["state"] == "confirmed"
    assert r["counts"]["verdict_illegal"] == 1


def test_verdict_bad_state_rejected():
    bb = _mk_graph()
    r = apply_observer_lines(bb, _lines(
        {"t": "verdict", "id": "F-001", "state": "killed", "reason": "r"}), round=3)
    assert len(r["rejects"]) == 1                           # 非法 state=结构非法进隔离区
    assert bb.node("F-001")["state"] == "proposed"


def test_same_root_primary_at_src_flips_edge():
    """primary=src → 翻转:边=非正主→正主(schema §4.1);非正主机械 dismissed。"""
    bb = _mk_graph()
    apply_observer_lines(bb, _lines(
        {"t": "edge", "rel": "same_root", "src": "F-002", "dst": "F-001",
         "primary": "F-002", "note": "正主是拉取"}), round=3)
    e = bb.edges(rel="same_root")[0]
    assert (e["src"], e["dst"]) == ("F-001", "F-002")
    assert bb.node("F-001")["state"] == "dismissed"
    assert "F-002" in bb.node("F-001")["payload"]["reason"]
    assert bb.node("F-002")["state"] == "proposed"          # 正主不受影响


def test_same_root_primary_missing_falls_back_confirmed_first():
    """primary 缺失 → 先到优先:confirmed 最早者为正主(schema §7)。"""
    bb = _mk_graph()
    bb.update_node("F-001", state="confirmed")
    apply_observer_lines(bb, _lines(
        {"t": "edge", "rel": "same_root", "src": "F-001", "dst": "F-002"}), round=3)
    e = bb.edges(rel="same_root")[0]
    assert (e["src"], e["dst"]) == ("F-002", "F-001")       # 正主=F-001 → 翻转
    assert bb.node("F-002")["state"] == "dismissed"
    assert bb.node("F-001")["state"] == "confirmed"


def test_same_root_primary_conflict_keeps_confirmed_with_warning():
    """非正主已 confirmed → 保持不翻案(不变量 3),只记警告。"""
    bb = _mk_graph()
    bb.update_node("F-001", state="confirmed")
    r = apply_observer_lines(bb, _lines(
        {"t": "edge", "rel": "same_root", "src": "F-001", "dst": "F-002",
         "primary": "F-002"}), round=3)
    assert bb.node("F-001")["state"] == "confirmed"         # 不变量 3 拒绝
    assert any("不翻案" in w for w in r["counts"]["warnings"])


def test_supersedes_migrates_only_confirmed():
    bb = _mk_graph()
    t_old = bb.create_node("fact", {"value": "旧情报:1200 Eureka 开放"}, origin="user", round=0)
    bb.update_node(t_old, state="confirmed")
    t_new = bb.create_node("fact", {"value": "实测:1200 已关闭"}, origin="worker", round=3)
    bb.update_node(t_new, state="confirmed")
    apply_observer_lines(bb, _lines(
        {"t": "edge", "rel": "supersedes", "src": t_new, "dst": t_old,
         "note": "9月实测取代4月情报"}), round=3)
    assert bb.node(t_old)["state"] == "superseded"
    # proposed fact 不可被取代(不变量:仅 confirmed→superseded)
    t_p = bb.create_node("fact", {"value": "未确认线索"}, origin="worker", round=3)
    r = apply_observer_lines(bb, _lines(
        {"t": "edge", "rel": "supersedes", "src": t_new, "dst": t_p}), round=4)
    assert bb.node(t_p)["state"] == "proposed"
    assert any("不可迁移" in w for w in r["counts"]["warnings"])


def test_comment_intent_intel_guide():
    bb = _mk_graph()
    r = apply_observer_lines(bb, _lines(
        {"t": "comment", "id": "D-001", "text": "已 blocked 两轮,建议转向"},
        {"t": "intent", "goal": "挖 k8s 镜像层凭证", "endpoint": "h:5000",
         "note": "延伸", "from": "F-001"},
        {"t": "intel", "text": "5000 是全局最大突破口"},
        {"t": "guide", "text": "主攻镜像层;备选 Druid;自由探索照常"}), round=3)
    assert bb.node("D-001")["payload"]["comment"] == "已 blocked 两轮,建议转向"
    obs_intents = [n for n in bb.nodes("intent") if n["origin"] == "observer"]
    assert len(obs_intents) == 1
    assert any(e["rel"] == "spawns" and e["src"] == "F-001" and e["dst"] == obs_intents[0]["id"]
               for e in bb.edges())
    assert bb.bookkeeping["intel"][-1]["text"] == "5000 是全局最大突破口"
    assert bb.bookkeeping["guide"]["text"].startswith("主攻镜像层")
    assert (r["counts"]["comment"], r["counts"]["intent"],
            r["counts"]["intel"], r["counts"]["guide"]) == (1, 1, 1, 1)


def test_malformed_lines_isolated():
    bb = _mk_graph()
    raw = ['{"t":"verdict","id":"F-001"}',      # 缺 state → 结构非法
           "纯垃圾行",
           '{"t":"unknown"}',
           '[1,2]',
           '{"t":"edge","rel":"same_root"}']    # 缺 src/dst → 结构非法
    r = apply_observer_lines(bb, raw, round=3)
    assert len(r["rejects"]) == 5
    assert bb.graph["edges"] == []


def test_zero_finding_round_semantics():
    """0-finding 轮:intel/comment/intent 行照常消费(schema §6.2 配方2 尾注)。"""
    bb = Blackboard()
    r = apply_observer_lines(bb, _lines(
        {"t": "intel", "text": "全局观察证词"}), round=1)
    assert r["counts"]["intel"] == 1 and not r["rejects"]
