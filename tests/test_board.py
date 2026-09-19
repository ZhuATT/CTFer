"""board v3 单测：三原子/六不变量/四视图/goal/Stop/旧板归档/持久化（schema v3.0）。"""

import json
import os

import pytest

from src.board import Blackboard


# ── 三原子（schema §6.1） ────────────────────────────────────────────────

def test_create_node_basic_and_ids():
    b = Blackboard()
    d = b.create_node("intent", {"goal": "打 registry", "note": "先枚举"},
                      endpoint="172.20.9.26:5000", origin="worker", round=1)
    f = b.create_node("finding", {"summary": "未授权访问", "evidence": "evidence/a.md"},
                      endpoint="172.20.9.26:5000", origin="worker", round=1)
    t = b.create_node("fact", {"value": "Shiro 站点", "evidence": "x"},
                      origin="worker", round=1)
    assert (d, f, t) == ("D-001", "F-001", "T-001")
    assert b.node(d)["state"] == "open"
    assert b.node(f)["state"] == "confirmed"            # R2：入图即终态
    assert b.node(t)["state"] == "confirmed"
    assert b.node(d)["endpoint"] == "172.20.9.26:5000"
    assert b.node(t)["endpoint"] == "global"            # 缺省旁挂
    with pytest.raises(ValueError):
        b.create_node("endpoint", {"value": "x"}, origin="worker")   # v2 kind 已死
    with pytest.raises(ValueError):
        b.create_node("fact", {"value": "x"}, origin="attacker")
    with pytest.raises(ValueError):
        b.create_node("fact", {"evidence": "没值"}, origin="worker")  # 必填缺失
    with pytest.raises(ValueError):
        b.create_node("fact", {"value": "x"}, origin="worker", state="proposed")  # R2：proposed 消亡


def test_create_node_dedup_key():
    b = Blackboard()
    a = b.create_node("fact", {"value": "WAF=宝塔"}, origin="worker", round=1)
    dup = b.create_node("fact", {"value": "  waf=宝塔  "}, origin="worker", round=2)  # 归一后同键
    assert a == dup
    other_ep = b.create_node("fact", {"value": "WAF=宝塔"}, endpoint="/api/x",
                             origin="worker", round=2)
    assert other_ep != a
    d = b.create_node("intent", {"goal": "WAF=宝塔"}, origin="worker", round=1)   # kind 隔离
    f = b.create_node("finding", {"summary": "WAF=宝塔"}, origin="worker", round=1)
    assert (d, f) == ("D-001", "F-001")


def test_create_node_worker_id_conflict_renumber():
    b = Blackboard()
    b.create_node("fact", {"value": "占位"}, origin="worker", round=0, id="T-001")
    nid = b.create_node("fact", {"value": "新事实"}, origin="worker", round=3, id="T-001")
    assert nid == "T-R3-T-001"                          # 不变量 6：冲突重编号
    nid2 = b.create_node("fact", {"value": "再一条"}, origin="worker", round=3, id="bad-id")
    assert nid2 == "T-002"                              # 非本前缀自报 → 顺位发号


def test_update_node_finding_terminal_immutable():
    """R2 终版：finding 终态写死——confirmed/dismissed 均不可迁移（翻案=加新节点）。"""
    b = Blackboard()
    f = b.create_node("finding", {"summary": "s"}, origin="worker", round=1)
    assert b.update_node(f, payload_patch={"severity": "high", "reason": "r"}) is True
    assert b.update_node(f, state="dismissed") is False
    assert b.node(f)["state"] == "confirmed"
    f2 = b.create_node("finding", {"summary": "s2", "reason": "判假"},
                       origin="worker", round=1, state="dismissed")
    assert b.update_node(f2, state="confirmed") is False
    assert b.node(f2)["state"] == "dismissed"
    assert b.update_node(f, state="killed") is False     # 非法 state
    assert b.update_node("F-999", state="confirmed") is False


def test_update_node_fact_superseded_only_from_confirmed():
    b = Blackboard()
    t = b.create_node("fact", {"value": "v"}, origin="worker", round=1)   # 直落 confirmed
    assert b.update_node(t, state="superseded") is True
    t2 = b.create_node("fact", {"value": "v2"}, origin="worker", round=1,
                       state="dismissed")
    assert b.update_node(t2, state="superseded") is False


def test_update_node_intent_transitions_and_comment():
    b = Blackboard()
    d = b.create_node("intent", {"goal": "g"}, origin="worker", round=1)
    assert b.update_node(d, state="in_progress") is True
    assert b.update_node(d, comment="已 blocked 两轮,建议转向") is True
    assert b.node(d)["payload"]["comment"] == "已 blocked 两轮,建议转向"
    assert b.update_node(d, state="done") is True


def test_add_edge_dedup_and_validation():
    """不变量 4：声明优先——(src,rel,dst) 已存在不覆盖。"""
    b = Blackboard()
    d = b.create_node("intent", {"goal": "g"}, origin="worker", round=1)
    t = b.create_node("fact", {"value": "v"}, origin="worker", round=1)
    assert b.add_edge(t, "sources", d, origin="worker", note="声明", round=1) is True
    assert b.add_edge(t, "sources", d, origin="observer", round=2) is False
    assert len(b.edges()) == 1 and b.edges()[0]["origin"] == "worker"
    with pytest.raises(ValueError):
        b.add_edge(t, "combines", d, origin="worker")    # v2 动词已死
    with pytest.raises(ValueError):
        b.add_edge(t, "sources", d, origin="user")       # 边 origin 三值


def test_sanitize_payload_drops_unknown_and_bad_severity():
    b = Blackboard()
    f = b.create_node("finding", {"summary": "s", "confidence": "observed",
                                  "evidence_verified": True, "severity": "超危"},
                      origin="worker", round=1)
    p = b.node(f)["payload"]
    assert "confidence" not in p and "evidence_verified" not in p
    assert "severity" not in p                           # 非法枚举丢弃
    b.update_node(f, payload_patch={"severity": "high", "junk": "x"})
    assert b.node(f)["payload"]["severity"] == "high"
    assert "junk" not in b.node(f)["payload"]


# ── 四派生视图（schema §5，零存储现算） ──────────────────────────────────

def _seed_graph() -> tuple[Blackboard, dict]:
    b = Blackboard()
    ids = {}
    ids["d1"] = b.create_node("intent", {"goal": "5000 registry"},
                              endpoint="h:5000", origin="worker", round=1)
    ids["d2"] = b.create_node("intent", {"goal": "9098 弱口令", "note": "4 组全阴性"},
                              endpoint="h:9098", origin="worker", round=1)
    b.update_node(ids["d2"], state="done")               # done ∧ 无 yields → 阴性
    ids["f1"] = b.create_node("finding", {"summary": "registry 未授权"},
                              endpoint="h:5000/v2/_catalog", origin="worker", round=2)
    b.add_edge(ids["d1"], "yields", ids["f1"], origin="worker", note="声明", round=2)
    ids["f2"] = b.create_node("finding", {"summary": "批量读公开评价", "reason": "信息本身公开可见"},
                              endpoint="h:80", origin="worker", round=2, state="dismissed")
    ids["t1"] = b.create_node("fact", {"value": "Shiro 站点"},
                              endpoint="h:9098", origin="worker", round=1)
    ids["t2"] = b.create_node("fact", {"value": "目标画像：内网 JVM 厂站"},
                              origin="worker", round=1)   # global 桶
    ids["t3"] = b.create_node("fact", {"value": "未锚定线索"},
                              endpoint="h:7000", origin="worker", round=2)
    return b, ids


def test_negative_view():
    b, ids = _seed_graph()
    rows = b.negative_view()
    kinds = {(r["kind"], r["id"]) for r in rows}
    assert ("intent", ids["d2"]) in kinds                # done 无产出
    assert ("intent", ids["d1"]) not in kinds            # 有 yields 出边 → 不阴性
    assert ("finding", ids["f2"]) in kinds               # dismissed 带死因
    d2row = next(r for r in rows if r["id"] == ids["d2"])
    assert "全阴性" in d2row["reason"]
    f2row = next(r for r in rows if r["id"] == ids["f2"])
    assert "公开可见" in f2row["reason"]


def test_endpoint_groups_excludes_global():
    b, ids = _seed_graph()
    g = b.endpoint_groups()
    assert set(g) == {"h:5000", "h:5000/v2/_catalog", "h:9098", "h:80", "h:7000"}
    assert "global" not in g
    assert ids["t2"] in [n["id"] for n in b.nodes("fact", endpoint="global")]


def test_lineage_view_parents_and_yields():
    b, ids = _seed_graph()
    lin = b.lineage_view()
    assert ids["d1"] in lin[ids["f1"]]["parents"]        # f1 ← d1 yields
    assert ids["f1"] in lin[ids["d1"]]["yields"]
    assert lin[ids["t1"]]["parents"] == []               # 无边节点也有条目
    assert set(lin) == {n["id"] for n in b.graph["nodes"]}


def test_untested_surface():
    b, ids = _seed_graph()
    un = b.untested_surface()
    assert "h:7000" in un                                # 只有孤 fact 锚定
    assert "h:5000" not in un                            # intent 覆盖
    assert "h:5000/v2/_catalog" not in un                # finding 覆盖
    assert "h:9098" not in un                            # done intent 也算覆盖过


# ── goal / Stop（T1.5） ──────────────────────────────────────────────────

def test_set_goal_and_roundtrip(tmp_path):
    p = str(tmp_path / "bb.json")
    b = Blackboard(p)
    b.set_goal("拿到域控", round=3)
    b.save()
    b2 = Blackboard(p)
    assert b2.goal == {"text": "拿到域控", "updated_round": 3}


def test_parse_stop_achieved_requires_existing_finding():
    """A18 引证护栏：无引证/引证不存在/引证非 finding → 无效。"""
    b, ids = _seed_graph()
    assert b.parse_stop("<Stop>目标达成，收工</Stop>") is None
    assert b.parse_stop("<Stop>目标达成 F-999</Stop>") is None
    assert b.parse_stop(f"<Stop>目标达成 {ids['d1']}</Stop>") is None   # D-xxx 不算引证
    r = b.parse_stop(f"<Stop>目标达成：registry 未授权已确认 {ids['f1']}</Stop>")
    assert r["kind"] == "achieved" and r["refs"] == [ids["f1"]]


def test_parse_stop_exhausted_needs_reason():
    b, ids = _seed_graph()
    r = b.parse_stop("<Stop>攻击面测尽：高中低价值端点全覆盖无新入口</Stop>")
    assert r["kind"] == "exhausted" and r["refs"] == []
    assert b.parse_stop("<Stop>测尽</Stop>") is None     # 理由过短
    assert b.parse_stop("没有标签的文本") is None
    assert b.parse_stop("") is None


# ── 持久化 / 旧板归档 / 摘要 ─────────────────────────────────────────────

def test_save_atomic_and_bak_fallback(tmp_path):
    p = str(tmp_path / "bb.json")
    b = Blackboard(p)
    b.create_node("fact", {"value": "keep"}, origin="worker", round=1)
    b.save()
    b.save()                                             # 第二次 save 产生 .bak
    assert os.path.isfile(p) and os.path.isfile(p + ".bak")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{corrupted!!")
    b2 = Blackboard(p)
    assert b2.node("T-001") is not None                  # .bak 回退


def test_full_schema_roundtrip(tmp_path):
    p = str(tmp_path / "bb.json")
    b = Blackboard(p)
    d = b.create_node("intent", {"goal": "g", "note": "n", "comment": "c",
                                 "blocked_reason": "br"}, endpoint="h:1",
                      origin="observer", round=1)
    b.update_node(d, state="blocked")
    f = b.create_node("finding", {"summary": "s", "report": "reports/F-001.md",
                                  "evidence": "e", "severity": "high", "reason": "r"},
                      origin="worker", round=1)
    b.update_node(f, state="confirmed")
    t = b.create_node("fact", {"value": "v", "evidence": "ev"}, origin="user", round=0)
    b.update_node(t, state="confirmed")
    t2 = b.create_node("fact", {"value": "v2"}, origin="worker", round=1)
    b.update_node(t2, state="confirmed")
    b.update_node(t2, state="superseded")
    b.add_edge(t2, "supersedes", t, origin="observer", round=1)
    b.set_goal("目标", round=2)
    b.record_handoff("干了 X")
    b.add_intel("全局判断", 2)
    b.offsets["facts"] = 42
    b.save()
    b2 = Blackboard(p)
    assert b2.node(f)["state"] == "confirmed"
    assert b2.node(f)["payload"]["report"] == "reports/F-001.md"
    assert b2.goal["text"] == "目标"
    assert b2.bookkeeping["handoff"] == "干了 X"
    assert b2.bookkeeping["intel"] == [{"round": 2, "text": "全局判断"}]
    assert b2.offsets["facts"] == 42
    assert any(e["rel"] == "supersedes" for e in b2.edges())
    data = json.load(open(p, encoding="utf-8"))
    assert set(data) == {"graph", "bookkeeping"}         # 两节分立，无 v2 死结构


def test_legacy_board_archived_and_fresh_start(tmp_path):
    """v2 遗形（无 graph 键）→ 归档改名 + 空板起步（已裁 09-18：不做内容迁移）。"""
    p = tmp_path / "blackboard.json"
    p.write_text(json.dumps({
        "facts": [{"kind": "endpoint", "value": "/api/old", "confidence": "observed",
                   "provenance": "p", "ts": "t", "round": 1}],
        "immune": [], "findings": [], "directions": [], "chains": [],
        "session_intel": {}, "handoff": "旧交接", "goal": {"stage": "recon"},
        "ledger": {"tried": {}, "background": []},
        "verified": {"confirmed": 0, "tentative": 0}, "config": {},
        "offsets": {"facts": 7},
    }, ensure_ascii=False), encoding="utf-8")
    b = Blackboard(str(p))
    assert b.legacy_archived == str(p) + ".v2-legacy.json"
    assert os.path.isfile(b.legacy_archived)
    assert not os.path.isfile(str(p))                    # 原位置让给 v3
    assert b.graph["nodes"] == [] and b.graph["edges"] == []
    assert b.offsets == {}                               # 旧簿记不带入
    b.create_node("fact", {"value": "新板第一条"}, origin="worker", round=1)
    b.save()
    assert json.load(open(p, encoding="utf-8"))["graph"]["nodes"]


def test_summarize_deterministic_and_counts():
    b, ids = _seed_graph()
    s1, s2 = b.summarize(2), b.summarize(2)
    assert s1 == s2                                      # 确定性
    assert "已确认发现" in s1 and "待接方向" in s1 and "STATE.md" in s1
    assert ids["d1"] in s1                               # 待接方向带 id


def test_intent_counts_and_active_order():
    b, ids = _seed_graph()
    b.update_node(ids["d1"], state="in_progress")
    act = b.active_intents()
    assert [n["id"] for n in act] == [ids["d1"]]         # done 的 d2 不进 active
    c = b.intent_counts()
    assert c == {"open": 0, "in_progress": 1, "done": 1, "blocked": 0}
