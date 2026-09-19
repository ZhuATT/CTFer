"""AT1 observer_harvest v2 —— 判断书执行器（批3fix F6；协议=contracts/OBSERVER-INTERFACE.md）。

观察者（-p 进程）终态写 `.observer/OBSERVER.json`（五操作）；本模块是协议唯一服务端：
逐条校验（schema/未知 id/终态翻案/noreport/查重）→ board 三原子入图 →
receipt 落 `.at1/interface_log.jsonl`；坏条进 `.observer/OBSERVER.rejects` 不拖累整份。

图唯一写手=观察者（经本执行器），入图即终态（R2）：finding 终态写死、
fact 仅 confirmed→superseded（画像前缀机械换代）。它决定，系统记录。
"""

from __future__ import annotations

import json
from pathlib import Path

OPS = ("add_fact", "add_finding", "add_intent", "set_state", "add_edge")
_RELS = ("sources", "yields", "derived_from", "spawns", "same_root", "supersedes")
_INTENT_STATES = ("open", "in_progress", "done", "blocked")
_SEVERITIES = ("high", "medium", "low", "none")
_RESULTS = ("confirmed", "dismissed")
_PICTURE_PREFIX = "目标画像"


def _dep_key(endpoint: str) -> str:
    """端点归一（兜底匹配键）：剥 query/尾斜杠/通配 **。"""
    ep = (endpoint or "").split("?")[0].strip().lower().rstrip("/")
    while ep.endswith("*"):
        ep = ep.rstrip("*").rstrip("/")
    return ep


def _endpoint_match(a: str, b: str) -> bool:
    ka, kb = _dep_key(a), _dep_key(b)
    if not ka or not kb:
        return False
    return ka in kb or kb in ka   # 双向子串：方向端点常是产出的前缀


def _auto_link(bb, node_id: str, *, round: int) -> int:
    """endpoint 兜底（schema §4.1：节点已有任何边 → 不动）。
    fact → 同端点在途 intent 补 sources；finding → 同端点在途 intent 补 yields。"""
    node = bb.node(node_id)
    if node is None or node["endpoint"] == "global":
        return 0
    if bb.edges(src=node_id) or bb.edges(dst=node_id):
        return 0
    n = 0
    for it in bb.nodes("intent"):
        if it["state"] == "done":
            continue
        if _endpoint_match(node["endpoint"], it["endpoint"]):
            if node["kind"] == "fact":
                src, dst, rel = node_id, it["id"], "sources"
            else:
                src, dst, rel = it["id"], node_id, "yields"
            if bb.add_edge(src, rel, dst, origin="controller",
                           note="endpoint 兜底", round=round):
                n += 1
    return n


def _ref_edge(bb, node_id: str, ref, *, round: int) -> int:
    """ref 自动连边（六动词语义表，schema §4.1）：
    - 方向 ref 线索（intent→fact/finding）：sources——线索支撑方向
    - 发现/事实 ref 方向（fact/finding→intent）：yields——方向产出该产出
    - 方向 ref 发现（intent→finding）：spawns——发现催生了新方向
    - 产出 ref 产出（fact/finding→fact/finding）：derived_from——本条派生自
    指向不存在的节点是建议性失配：不连边、不报错（ref 非强制字段）。"""
    r = str(ref or "").strip()
    if not r or r == node_id:
        return 0
    node = bb.node(node_id)
    target = bb.node(r)
    if node is None or target is None:
        return 0
    nk, tk = node["kind"], target["kind"]
    if nk == "intent" and tk == "finding":
        rel, src, dst = "spawns", r, node_id        # 发现催生方向
    elif nk == "intent" and tk == "fact":
        rel, src, dst = "sources", node_id, r       # 线索支撑方向
    elif nk in ("fact", "finding") and tk == "intent":
        rel, src, dst = "yields", r, node_id        # 方向产出该产出
    elif nk == "intent" and tk == "intent":
        rel, src, dst = "spawns", r, node_id
    else:
        rel, src, dst = "derived_from", node_id, r
    return 1 if bb.add_edge(src, rel, dst, origin="observer",
                            note="ref 自动连线", round=round) else 0


def _swap_picture(bb, node_id: str, *, round: int) -> int:
    """画像前缀机械换代：新 fact 摘要带"目标画像"前缀 → 旧画像 fact 标 superseded
    并连 supersedes 边（R2：翻案=加新节点替代）。返回换代数。"""
    node = bb.node(node_id)
    if node is None or not str(node["payload"].get("value", "")).startswith(_PICTURE_PREFIX):
        return 0
    n = 0
    for other in bb.nodes("fact"):
        if other["id"] == node_id or other["state"] != "confirmed":
            continue
        if str(other["payload"].get("value", "")).startswith(_PICTURE_PREFIX):
            if (bb.add_edge(node_id, "supersedes", other["id"], origin="observer",
                            note="画像换代", round=round)
                    and bb.update_node(other["id"], state="superseded")):
                n += 1
    return n


def _op_add_fact(bb, op, *, round, noreport_rejects):
    summary = str(op.get("summary", "")).strip()
    evidence = str(op.get("evidence", "")).strip()
    if not summary or not evidence:
        return "rejected", {}, "add_fact 缺必填 summary/evidence"
    endpoint = str(op.get("endpoint", "")).strip() or "global"
    before = {n["id"] for n in bb.graph["nodes"]}
    nid = bb.create_node("fact", {"value": summary[:500], "evidence": evidence[:200]},
                         endpoint=endpoint, origin="observer", round=round)
    status = "existing" if nid in before else "applied"
    edges = _ref_edge(bb, nid, op.get("ref"), round=round) + _auto_link(bb, nid, round=round)
    edges += _swap_picture(bb, nid, round=round)
    return status, {"id": nid, "edges": edges}, None


def _op_add_finding(bb, op, *, round, noreport_rejects):
    summary = str(op.get("summary", "")).strip()
    report = str(op.get("report", "")).replace("\\", "/").strip()
    severity = str(op.get("severity", "")).strip()
    reason = str(op.get("reason", "")).strip()
    if not summary or not report or not severity or not reason:
        return "rejected", {}, "add_finding 缺必填 summary/report/severity/reason"
    if severity not in _SEVERITIES:
        return "rejected", {}, f"severity 非法：{severity}"
    result = str(op.get("result", "")).strip() or "confirmed"
    if result not in _RESULTS:
        return "rejected", {}, f"result 非法：{result}"
    if report in set(noreport_rejects or ()):
        return "rejected", {}, f"noreport 硬拒命中：{report}"
    endpoint = str(op.get("endpoint", "")).strip() or "global"
    before = {n["id"] for n in bb.graph["nodes"]}
    nid = bb.create_node("finding", {"summary": summary[:300], "report": report[:200],
                                     "severity": severity, "reason": reason[:500]},
                         endpoint=endpoint, origin="observer", round=round, state=result)
    status = "existing" if nid in before else "applied"
    edges = _ref_edge(bb, nid, op.get("ref"), round=round) + _auto_link(bb, nid, round=round)
    return status, {"id": nid, "edges": edges}, None


def _op_add_intent(bb, op, *, round, noreport_rejects):
    goal = str(op.get("goal", "")).strip()
    note = str(op.get("note", "")).strip()
    if not goal:
        return "rejected", {}, "add_intent 缺必填 goal"
    endpoint = str(op.get("endpoint", "")).strip() or "global"
    nid = bb.create_node("intent", {"goal": goal[:200], "note": note[:500]},
                         endpoint=endpoint, origin="observer", round=round)
    edges = _ref_edge(bb, nid, op.get("ref"), round=round)
    return "applied", {"id": nid, "edges": edges}, None


def _op_set_state(bb, op, *, round, noreport_rejects):
    nid = str(op.get("id", "")).strip()
    state = str(op.get("state", "")).strip()
    reason = str(op.get("reason", "")).strip()
    node = bb.node(nid)
    if node is None:
        return "rejected", {}, f"set_state 目标不存在：{nid}"
    if node["kind"] != "intent":
        return "rejected", {}, f"set_state 仅作用 intent（{nid} 是 {node['kind']} 终态写死）"
    if state not in _INTENT_STATES:
        return "rejected", {}, f"state 非法：{state}"
    if state == "blocked" and not reason:
        return "rejected", {}, "blocked 必带可检验条件（A11）"
    patch = {"blocked_reason": reason[:300]} if state == "blocked" else {"note": reason[:500]}
    ok = bb.update_node(nid, state=state, payload_patch=patch)
    return ("applied" if ok else "rejected"), {"id": nid}, None if ok else "迁移未生效"


def _op_add_edge(bb, op, *, round, noreport_rejects):
    src = str(op.get("src", "")).strip()
    dst = str(op.get("dst", "")).strip()
    rel = str(op.get("rel", "")).strip()
    note = str(op.get("note", "")).strip()[:300]
    if not src or not dst:
        return "rejected", {}, "add_edge 缺 src/dst"
    if rel not in _RELS:
        return "rejected", {}, f"rel 非法：{rel}（六动词）"
    if bb.node(src) is None or bb.node(dst) is None:
        return "rejected", {}, f"端点节点不存在：{src}/{dst}"
    if not bb.add_edge(src, rel, dst, origin="observer", note=note, round=round):
        return "existing", {"src": src, "rel": rel, "dst": dst}, None   # 声明优先
    if rel == "supersedes":
        dup = bb.node(dst)
        if dup is not None and dup["kind"] == "fact" and dup["state"] == "confirmed":
            bb.update_node(dst, state="superseded")
    return "applied", {"src": src, "rel": rel, "dst": dst}, None


_HANDLERS = {"add_fact": _op_add_fact, "add_finding": _op_add_finding,
             "add_intent": _op_add_intent, "set_state": _op_set_state,
             "add_edge": _op_add_edge}


def apply_judgment(bb, doc, *, round: int, root: Path,
                   noreport_rejects=()) -> dict:
    """判断书 → 图（协议唯一服务端）。返回 {"counts","rejects","receipts","applied"}。
    逐条 best-effort：坏条进 rejects（落 .observer/OBSERVER.rejects），不拖累整份；
    每条成功落 receipt（.at1/interface_log.jsonl）。"""
    counts = {op: 0 for op in OPS}
    counts["dedup_existing"] = 0
    applied = 0                                  # 真落笔数（幂等撞键的 existing 不计）
    rejects: list[dict] = []
    receipts: list[dict] = []
    ops = doc.get("operations") if isinstance(doc, dict) else None
    if not isinstance(ops, list):
        return {"counts": counts, "rejects": [{"error": "operations 缺失或非数组"}],
                "receipts": [], "applied": 0}
    for i, op in enumerate(ops):
        if not isinstance(op, dict) or op.get("op") not in OPS:
            rejects.append({"index": i, "error": "未知 op 或非对象", "raw": str(op)[:200]})
            continue
        try:
            status, info, err = _HANDLERS[op["op"]](bb, op, round=round,
                                                    noreport_rejects=noreport_rejects)
        except Exception as e:                       # 单条异常不拖垮整份
            status, info, err = "rejected", {}, f"执行器异常：{e}"
        if status == "rejected":
            rejects.append({"index": i, "op": op.get("op"), "error": err})
            continue
        counts[op["op"]] += 1
        if status == "existing":
            counts["dedup_existing"] += 1
        else:
            applied += 1
        receipts.append({"ts_round": round, "op": op.get("op"), "status": status, **info})
    _write_receipts(root, receipts)
    return {"counts": counts, "rejects": rejects, "receipts": receipts,
            "applied": applied}


def _write_receipts(root, receipts: list[dict]) -> None:
    if not receipts or root is None:
        return
    p = Path(root) / ".at1" / "interface_log.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in receipts:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_rejects(root, rejects: list[dict], *, round: int) -> None:
    """坏条隔离区（追加式）。"""
    if not rejects or root is None:
        return
    p = Path(root) / ".observer" / "OBSERVER.rejects"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in rejects:
            f.write(json.dumps({"round": round, **r}, ensure_ascii=False) + "\n")
