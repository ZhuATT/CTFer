"""AT1 harvest —— 轮末收割辅助（配方 1：worker 账本行 → 图节点，schema §6.2）。

v3：A19 后合成交接机制死（观察者自己读磁盘），本模块收敛为配方 1 的代写函数——
controller 独占三原子，账本行在这里翻译成 create_node/add_edge。
兜底原则（schema §4.1）：worker 声明优先，auto_link 只在节点无任何边时机械补线。
"""

from __future__ import annotations

import json
import os
from typing import Optional


def diff_new_lines(path: str, offset: int = 0) -> tuple[list[str], int]:
    """从字节 offset 起读新增的完整行（不完整行留给下次）。返回 (行列表, 新 offset)。

    幂等：两次调用同一 offset 结果一致；文件不存在 → ([], offset)。
    """
    if not os.path.isfile(path):
        return [], offset
    size = os.path.getsize(path)
    if size <= offset:
        return [], offset
    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read()
    # 只消费到最后一个换行——半行（写入中）留给下一次
    last_nl = raw.rfind(b"\n")
    if last_nl < 0:
        return [], offset
    consumed = raw[:last_nl + 1]
    text = consumed.decode("utf-8", errors="replace")
    lines = [l.rstrip("\r") for l in text.split("\n")]     # Windows CRLF
    lines = [l for l in lines if l.strip()]
    return lines, offset + last_nl + 1


# ── 账本行 → 节点（配方 1 代写） ─────────────────────────────────────────

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
    return ka in kb or kb in ka   # 双向子串：方向端点常是产出的前缀（host:5000 vs host:5000/v2/x）


def _declare_chain(bb, node_id: str, chain, *, round_: int) -> int:
    """worker 账本行 chain 声明照抄成边（FORMATS 三动词，方向按 schema §4.1）：
    - derived_from：本条 → ref（派生自）
    - sources：本条(F/T) → ref(D-xxx)（线索支撑方向）
    - yields：ref(D-xxx) → 本条（产出源自方向——方向相反，翻边）
    same_root 判重归观察者裁（FORMATS 禁令），worker 声明不受理。返回新建边数。"""
    if not isinstance(chain, dict):
        return 0
    rel = chain.get("rel")
    if rel not in ("derived_from", "sources", "yields"):
        return 0
    refs = chain.get("refs") if isinstance(chain.get("refs"), list) else []
    note = str(chain.get("note", ""))[:300]
    n = 0
    for r in refs:
        r = str(r).strip()
        if not r or r == node_id:
            continue
        if rel == "yields":
            ok = bb.add_edge(r, "yields", node_id, origin="worker",
                             note=note, round=round_)
        else:
            ok = bb.add_edge(node_id, rel, r, origin="worker",
                             note=note, round=round_)
        if ok:
            n += 1
    return n


def auto_link(bb, node_id: str, *, round_: int) -> int:
    """endpoint 兜底（schema §4.1：声明优先，节点已有任何边 → 不动）。
    fact → 同端点在途 intent 补 sources；finding → 同端点在途 intent 补 yields。"""
    node = bb.node(node_id)
    if node is None or node["endpoint"] == "global":
        return 0
    if bb.edges(src=node_id) or bb.edges(dst=node_id):
        return 0                                   # 兜底只在无人声明时（不变量 4）
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
                           note="endpoint 兜底", round=round_):
                n += 1
    return n


def finding_to_node(bb, row: dict, *, round_: int) -> Optional[str]:
    """FINDINGS 行 → finding 节点（proposed 起步；report 指针透传；
    worker 自报 id 冲突由 board 重编号）。返回节点 id；无效行 None。"""
    if not isinstance(row, dict):
        return None
    summary = str(row.get("summary", "")).strip()
    endpoint = str(row.get("endpoint", "")).strip()
    if not summary or not endpoint:
        return None
    nid = bb.create_node(
        "finding",
        {"summary": summary, "report": str(row.get("report", "")),
         "evidence": str(row.get("evidence", "")), "severity": str(row.get("severity") or "")},
        endpoint=endpoint, origin="worker", round=round_,
        id=str(row.get("id", "")).strip() or None)
    _declare_chain(bb, nid, row.get("chain"), round_=round_)
    auto_link(bb, nid, round_=round_)
    return nid


def facts_to_nodes(bb, lines, *, round_: int) -> int:
    """FACTS 行 → fact 节点（配方 1 FACTS 半边）。宽容 BOM/空白/坏行；
    value 必填；行上的 fact_kind 字段丢弃（v3 无类别）。返回新建行数。"""
    n = 0
    for line in lines or []:
        line = line.strip().lstrip("﻿").strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        value = str(d.get("value", "")).strip()
        if not value:
            continue
        before = len(bb.graph["nodes"])
        nid = bb.create_node("fact",
                             {"value": value, "evidence": str(d.get("evidence", ""))},
                             endpoint=str(d.get("endpoint", "")).strip() or "global",
                             origin="worker", round=round_)
        _declare_chain(bb, nid, d.get("chain"), round_=round_)
        auto_link(bb, nid, round_=round_)
        if len(bb.graph["nodes"]) > before:
            n += 1
    return n
