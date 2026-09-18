"""AT1 observer_harvest —— 配方 2:OBSERVER 七类行 → 图(schema §7)。

观察者(-p 进程,P5 上车)把判断书写进 `.observer/OBSERVER`(JSONL,七类行);
controller 收割器机械执行本模块的翻译——**它决定,系统记录**,每次写入带 round+origin。
- 不变量 3(verdict 仅作用 proposed、confirmed 不可翻案)由 board.update_node 机械兜底;
- noreport 硬拒条目 verdict 不受理(`rejected_ids` 前置闭环,T2.6);
- 结构非法行(坏 JSON/未知 t/必填缺失)进 rejects——调用方落
  `.observer/OBSERVER.rejects` + `observer_parse_fail` 事件;
- 语义未生效(节点不存在/不变量拒绝)记 warnings,不阻塞。

批 2 交付解析器+单测先行;激活=P5(observer.py 重写后产出 OBSERVER 文件)。
"""

from __future__ import annotations

import json

_SEVEN_TYPES = ("verdict", "edge", "comment", "intent", "intel", "guide")
_VERDICT_STATES = ("confirmed", "dismissed")


def apply_observer_lines(bb, lines, *, round: int,
                         rejected_ids: set | None = None) -> dict:
    """OBSERVER JSONL 行 → 图操作(配方 2,schema §6.2/§7)。
    返回 {"counts": {...}, "rejects": [结构非法行原文]}。"""
    rejected_ids = rejected_ids or set()
    counts = {"verdict": 0, "verdict_skip_rejected": 0, "verdict_illegal": 0,
              "edge": 0, "dismissed_by_primary": 0, "comment": 0,
              "intent": 0, "intel": 0, "guide": 0, "warnings": []}
    rejects: list[str] = []
    for raw in lines or []:
        line = raw.strip().lstrip("﻿").strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            rejects.append(raw)
            continue
        if not isinstance(d, dict) or d.get("t") not in _SEVEN_TYPES:
            rejects.append(raw)
            continue
        t = d["t"]
        if t == "verdict":
            _apply_verdict(bb, d, counts, rejects, rejected_ids)
        elif t == "edge":
            _apply_edge(bb, d, counts, rejects, round)
        elif t == "comment":
            if str(d.get("id", "")).strip() and bb.update_node(
                    str(d["id"]), comment=str(d.get("text", ""))):
                counts["comment"] += 1
            else:
                counts["warnings"].append(f"comment 目标不存在:{d.get('id')}")
        elif t == "intent":
            nid = bb.create_node("intent",
                                 {"goal": str(d.get("goal", "")),
                                  "note": str(d.get("note", ""))},
                                 endpoint=str(d.get("endpoint", "")) or "global",
                                 origin="observer", round=round)
            counts["intent"] += 1
            src = str(d.get("from", "")).strip()
            if src:
                bb.add_edge(src, "spawns", nid, origin="observer",
                            note="观察者立向", round=round)
        elif t == "intel":
            text = str(d.get("text", "")).strip()
            if text:
                bb.add_intel(text, round)
                counts["intel"] += 1
            else:
                counts["warnings"].append("intel 缺 text(必填)")
        elif t == "guide":
            text = str(d.get("text", "")).strip()
            if text:
                bb.bookkeeping["guide"] = {"round": int(round), "text": text[:2000]}
                counts["guide"] += 1
            else:
                counts["warnings"].append("guide 缺 text")
    return {"counts": counts, "rejects": rejects}


def _apply_verdict(bb, d, counts, rejects, rejected_ids) -> None:
    """verdict 行:审查结论。硬拒 id 不受理;不变量 3 由 board 兜底。"""
    nid = str(d.get("id", "")).strip()
    state = d.get("state")
    if not nid or state not in _VERDICT_STATES:
        rejects.append(json.dumps(d, ensure_ascii=False))
        return
    if nid in rejected_ids:
        counts["verdict_skip_rejected"] += 1
        return
    patch = {"reason": str(d.get("reason", ""))[:500]}
    if d.get("severity"):
        patch["severity"] = str(d["severity"])
    if bb.update_node(nid, state=state, payload_patch=patch):
        counts["verdict"] += 1
    else:
        counts["verdict_illegal"] += 1
        counts["warnings"].append(f"verdict 未生效:{nid}(不存在或非 proposed——不可翻案)")


def _primary_fallback(bb, a: str, b: str) -> str:
    """先到优先(schema §7):confirmed 最早者为正主;无 confirmed 取 round 最早;再并列取 a。"""
    def rank(nid: str):
        n = bb.node(nid)
        if n is None:
            return (1, 999_999, nid)
        return (0 if n["state"] == "confirmed" else 1, n.get("round", 0), nid)
    return a if rank(a) <= rank(b) else b


def _apply_edge(bb, d, counts, rejects, round: int) -> None:
    rel = d.get("rel")
    src, dst = str(d.get("src", "")).strip(), str(d.get("dst", "")).strip()
    note = str(d.get("note", ""))[:300]
    if not src or not dst:
        rejects.append(json.dumps(d, ensure_ascii=False))
        return
    if rel == "same_root":
        # 正主规则(拍板2=B):primary∈{src,dst} → 正主=primary;缺失/非法 → 先到优先。
        # 边方向=非正主→正主(schema §4.1)——primary 指向 src 时翻转。
        primary = str(d.get("primary", "")).strip()
        if primary not in (src, dst):
            primary = _primary_fallback(bb, src, dst)
        if primary == src:
            src, dst = dst, src
        if bb.add_edge(src, "same_root", dst, origin="observer", note=note, round=round):
            counts["edge"] += 1
        dup = bb.node(src)
        if dup is not None and dup["state"] == "proposed":
            if bb.update_node(src, state="dismissed",
                              payload_patch={"reason": f"并入正主 {dst}"}):
                counts["dismissed_by_primary"] += 1
        elif dup is not None and dup["state"] == "confirmed":
            counts["warnings"].append(f"非正主 {src} 已 confirmed,保持不翻案(不变量 3)")
    elif rel == "supersedes":
        if bb.add_edge(src, "supersedes", dst, origin="observer", note=note, round=round):
            counts["edge"] += 1
        if not bb.update_node(dst, state="superseded"):
            counts["warnings"].append(f"supersedes 目标不可迁移:{dst}(仅 confirmed 可被取代)")
    else:
        # sources/yields/derived_from/spawns:观察者补线(§4.1 观察者决定权内),平铺 add_edge
        if bb.add_edge(src, str(rel), dst, origin="observer", note=note, round=round):
            counts["edge"] += 1
        else:
            counts["warnings"].append(f"边已存在(声明优先):{src}-{rel}->{dst}")
