"""AT1 board —— 图黑板 v3（docs/at1-黑板schema.md v3.0：graph 协作面 + bookkeeping 簿记）。

两层分家（图与黑板v3设计 §〇）：写入面（worker 三账本，本文件不感知）与协作面
（图，渗透知识的唯一事实源，controller 从账本蒸馏）。worker/观察者永不直接调用
三原子——只通过账本/OBSERVER 间接表达意愿，controller 代写（每次写带 round+origin）。

三原子操作（schema §6.1）+ 六不变量（§6.3，board 级机械强制点见各方法）：
  1 代写唯一入口  2 节点/边不删  3 verdict 仅作用于 proposed
  4 声明优先（add_edge 不覆盖）  5 去重键  6 冲突重编号
四派生视图（§5，零存储现算）：阴性 / 端点分组 / 谱系 / 未测面。
旧黑板（v2 形状，无 graph 键）读到即归档改名空板新开（已裁 09-18：不做内容迁移）。
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Optional

KINDS = ("intent", "finding", "fact")
KIND_PREFIX = {"intent": "D", "finding": "F", "fact": "T"}

# ── 六动词边（schema §4.1；v2 combines 已死，边词表不收录） ───────────────
RELS = ("sources", "yields", "derived_from", "spawns", "same_root", "supersedes")
EDGE_ORIGINS = ("worker", "observer", "controller")

NODE_ORIGINS = ("worker", "controller", "observer", "user")

INTENT_STATES = ("open", "in_progress", "done", "blocked")
FINDING_STATES = ("proposed", "confirmed", "dismissed")
FACT_STATES = ("proposed", "confirmed", "dismissed", "superseded")
STATES = {"intent": INTENT_STATES, "finding": FINDING_STATES, "fact": FACT_STATES}

# payload 白名单（schema §3；写入口滤未知键——快照 additionalProperties:false 的执行半边）
_PAYLOAD_FIELDS = {
    "intent": {"goal": 200, "note": 500, "comment": 300, "blocked_reason": 300},
    "finding": {"summary": 300, "report": 200, "evidence": 200,
                "severity": 10, "reason": 500},
    "fact": {"value": 500, "evidence": 200},
}
_PAYLOAD_REQUIRED = {"intent": "goal", "finding": "summary", "fact": "value"}
_SEVERITIES = ("high", "medium", "low", "none")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_text(v) -> str:
    """去重键归一：压空白、小写、截 120（schema §6.3 不变量 5）。"""
    return re.sub(r"\s+", " ", str(v or "")).strip().lower()[:120]


class Blackboard:
    """唯一事实源（.at1/blackboard.json）。worker 永不直接读它——只经 STATE.md 投影。"""

    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._lock = threading.RLock()
        self.graph: dict = {"nodes": [], "edges": []}
        self.bookkeeping: dict = {
            "offsets": {},
            "goal": {"text": "", "updated_round": 0},
            "handoff": "",
            "config": {},
            "intel": [],
        }
        self.legacy_archived: str | None = None     # 旧板归档路径（v2 遗形自动改名）
        if path and os.path.isfile(path):
            self._load()

    # ── 属性捷径 ───────────────────────────────────────────────────────
    @property
    def offsets(self) -> dict:
        return self.bookkeeping["offsets"]

    @property
    def goal(self) -> dict:
        return self.bookkeeping["goal"]

    # ── 持久化：原子写 + fsync + .bak 回退 + 旧板归档 ──────────────────
    def _load(self) -> None:
        data = self._read_v3(self.path)
        if data is None and self.path:
            data = self._read_v3(self.path + ".bak")     # 主文件写坏 → 回退上一份好的
        if not data:
            return
        self.graph = {"nodes": list(data["graph"].get("nodes", [])),
                      "edges": list(data["graph"].get("edges", []))}
        bk = data.get("bookkeeping", {})
        self.bookkeeping = {
            "offsets": bk.get("offsets", {}),
            "goal": bk.get("goal", {"text": "", "updated_round": 0}),
            "handoff": bk.get("handoff", ""),
            "config": bk.get("config", {}),
            "intel": bk.get("intel", []),
        }

    def _read_v3(self, p) -> Optional[dict]:
        """读一个 v3 形状的黑板文件；v2 遗形（无 graph 键）→ 归档改名 + 空板起步。"""
        if not p or not os.path.isfile(p):
            return None
        try:
            data = json.load(open(p, encoding="utf-8"))
        except Exception:
            return None                                   # JSON 坏：不归档（留给 .bak 回退）
        if not isinstance(data, dict) or "graph" not in data:
            try:
                os.replace(p, p + ".v2-legacy.json")
                self.legacy_archived = p + ".v2-legacy.json"
            except OSError:
                pass
            return None
        return data

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            snapshot = {"graph": self.graph, "bookkeeping": self.bookkeeping}
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            if os.path.isfile(self.path):
                os.replace(self.path, self.path + ".bak")   # 留上一份好的
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)                       # 原子落位
        except Exception:
            pass

    # ── 三原子操作（schema §6.1，controller 独占） ─────────────────────
    def create_node(self, kind: str, payload: dict, *, endpoint: str = "global",
                    origin: str, round: int = 0, id: str | None = None) -> str:
        """建节点并发号（D-###/F-###/T-###）。去重键 (kind, endpoint, 归一化内容)
        命中 → 幂等返回已有 id（不变量 5）。worker 自报 id 冲突 → 重编号
        `{prefix}-R{round}-{orig}`（不变量 6），再冲突 → 顺位新号。"""
        if kind not in KINDS:
            raise ValueError(f"非法 kind：{kind}")
        if origin not in NODE_ORIGINS:
            raise ValueError(f"非法 origin：{origin}")
        payload = self._sanitize_payload(kind, payload)
        if not payload.get(_PAYLOAD_REQUIRED[kind]):
            raise ValueError(f"{kind} payload 缺必填 {_PAYLOAD_REQUIRED[kind]}")
        endpoint = str(endpoint or "global").strip() or "global"
        with self._lock:
            key = (kind, _norm_text(endpoint), _norm_text(payload[_PAYLOAD_REQUIRED[kind]]))
            for n in self.graph["nodes"]:
                if (n["kind"], _norm_text(n["endpoint"]),
                        _norm_text(n["payload"].get(_PAYLOAD_REQUIRED[kind], ""))) == key:
                    return n["id"]                        # 幂等：同内容不重复建
            nid = self._alloc_id(kind, id, round)
            node = {"id": nid, "kind": kind, "state": self._initial_state(kind),
                    "payload": payload, "endpoint": endpoint, "origin": origin,
                    "round": int(round), "updated_at": _now_iso()}
            self.graph["nodes"].append(node)
            return nid

    def update_node(self, id: str, *, state: str | None = None,
                    payload_patch: dict | None = None, comment: str | None = None) -> bool:
        """状态迁移 / payload 补丁 / 观察者批注。机械不变量：
        - finding/fact → confirmed/dismissed 仅从 proposed（verdict 不翻案，不变量 3）
        - fact → superseded 仅从 confirmed"""
        with self._lock:
            node = self._get(id)
            if node is None:
                return False
            kind = node["kind"]
            if state is not None:
                if state not in STATES[kind]:
                    return False
                if state != node["state"]:
                    if kind in ("finding", "fact") and state in ("confirmed", "dismissed") \
                            and node["state"] != "proposed":
                        return False                    # 不变量 3
                    if kind == "fact" and state == "superseded" and node["state"] != "confirmed":
                        return False
                node["state"] = state
            if payload_patch:
                node["payload"].update(self._sanitize_payload(kind, payload_patch))
            if comment is not None:
                node["payload"]["comment"] = str(comment).strip()[:300]
            node["updated_at"] = _now_iso()
            return True

    def add_edge(self, src: str, rel: str, dst: str, *, origin: str,
                 note: str = "", round: int = 0) -> bool:
        """建边（(src,rel,dst) 去重——声明优先，已存在返回 False，不变量 4）。"""
        if rel not in RELS:
            raise ValueError(f"非法 rel：{rel}")
        if origin not in EDGE_ORIGINS:
            raise ValueError(f"非法边 origin：{origin}")
        with self._lock:
            for e in self.graph["edges"]:
                if (e["src"], e["rel"], e["dst"]) == (src, rel, dst):
                    return False
            self.graph["edges"].append({
                "src": src, "rel": rel, "dst": dst, "origin": origin,
                "note": str(note or "").strip()[:300], "round": int(round)})
            return True

    # ── 三原子内部件 ───────────────────────────────────────────────────
    @staticmethod
    def _initial_state(kind: str) -> str:
        return {"intent": "open", "finding": "proposed", "fact": "proposed"}[kind]

    def _alloc_id(self, kind: str, hint: str | None, round: int) -> str:
        prefix = KIND_PREFIX[kind]
        ids = {n["id"] for n in self.graph["nodes"]}
        if hint:
            hint = str(hint).strip()
            if hint.startswith(prefix + "-"):
                if hint not in ids:
                    return hint
                renum = f"{prefix}-R{round}-{hint}"
                if renum not in ids:
                    return renum                         # 不变量 6：冲突重编号
        n = 1
        while f"{prefix}-{n:03d}" in ids:
            n += 1
        return f"{prefix}-{n:03d}"

    def _get(self, id: str) -> Optional[dict]:
        for n in self.graph["nodes"]:
            if n["id"] == id:
                return n
        return None

    @staticmethod
    def _sanitize_payload(kind: str, payload: dict) -> dict:
        """白名单滤键 + 截长 + severity 枚举校验（schema additionalProperties:false 的写半边）。"""
        out: dict = {}
        fields = _PAYLOAD_FIELDS[kind]
        for k, cap in fields.items():
            if k not in payload or payload[k] is None:
                continue
            v = str(payload[k]).strip()[:cap]
            if k == "severity" and v not in _SEVERITIES:
                continue
            if v:
                out[k] = v
        return out

    # ── 查询 ───────────────────────────────────────────────────────────
    def node(self, id: str) -> Optional[dict]:
        return self._get(id)

    def nodes(self, kind: str | None = None, state: str | None = None,
              endpoint: str | None = None) -> list[dict]:
        out = [n for n in self.graph["nodes"]
               if (kind is None or n["kind"] == kind)
               and (state is None or n["state"] == state)
               and (endpoint is None or _norm_text(n["endpoint"]) == _norm_text(endpoint))]
        return sorted(out, key=lambda n: n["id"])

    def edges(self, rel: str | None = None, src: str | None = None,
              dst: str | None = None) -> list[dict]:
        return [e for e in self.graph["edges"]
                if (rel is None or e["rel"] == rel)
                and (src is None or e["src"] == src)
                and (dst is None or e["dst"] == dst)]

    def fact_values(self) -> list[str]:
        """全图 fact 值（T4.2 路由燃料：全值扫描，不再按 kind=fingerprint 查）。"""
        return [n["payload"]["value"] for n in self.nodes("fact")]

    def confirmed_findings(self) -> list[dict]:
        return self.nodes("finding", state="confirmed")

    def active_intents(self) -> list[dict]:
        """open/in_progress/blocked 方向，in_progress 最先（干到一半的接力价值最高）。"""
        order = {"in_progress": 0, "open": 1, "blocked": 2}
        act = [n for n in self.graph["nodes"]
               if n["kind"] == "intent" and n["state"] in order]
        return sorted(act, key=lambda n: (order[n["state"]], n["id"]))

    def intent_counts(self) -> dict:
        out = {s: 0 for s in INTENT_STATES}
        for n in self.graph["nodes"]:
            if n["kind"] == "intent":
                out[n["state"]] = out.get(n["state"], 0) + 1
        return out

    def summarize(self, round_: int = 0) -> str:
        """紧凑摘要（prompt 摘要段 / 观察者 board_summary 共用）：计数+待接方向+欠账指路。
        纯图现算（四视图派生）；确定性——同图两次调用逐字节相同。"""
        c = self.intent_counts()
        neg = self.negative_view()
        un = self.untested_surface()
        lines = [f"第 {round_} 轮｜方向 open {c['open']}/进行中 {c['in_progress']}"
                 f"/blocked {c['blocked']}/done {c['done']}；"
                 f"已确认发现 {len(self.confirmed_findings())} 条；"
                 f"阴性 {len(neg)} 条；未测面 {len(un)} 个（目标：清零）"]
        pending = self.active_intents()
        if pending:
            lines.append("待接方向（接手优先于开新方向）：")
            for d in pending[:8]:
                p = d["payload"]
                src = "（观察者建议）" if d["origin"] == "observer" else ""
                lines.append(f"- [{d['id']}] ({d['state']}) {p.get('goal', '')}"
                             f" — {p.get('note', '')}{src}")
        lines.append("（欠账全文——方向谱系/阴性/端点分组/事实——见本目录 STATE.md）")
        return "\n".join(lines)

    # ── 四派生视图（schema §5，零存储现算） ────────────────────────────
    def negative_view(self) -> list[dict]:
        """阴性：intent(done ∧ 无 yields 出边，死因=note) ∪ finding(dismissed，死因=reason)。"""
        rows: list[dict] = []
        yields_srcs = {e["src"] for e in self.graph["edges"] if e["rel"] == "yields"}
        for n in self.graph["nodes"]:
            if n["kind"] == "intent" and n["state"] == "done" and n["id"] not in yields_srcs:
                rows.append({"kind": "intent", "id": n["id"], "endpoint": n["endpoint"],
                             "reason": n["payload"].get("note") or n["payload"].get("goal", "")})
            elif n["kind"] == "finding" and n["state"] == "dismissed":
                rows.append({"kind": "finding", "id": n["id"], "endpoint": n["endpoint"],
                             "reason": n["payload"].get("reason", "")})
        return rows

    def endpoint_groups(self) -> dict[str, list[dict]]:
        """端点分组（global 桶不进——全局认知单列，schema §8）。"""
        groups: dict[str, list[dict]] = {}
        for n in sorted(self.graph["nodes"], key=lambda x: x["id"]):
            if n["endpoint"] and n["endpoint"] != "global":
                groups.setdefault(n["endpoint"], []).append(n)
        return groups

    def lineage_view(self) -> dict[str, dict]:
        """谱系：每节点 parentsOf（指入边源）+ yieldsOf（指出边目标）。"""
        lin = {n["id"]: {"parents": [], "yields": []} for n in self.graph["nodes"]}
        for e in self.graph["edges"]:
            if e["dst"] in lin:
                lin[e["dst"]]["parents"].append(e["src"])
            if e["src"] in lin:
                lin[e["src"]]["yields"].append(e["dst"])
        return lin

    def untested_surface(self) -> list[str]:
        """未测面：出现过的 endpoint − 有 intent/finding 覆盖的 endpoint（判停分母/路标）。"""
        covered = {n["endpoint"] for n in self.graph["nodes"] if n["kind"] in ("intent", "finding")}
        seen = {n["endpoint"] for n in self.graph["nodes"]
                if n["endpoint"] and n["endpoint"] != "global"}
        return sorted(seen - covered)

    # ── goal / Stop（T1.5；判停三角=预算+人工停+worker 有效 Stop） ──────
    def set_goal(self, text: str, round: int = 0) -> None:
        """任务级 goal（A24：控制台 goal-set 的底层；worker <Stop> 自停锚点）。"""
        self.bookkeeping["goal"] = {"text": str(text or "").strip()[:500],
                                    "updated_round": int(round)}

    def parse_stop(self, text: str) -> Optional[dict]:
        """解析含 <Stop>…</Stop> 标记的原文；无标记 → None（不是停机尝试）。"""
        if not text:
            return None
        m = re.search(r"<Stop>(.*?)</Stop>", str(text), re.DOTALL | re.IGNORECASE)
        if not m:
            return None
        return self.validate_stop_content(m.group(1).strip())

    def validate_stop_content(self, content: str) -> Optional[dict]:
        """校验已抽取的 Stop 内容（runner.extract_stop 的产物，A18 双理由自停）。
        - 达成型：必须引证现存 finding id（F-xxx），无引证/引证不存在 → None（无效）
        - 测尽型（内容含"测尽"）：理由 ≥6 字即可，无需引证
        返回 {"kind": "achieved"|"exhausted", "reason", "refs":[有效 F-xxx]} 或 None。"""
        content = (content or "").strip()
        if not content:
            return None
        refs = []
        for r in re.findall(r"\bF-[A-Za-z0-9\-]+", content):
            n = self._get(r)
            if n is not None and n["kind"] == "finding" and r not in refs:
                refs.append(r)
        if "测尽" in content:
            if len(content) < 6:
                return None
            return {"kind": "exhausted", "reason": content[:500], "refs": refs}
        if not refs:
            return None                                  # 引证护栏：无有效 F-xxx = 无效 Stop
        return {"kind": "achieved", "reason": content[:500], "refs": refs}

    # ── Handoff / 证词 ─────────────────────────────────────────────────
    def record_handoff(self, text: str) -> None:
        """worker 轮末交接（A19：读者=观察者，住 STATE.md，不进 stdin）。"""
        self.bookkeeping["handoff"] = (text or "").strip()

    def add_intel(self, text: str, round: int = 0) -> None:
        """观察者证词追加（schema §1 bookkeeping.intel 按轮）。"""
        t = str(text or "").strip()
        if t:
            self.bookkeeping["intel"].append({"round": int(round), "text": t[:600]})
