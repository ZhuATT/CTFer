"""AT1 transcript_check —— 证据的 transcript 双向对账（P4.4 → phase5 C-5 v2，2026-09-04 定稿）。

观察者架构的事实层物理锚：transcript 是 worker 摸不到（.at1/ 隔离）的**账本**，
evidence 是 worker 的一组**可查账的 claim**；验证 = 账本查询（字节比对，零 LLM）。

对账两侧（C-5 v2）：
- 请求侧（原有+增强）：完整 URL / method+路径 / 引号 api 路径锚定 → 命中后进一步
  逐参数值对账（`?id=8823` → 查 "8823"；整 URL 不中才降级逐参数——防命令重排/编码差异误杀）
- 响应侧（★新增）：evidence 响应段抽高信号 token（≥4 位纯数字/含字母数字混合 ≥6 字符，
  滤 HTTP 状态码），逐个查账——"B 的手机号 139…" 从未出现在任何真实工具输出 = 响应是编的

判定：
- evidence_verified（硬线）：请求锚命中（原语义）；**双侧全空**（路径中但参数与响应
  关键串全不中）→ false——该形态即编造
- param_verified / response_verified（软标记）：部分未中 → false 标记 + 命中计数，
  如实进判官 prompt 作加权数据（不硬杀：URL 编码/重排版有误杀空间）

锚定提取（实测教训：白话证据通常写相对路径 `GET /search?q=%27`，没有完整 URL）。
匹配：transcript 逐行 json.loads 后递归抽字符串值拼解码文本（phase3 附录 D：原始
字节 grep 会假阴性），规范化（压空白+小写）+ URL-decode 双形态子串匹配。
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import unquote

_EVIDENCE_URL_RX = re.compile(r"https?://[^\s\"'`<>)\]}]+", re.IGNORECASE)
# method + 路径（白话证据形态：`GET /search?q=%27`、`POST /admin/config/update`）
_EVIDENCE_METHOD_PATH_RX = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+([/][^\s\"'`<>)]+)", re.IGNORECASE)
# 引号/反引号包裹的 api 形态路径（`"/api/order/detail"`、`/admin/config`）
_EVIDENCE_QUOTED_PATH_RX = re.compile(
    r"[/](?:api|admin|search|redirect|internal|static|order|address|user|config|upload|login|debug)"
    r"[A-Za-z0-9_?=&.%'~{}/:*-]*", re.IGNORECASE)

# 响应段定位：## 响应 / 响应：/ **响应（evidence 模板 §3.4.4 有段头；白话证据兜底全文）
_RESPONSE_SECTION_RX = re.compile(r"(?:^|\n)\s*(?:#+\s*|\**)?响\s*应\s*[：:\n]", re.IGNORECASE)
_NEXT_SECTION_RX = re.compile(r"\n\s*#{1,3}\s|\*\*佐证", re.IGNORECASE)

# 高信号 token：纯数字 ≥4 位（手机号/订单号/id）；字母数字混合 ≥6 字符（工号/凭证形状/哈希）
_DIGIT_TOKEN_RX = re.compile(r"\d{4,}")
_MIXED_TOKEN_RX = re.compile(r"(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{6,}")
_STATUS_CODES = {"200", "201", "204", "301", "302", "303", "304", "400", "401", "403",
                 "404", "405", "409", "422", "429", "500", "502", "503"}
_TOKEN_NOISE = {"true", "false", "null", "none", "undefined"}
_RESPONSE_TOKEN_CAP = 10

# 参数值噪声：太短/布尔类
_PARAM_NOISE = {"0", "1", "true", "false", "null", "none"}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _strings_of(obj, out: list) -> None:
    """递归抽取 JSON 对象里的全部字符串值。"""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _strings_of(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _strings_of(v, out)


def _transcript_hays(transcript_path: str, start_offset: int = 0) -> tuple[str, str]:
    """账本双形态解码文本：(原文规范化, URL-decode 后规范化)。
    逐行 json.loads 后拼字符串值（防转义假阴性）；decode 形态防 evidence 写明文、
    账本记编码（q=' vs q=%27）的假阴性。
    start_offset > 0 时只读该字节之后的窗口（治理批#2：轮窗复现抽验——
    transcript 跨轮追加，整卷查"出现过"对被动事实永远为真）。"""
    parts: list[str] = []
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            if start_offset > 0:
                f.seek(start_offset)
                f.readline()                     # 丢弃半行（偏移可能落在行中间）
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if isinstance(ev, dict):
                    _strings_of(ev, parts)
    except OSError:
        return "", ""
    joined = " \n ".join(parts)
    return _norm(joined), _norm(unquote(joined))


def _evidence_anchors(evidence_text: str) -> list[str]:
    """从证据提取请求侧锚定串：完整 URL + method+路径 + 引号 api 路径。去尾标点去重。"""
    anchors: set[str] = set()
    for m in _EVIDENCE_URL_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    for m in _EVIDENCE_METHOD_PATH_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    for m in _EVIDENCE_QUOTED_PATH_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    return sorted(anchors)


def _param_values(anchors: list[str]) -> list[str]:
    """从请求锚定串抽 query 参数值：`?a=1&id=8823` → ["1"→滤掉, "8823"]。"""
    out: list[str] = []
    for a in anchors:
        if "?" not in a:
            continue
        query = a.split("?", 1)[1]
        for kv in query.split("&"):
            if "=" not in kv:
                continue
            v = kv.split("=", 1)[1].strip()
            if len(v) >= 3 and v.lower() not in _PARAM_NOISE:
                out.append(v)
    # 去重保序
    seen, dedup = set(), []
    for v in out:
        k = v.lower()
        if k not in seen:
            seen.add(k)
            dedup.append(v)
    return dedup


def _response_section(evidence_text: str) -> str:
    """evidence 响应段：有段头取段内（到下一段头）；白话无段头 → 全文兜底。"""
    m = _RESPONSE_SECTION_RX.search(evidence_text)
    if not m:
        return evidence_text
    rest = evidence_text[m.end():]
    m2 = _NEXT_SECTION_RX.search(rest)
    return rest[:m2.start()] if m2 else rest


def _response_tokens(evidence_text: str) -> list[str]:
    """响应段高信号 token：纯数字 ≥4（滤状态码）+ 字母数字混合 ≥6。cap 10，按出现序。"""
    section = _response_section(evidence_text)
    tokens: list[str] = []
    for m in _DIGIT_TOKEN_RX.findall(section):
        if m not in _STATUS_CODES:
            tokens.append(m)
    tokens.extend(_MIXED_TOKEN_RX.findall(section))
    seen, dedup = set(), []
    for t in tokens:
        k = _norm(t)
        if len(k) >= 4 and k not in _STATUS_CODES and k not in _TOKEN_NOISE and k not in seen:
            seen.add(k)
            dedup.append(k)
    return dedup[:_RESPONSE_TOKEN_CAP]


def _hit(needle: str, hays: tuple[str, str]) -> bool:
    n = _norm(needle)
    n_uq = _norm(unquote(needle))
    return (len(n) >= 3 and (n in hays[0] or n in hays[1])) or \
           (len(n_uq) >= 3 and (n_uq in hays[0] or n_uq in hays[1]))


def verify_evidence_detailed(transcript_path: str, evidence_text: str) -> dict:
    """C-5 v2 双向对账。返回：
    {evidence_verified, param_hits, param_total, response_hits, response_total,
     param_verified (True/False/None=未检), response_verified (True/False/None)}"""
    empty = {"evidence_verified": False, "param_hits": 0, "param_total": 0,
             "response_hits": 0, "response_total": 0,
             "param_verified": None, "response_verified": None}
    if not evidence_text or not os.path.isfile(transcript_path):
        return empty
    hays = _transcript_hays(transcript_path)
    if not hays[0]:
        return empty
    anchors = _evidence_anchors(evidence_text)
    # 请求侧硬判定用【去 query 的路径】（v1 锚连 query 一起抓，参数不同则整锚不中——
    # 把参数对账混进了路径判定；v2 分层：路径命中=请求发生过，参数另行对账）
    paths = sorted({a.split("?", 1)[0] for a in anchors})
    request_hit = any(len(p) >= 5 and _hit(p, hays) for p in paths)
    out = dict(empty)
    out["evidence_verified"] = request_hit

    # 请求侧参数对账（只在请求锚命中后才有意义）
    if request_hit:
        params = _param_values(anchors)
        out["param_total"] = len(params)
        out["param_hits"] = sum(1 for v in params if _hit(v, hays))
        out["param_verified"] = (out["param_hits"] == out["param_total"]) if params else None

    # 响应侧关键串对账
    r_tokens = _response_tokens(evidence_text)
    out["response_total"] = len(r_tokens)
    out["response_hits"] = sum(1 for t in r_tokens if _hit(t, hays))
    out["response_verified"] = (out["response_hits"] == out["response_total"]) if r_tokens else None

    # 硬线：路径中但双侧全空 = 编造形态 → 整体降 false
    if request_hit and out["param_total"] > 0 and out["param_hits"] == 0 \
            and out["response_total"] > 0 and out["response_hits"] == 0:
        out["evidence_verified"] = False
    return out


def verify_evidence_in_transcript(transcript_path: str, evidence_text: str) -> bool:
    """兼容入口：只取对账的 evidence_verified 硬判定。"""
    return verify_evidence_detailed(transcript_path, evidence_text)["evidence_verified"]
