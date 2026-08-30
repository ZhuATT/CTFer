"""AT1 transcript_check —— 证据的 transcript 定点比对（P4.4，phase3.5 §四）。

观察者架构的事实层物理锚：evidence 里的请求必须真实出现在 runner 独立记录的
transcript 里（worker 够不到 .at1/，伪造自洽 evidence 骗不过这一层）。

锚定提取（实测教训：白话证据通常写相对路径 `GET /search?q=%27`，没有完整 URL）：
- 完整 URL（https?://…）
- method+路径（`GET /api/order/detail?id=8823`、`POST /search?q=…`）
- 引号/反引号包裹的 api 形态路径（`"/api/order/detail"`）

匹配：transcript 逐行 json.loads 后递归抽所有字符串值拼成解码文本（命令里的
URL 在 JSON 里带 \\u/\\\" 转义，原始字节 grep 会假阴性——phase3 附录 D 教训），
规范化（压空白+小写）后做子串匹配——相对路径是 transcript 全 URL 的子串，天然命中。

锚定强度的诚实说明：路径级匹配防"完全编造的请求"（编造一个没打过的端点）；
同端点不同参数的伪造仍需观察者语义层把关。深度逐字节比对需结构化 evidence，
留观察者架构稳定后再议。
"""

from __future__ import annotations

import json
import os
import re

_EVIDENCE_URL_RX = re.compile(r"https?://[^\s\"'`<>)\]}]+", re.IGNORECASE)
# method + 路径（白话证据形态：`GET /search?q=%27`、`POST /admin/config/update`）
_EVIDENCE_METHOD_PATH_RX = re.compile(
    r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+([/][^\s\"'`<>)]+)", re.IGNORECASE)
# 引号/反引号包裹的 api 形态路径（`"/api/order/detail"`、`/admin/config`）
_EVIDENCE_QUOTED_PATH_RX = re.compile(
    r"[/](?:api|admin|search|redirect|internal|static|order|address|user|config|upload|login|debug)"
    r"[A-Za-z0-9_?=&.%'~{}/:*-]*", re.IGNORECASE)


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


def _transcript_decoded_text(transcript_path: str) -> str:
    """transcript 全文解码：逐行 json.loads 后拼字符串值（防转义假阴性）。"""
    parts: list[str] = []
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
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
        return ""
    return _norm(" \n ".join(parts))


def _evidence_anchors(evidence_text: str) -> list[str]:
    """从证据提取锚定串：完整 URL + method+路径 + 引号 api 路径。去尾标点去重。"""
    anchors: set[str] = set()
    for m in _EVIDENCE_URL_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    for m in _EVIDENCE_METHOD_PATH_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    for m in _EVIDENCE_QUOTED_PATH_RX.findall(evidence_text):
        anchors.add(m.rstrip(".,;:)」】"))
    return sorted(anchors)


def verify_evidence_in_transcript(transcript_path: str, evidence_text: str) -> bool:
    """evidence 里的请求是否出现在 transcript（worker 无法编辑的独立记录）。"""
    if not evidence_text or not os.path.isfile(transcript_path):
        return False
    anchors = _evidence_anchors(evidence_text)
    if not anchors:
        return False                       # 无可锚定请求特征
    hay = _transcript_decoded_text(transcript_path)
    if not hay:
        return False
    for a in anchors:
        if len(a) >= 5 and _norm(a) in hay:   # 短锚（如 /api）噪声大，≥5 字符才可信
            return True
    return False
