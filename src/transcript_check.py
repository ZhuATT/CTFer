"""AT1 transcript_check —— 证据的 transcript 定点比对（P4.4，phase3.5 §四）。

观察者架构的事实层物理锚：evidence 里的请求必须真实出现在 runner 独立记录的
transcript 里（worker 够不到 .at1/，伪造自洽 evidence 骗不过这一层）。

实现（宽松锚定）：
- evidence 是白话格式（A4 后无固定四段结构），提取其中的 URL 形状作为请求锚点
- transcript 逐行 json.loads 后递归抽取所有字符串值拼成解码文本——命令里的
  URL 在 JSON 里带 \\u/\\\" 转义，原始字节 grep 会假阴性（phase3 附录 D 教训）
- 规范化（压空白+小写）后子串匹配；任一 URL 命中 → True
- evidence 里没有任何 URL → False（没有可锚定的请求特征）

锚定强度的诚实说明：URL 级匹配防"完全编造的请求"；URL 相同但参数不同的
伪造仍需观察者语义层把关。深度逐字节比对需要结构化 evidence 格式，留观察者
架构稳定后再议。
"""

from __future__ import annotations

import json
import os
import re

_EVIDENCE_URL_RX = re.compile(r"https?://[^\s\"'`<>)\]}]+", re.IGNORECASE)


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


def verify_evidence_in_transcript(transcript_path: str, evidence_text: str) -> bool:
    """evidence 里的请求 URL 是否出现在 transcript（worker 无法编辑的独立记录）。"""
    if not evidence_text or not os.path.isfile(transcript_path):
        return False
    urls = [u.rstrip(".,;:") for u in _EVIDENCE_URL_RX.findall(evidence_text)]
    if not urls:
        return False                       # 无可锚定请求特征
    hay = _transcript_decoded_text(transcript_path)
    if not hay:
        return False
    for u in urls:
        if _norm(u) in hay:
            return True
    return False
