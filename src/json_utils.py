"""AT1 json_utils —— LLM 输出的 JSON 容错解析（P4.11 自 verify.py 迁出）。

verify.py 旧四门漏斗整体删除后，observer 仍依赖 parse_llm_json 的"三层剥取"。
本模块是它唯一的存活出口（vendor 自 hxbai，原样保留）。
"""

from __future__ import annotations

import json
import re
from typing import Optional

_JSON_RX = re.compile(r"\{.*\}", re.DOTALL)


def parse_llm_json(text: str) -> Optional[dict]:
    """三层剥取（vendor 自 hxbai）：整段 → 去栅栏 → 正则抠块。"""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t)
    for cand in (text, t):
        try:
            d = json.loads(cand)
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    m = _JSON_RX.search(text)
    if not m:
        return None
    frag = m.group(0)
    for cand in (frag, frag[: frag.rfind("}") + 1]):
        try:
            d = json.loads(cand)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None
