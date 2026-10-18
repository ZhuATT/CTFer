"""json_utils 单测（P4.11 自 test_verify.py 迁出）——parse_llm_json 三层剥取。"""

from src.json_utils import parse_llm_json


def test_parse_llm_json_three_layers():
    assert parse_llm_json('{"refuted": true, "reason": "x"}')["refuted"] is True
    assert parse_llm_json('```json\n{"refuted": false}\n```')["refuted"] is False
    assert parse_llm_json('我认为不对。\n{"refuted": true, "reason": "buyer=userA"} 就这些')["refuted"] is True
    assert parse_llm_json("完全是废话没有结构") is None


def test_parse_llm_json_mixed_prose_and_json():
    # 观察者 prompt 常见的"一句说明 + JSON"形态
    d = parse_llm_json('已判定：{"is_vulnerability": true, "severity": "high", "reason": "越权"}')
    assert d["is_vulnerability"] is True and d["severity"] == "high"


def test_parse_llm_json_greedy_multi_block_returns_none():
    # 正则 \{.*\} 贪婪：跨多个 JSON 块匹配 → json.loads 失败 → None（未定义行为，不保证）
    assert parse_llm_json('{"a": 1} 然后 {"b": 2}') is None
