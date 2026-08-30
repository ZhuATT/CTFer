"""transcript_check 单测（P4.4）：真请求命中（含转义变体）/ 编造请求拒 / 无 URL 拒。"""

import json

from src.transcript_check import verify_evidence_in_transcript


def _write_transcript(tmp_path, tool_command: str):
    """模拟 runner transcript：tool_use 事件里带 curl 命令（JSON 转义形态）。"""
    tp = tmp_path / "transcript.jsonl"
    lines = [
        json.dumps({"type": "system", "subtype": "init", "session_id": "s1"}),
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash",
             "input": {"command": tool_command}}]}}),
        json.dumps({"type": "result", "subtype": "success", "num_turns": 2}),
    ]
    tp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(tp)


def test_real_request_found(tmp_path):
    tp = _write_transcript(tmp_path, 'curl -s "http://127.0.0.1:8790/search?q=1%27" -H "X: y"')
    ev = """# F-001 SQL 注入
## 请求
curl -s "http://127.0.0.1:8790/search?q=1%27"
## 响应
500 SQL syntax error
"""
    assert verify_evidence_in_transcript(tp, ev) is True


def test_fabricated_request_rejected(tmp_path):
    # evidence 声称的请求 URL 从未出现在 transcript → 编造
    tp = _write_transcript(tmp_path, "curl -s http://127.0.0.1:8790/real")
    ev = "curl -s http://10.0.0.99:9999/admin/secret（响应含 AKIA...）"
    assert verify_evidence_in_transcript(tp, ev) is False


def test_url_in_query_string_form_found(tmp_path):
    # URL 出现在 MCP browser 工具的 url 参数里（字符串值递归抽取）
    tp = tmp_path / "transcript.jsonl"
    tp.write_text(json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "id": "b1", "name": "mcp__playwright__browser_navigate",
         "input": {"url": "https://app.example.com/order/detail?id=8823"}}]}}) + "\n",
        encoding="utf-8")
    ev = "browser_navigate → https://app.example.com/order/detail?id=8823 返回 B 的手机号"
    assert verify_evidence_in_transcript(str(tp), ev) is True


def test_no_url_in_evidence(tmp_path):
    tp = _write_transcript(tmp_path, "curl -s http://x/")
    assert verify_evidence_in_transcript(tp, "响应里有个手机号 13800138000") is False


def test_missing_transcript(tmp_path):
    assert verify_evidence_in_transcript(str(tmp_path / "none.jsonl"), "http://a.com/") is False


def test_whitespace_normalized_match(tmp_path):
    # evidence 里 URL 换行断开（压空白后仍命中）
    tp = _write_transcript(tmp_path, "curl -s http://127.0.0.1:8790/api/v1/user?id=2")
    ev = "请求了 http://127.0.0.1:8790/api/v1/user?\nid=2"
    assert verify_evidence_in_transcript(tp, ev) is True


def test_relative_path_prose_evidence(tmp_path):
    """白话证据写相对路径（GET /search?q=%27），transcript 是全 URL → 子串命中。"""
    tp = _write_transcript(tmp_path, 'Invoke-WebRequest "http://127.0.0.1:8790/search?q=%27%20OR%20%271%27%3D%271"')
    ev = """# SQL 注入 — /search?q=
请求：`GET /search?q=%27`（即 q='）
响应：<h1>Debug</h1><p>error in your SQL syntax</p>"""
    assert verify_evidence_in_transcript(tp, ev) is True


def test_quoted_api_path_anchor(tmp_path):
    tp = _write_transcript(tmp_path, 'curl http://127.0.0.1:8790/api/order/detail?id=8823')
    ev = '端点 `/api/order/detail?id=8823` 返回了 B 的手机号'
    assert verify_evidence_in_transcript(tp, ev) is True


def test_short_anchor_noise_rejected(tmp_path):
    # 太短的锚（<5 字符）噪声大不匹配——证据只有 "GET /api" 这种
    tp = _write_transcript(tmp_path, "curl http://127.0.0.1:8790/anything")
    ev = "看了 GET /api 一眼"
    assert verify_evidence_in_transcript(tp, ev) is False
