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


# ── phase5 C-5 v2：双向对账（参数侧 + 响应侧 + 硬线） ─────────────────────

from src.transcript_check import verify_evidence_detailed


def _write_transcript_with_output(tmp_path, command: str, output: str):
    """带 tool_result 的 transcript：命令 + 真实输出（响应侧对账的账源）。"""
    tp = tmp_path / "transcript.jsonl"
    lines = [
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "id": "t1", "name": "Bash",
             "input": {"command": command}}]}}),
        json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": output}]}]}}),
    ]
    tp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(tp)


def test_param_fabrication_flagged(tmp_path):
    """①参数伪造（掺半诚实：响应有真内容、参数是编的）→ param_verified=False 软标记。
    注：参数与响应关键串【双侧全空】的纯编造形态走硬线（见 test_both_sides_empty_hard_false）。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl http://t/api/order/detail?id=100",
        '{"order":100,"phone":"13900001111"}')
    ev = """## 请求
GET /api/order/detail?id=8823
## 响应
{"phone":"13900001111"}"""                         # 手机号是真的（在账），id 是编的
    r = verify_evidence_detailed(tp, ev)
    assert r["evidence_verified"] is True          # 路径命中 + 响应有关键串在账 → 不触硬线
    assert r["param_total"] == 1 and r["param_hits"] == 0
    assert r["param_verified"] is False            # 软标记：参数未在账
    assert r["response_verified"] is True          # 真手机号在账


def test_response_fabrication_flagged(tmp_path):
    """③响应伪造：请求真发过，响应里的 PII 是编的 → response_verified=False。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl http://t/api/order/detail?id=8823",
        '{"order":8823,"status":"ok"}')            # 真响应里没有手机号
    ev = """## 请求
GET /api/order/detail?id=8823
## 响应
{"order":8823,"phone":"13911112222","name":"zhangsan"}"""
    r = verify_evidence_detailed(tp, ev)
    assert r["param_verified"] is True             # 8823 真在账
    assert r["response_hits"] < r["response_total"]
    assert r["response_verified"] is False         # 编造的手机号不在账


def test_all_clear_when_honest(tmp_path):
    """诚实证据：请求参数与响应关键串都在账 → 双 verified=True。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl http://t/api/order/detail?id=8823",
        '{"order":8823,"phone":"13900001111"}')
    ev = """## 请求
GET /api/order/detail?id=8823
## 响应
{"order":8823,"phone":"13900001111"}"""
    r = verify_evidence_detailed(tp, ev)
    assert r["evidence_verified"] and r["param_verified"] and r["response_verified"]


def test_both_sides_empty_hard_false(tmp_path):
    """④硬线：路径中但参数与响应关键串全不中 → evidence_verified=False（编造形态）。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl http://t/api/order/detail?id=100",
        '{"order":100,"status":"ok"}')
    ev = """## 请求
GET /api/order/detail?id=8823
## 响应
{"order":8823,"phone":"13900002222"}"""
    r = verify_evidence_detailed(tp, ev)
    assert r["evidence_verified"] is False         # 硬降


def test_url_encoded_variant_hits(tmp_path):
    """⑤编码变体：evidence 明文 q='，账本 %27 → decode 形态命中。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl 'http://t/search?q=%27%20OR%201%3D1'",
        "500 SQL syntax error")
    ev = """## 请求
GET /search?q=' OR 1=1
## 响应
500 SQL syntax error"""
    r = verify_evidence_detailed(tp, ev)
    assert r["evidence_verified"] is True


def test_prose_evidence_without_sections_unchanged(tmp_path):
    """⑥白话证据（无段头无参数无长 token）→ 行为与 v1 一致，软标记不误报。"""
    tp = _write_transcript_with_output(
        tmp_path, "curl http://t/search?q=1", "SQL syntax error")
    ev = "GET /search?q=1 返回了 SQL 报错"
    r = verify_evidence_detailed(tp, ev)
    assert r["evidence_verified"] is True
    assert r["param_total"] == 0                    # q=1 值"1"太短被滤 → 无参数可对账
    assert r["param_verified"] is None
    assert r["response_total"] == 0                 # "SQL"无数字混合 → 无关键串 → None 软标记
    assert r["response_verified"] is None


def test_anchor_note_rendering():
    """观察者侧：对账结果如实渲染（含缺省诚实化）。"""
    from src.observer import _anchor_note
    assert "未执行" in _anchor_note({})                                    # 无对账数据不谎称通过
    assert "未在账上出现" in _anchor_note({"evidence_verified": False})
    assert "请求参数未全部在账" in _anchor_note(
        {"evidence_verified": True, "param_verified": False, "param_hits": "0/1"})
    assert "响应关键串未全部在账" in _anchor_note(
        {"evidence_verified": True, "param_verified": True,
         "response_verified": False, "response_hits": "1/2"})
    assert "均在账" in _anchor_note({"evidence_verified": True,
                                     "param_verified": True, "response_verified": True})
