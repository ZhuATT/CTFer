"""verify 单测：七案 + 每类正负例 + 解析容错。不调真 LLM（gate2 用 mock）。"""

import json
from pathlib import Path

import pytest

from src.verify import (Claim, parse_claim, parse_evidence, parse_llm_json,
                        gate1, gate2, gate3, verify_claims)


# ── 构造工具 ────────────────────────────────────────────────────────────────
def _ev(request="", response="", support="", provenance=""):
    parts = []
    if request:
        parts.append(f"## 请求\n{request}")
    if response:
        parts.append(f"## 响应\n{response}")
    if support:
        parts.append(f"## 佐证\n{support}")
    if provenance:
        parts.append(f"## 时间与来源命令\n{provenance}")
    return "\n\n".join(parts)


def _claim(**kw):
    base = dict(id="F-001", klass="idor_read", endpoint="/api/order/detail",
                as_identity="userA", owner_identity="userB", marker="13800000000",
                marker_source="evidence/b.md", evidence="evidence/a.md",
                expect="", distinct_from="首条", round=1)
    base.update(kw)
    return Claim(**base)


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)


MOCK_PASS = lambda msgs: '{"refuted": false, "reason": "通过：无反驳依据"}'
MOCK_REFUTE = lambda msgs: '{"refuted": true, "reason": "否决：响应 buyer=userA（依据：响应第2行）"}'


# ── 七案 ────────────────────────────────────────────────────────────────────
def _setup_seven(tmp_path, case):
    """返回 (claims, workdir, transcript_path, gate2_fn)"""
    marker = "13800000000"
    resp = json.dumps({"order_id": 8823, "buyer": "userA" if case == "shared" else "userC",
                       "receiver_phone": marker})
    req = 'curl -s -H "Cookie: sid=A" https://t.example/api/order/detail?id=8823'
    if case == "fabricate":
        req = "curl -s https://never-ran.example/ghost"          # 不写进 transcript
    ev = _ev(request=req, response="HTTP/1.1 200 OK\n\n" + resp,
             provenance="2026-08-26T10:00:00Z | " + req)
    ms = _ev(response=f"userB 资料页快照：手机号 {marker}，uid=20001")

    _write(tmp_path, "evidence/a.md", ev)
    _write(tmp_path, "evidence/b.md", ms)
    transcript = tmp_path / "transcript.jsonl"
    lines = [json.dumps({"type": "user", "message": {"content": [
        {"type": "tool_result", "content": [
            {"type": "text", "text": "…"}]}]}})]
    if case != "fabricate":
        lines.insert(0, json.dumps({"command": req, "tool": "Bash"}))
    transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")

    g2 = MOCK_REFUTE if case == "shared" else MOCK_PASS
    return [_claim()], str(tmp_path), str(transcript), g2


def test_case1_forged_marker(tmp_path):
    # ①伪造：marker 不在响应原文 → 门1 拒
    ev = _ev(response="HTTP/1.1 200 OK\n\n" + json.dumps({"data": "nothing here"}))
    ms = _ev(response="userB 手机号 13800000000")
    v = gate1(_claim(), ev, ms)
    assert v.verdict == "rejected" and "不双点" in v.reasons[0]


def test_case2_forged_marker_source(tmp_path):
    # ②编造 marker_source：文件内容里没有 marker → 门1 拒（B 点不接地）
    ev = _ev(response="HTTP/1.1 200 OK\n\n13800000000")
    ms = _ev(response="userB 资料页（无手机号字段）")
    v = gate1(_claim(), ev, ms)
    assert v.verdict == "rejected"


def test_case3_real_double_grounding(tmp_path):
    # ③真实双点 → 过门1（中间态 pass）
    claims, wd, tp, g2 = _setup_seven(tmp_path, "real")
    v = gate1(claims[0], open(wd + "/evidence/a.md", encoding="utf-8").read(),
              open(wd + "/evidence/b.md", encoding="utf-8").read())
    assert v.verdict == "pass" and "双点接地" in v.reasons[0]


def test_case4_negative_oracle(tmp_path):
    # ④负 oracle：403 → 阴性记录（不是 rejected）；附录 C：载荷带 status/round
    ev = _ev(response="HTTP/1.1 403 Forbidden\n\n{\"msg\":\"denied\"}")
    v = gate1(_claim(round=3), ev, "")
    assert v.verdict == "immune"
    assert v.immune == {"endpoint": "/api/order/detail", "class": "idor_read",
                        "status": "403", "round": 3}


def test_case5_shared_address_full_funnel(tmp_path):
    # ⑤共享地址：门1 过、门2 refuted → rejected
    claims, wd, tp, g2 = _setup_seven(tmp_path, "shared")
    vs = verify_claims(claims, wd, tp, gate2_fn=g2)
    assert vs[0].verdict == "rejected" and "buyer=userA" in vs[0].reasons[0]


def test_case6_true_idor_confirmed(tmp_path):
    # ⑥真 idor：全链 → confirmed
    claims, wd, tp, g2 = _setup_seven(tmp_path, "real")
    vs = verify_claims(claims, wd, tp, gate2_fn=g2)
    assert vs[0].verdict == "confirmed" and vs[0].confidence == 0.9
    assert any("gate3" in r for r in vs[0].reasons)


def test_case7_whole_fabrication(tmp_path):
    # ⑦整体虚构：三件套自洽、门2 放行、但请求不在 transcript → 门3 杀
    claims, wd, tp, g2 = _setup_seven(tmp_path, "fabricate")
    v1 = gate1(claims[0], open(wd + "/evidence/a.md", encoding="utf-8").read(),
               open(wd + "/evidence/b.md", encoding="utf-8").read())
    assert v1.verdict == "pass"                                   # 门1 确实被骗过
    vs = verify_claims(claims, wd, tp, gate2_fn=g2)
    assert vs[0].verdict == "rejected" and "整体虚构" in vs[0].reasons[0]


# ── 每类正负例 ─────────────────────────────────────────────────────────────
def test_infoleak_positive_blacklist():
    c = _claim(klass="infoleak", marker="AKIAFAKEFAKEFAKEFAKE")
    ok = gate1(c, _ev(response="config: aws_key=AKIAFAKEFAKEFAKEFAKE"), "")
    assert ok.verdict == "pass"
    # instance-id 铁律
    v = gate1(_claim(klass="infoleak", marker="i-0abc123def456789a"),
              _ev(response="instance: i-0abc123def456789a"), "")
    assert v.verdict == "rejected" and "黑名单" in v.reasons[0]
    # 内网 IP 铁律
    v2 = gate1(_claim(klass="infoleak", marker="172.16.0.85"),
               _ev(response="backend: 172.16.0.85"), "")
    assert v2.verdict == "rejected"


def test_infoleak_placeholder():
    v = gate1(_claim(klass="infoleak", marker="sk-REDACTEDPLACEHOLDER00"),
              _ev(response="key: sk-REDACTEDPLACEHOLDER00"), "")
    assert v.verdict == "rejected" and "占位符" in v.reasons[0]


def test_sqli_error_and_diff():
    ok = gate1(_claim(klass="sqli_error"), _ev(response="err: You have an error in your SQL syntax"), "")
    assert ok.verdict == "pass"
    bad = gate1(_claim(klass="sqli_error"), _ev(response="500 Internal Server Error"), "")
    assert bad.verdict == "rejected"
    okd = gate1(_claim(klass="sqli_diff"), _ev(response="[baseline] id=1 -> 2 rows\n[attack] id=1' -> 1 row"), "")
    assert okd.verdict == "pass"
    badd = gate1(_claim(klass="sqli_diff"), _ev(response="id=1 -> 2 rows"), "")
    assert badd.verdict == "rejected"


def test_ssrf_uxxe_lfi_xss():
    assert gate1(_claim(klass="ssrf"), _ev(response="OOB hit: dnslog.x received from 10.2.3.4"), "").verdict == "pass"
    assert gate1(_claim(klass="ssrf"), _ev(response="404 not found"), "").verdict == "rejected"
    assert gate1(_claim(klass="lfi"), _ev(response="root:x:0:0:root:/root:/bin/bash"), "").verdict == "pass"
    assert gate1(_claim(klass="xxe"), _ev(response="root:x:0:0:root"), "").verdict == "pass"
    assert gate1(_claim(klass="xss", marker="<svg/onload=at1xss>"),
                 _ev(response="<div><svg/onload=at1xss></div>"), "").verdict == "pass"
    assert gate1(_claim(klass="xss", marker="<svg/onload=at1xss>"),
                 _ev(response="<div>safe</div>"), "").verdict == "rejected"


def test_idor_write_readback():
    ok = gate1(_claim(klass="idor_write", expect="\"code\":0"),
               _ev(response="HTTP/1.1 200\n\n{\"code\":0}\n复查：GET /api/address → 手机号已改为 13900000000"), "")
    assert ok.verdict == "pass"
    bad = gate1(_claim(klass="idor_write", expect="\"code\":0"),
                _ev(response="HTTP/1.1 200\n\n{\"code\":0}"), "")
    assert bad.verdict == "rejected" and "读回" in bad.reasons[0]


def test_logic_race():
    ok = gate1(_claim(klass="logic_race"),
               _ev(response="before: 余额=100\nafter: 余额=99.9（两次并发各扣 0.05×2）"), "")
    assert ok.verdict == "pass"
    bad = gate1(_claim(klass="logic_race"), _ev(response="after: 余额=99.9"), "")
    assert bad.verdict == "rejected"


def test_authbypass_403():
    # 语义定论：authbypass 证据显示 403 = 口子是关的 → 负 oracle 免疫记录（防重测），
    # 比 rejected 更有价值（阴性结论）——原测试期望 rejected 是错的
    v = gate1(_claim(klass="authbypass"), _ev(response="HTTP/1.1 403\n"), "")
    assert v.verdict == "immune"
    assert v.immune["class"] == "authbypass" and v.immune["status"] == "403"


def test_gate2_rejected_carries_pattern():
    # 门2 语义否决 → Verdict.pattern（已否决模式载荷，M4 driver 入板）
    it = iter(['{"refuted": true, "reason": "否决：buyer=userA 属设计内行为"}'] * 3)
    v = gate2(_claim(round=5), _ev(), "", llm_chat=lambda m: next(it))
    assert v.verdict == "rejected"
    assert v.pattern == {"endpoint": "/api/order/detail", "class": "idor_read",
                         "reason_head": "否决：buyer=userA 属设计内行为", "round": 5}


def test_funnel_propagates_pattern(tmp_path):
    # 全链：⑤共享地址 → gate2 拒 → pattern 随 Verdict 返回（driver 写板）
    claims, wd, tp, g2 = _setup_seven(tmp_path, "shared")
    vs = verify_claims(claims, wd, tp, gate2_fn=g2)
    assert vs[0].verdict == "rejected" and vs[0].pattern is not None
    assert vs[0].pattern["class"] == "idor_read"


# ── 解析容错 ────────────────────────────────────────────────────────────────
def test_parse_claim_tolerant():
    c, err = parse_claim('﻿{"id":"F-1","class":"idor","endpoint":"/x","marker":"m",'
                         '"evidence":"e/a.md","distinct_from":"首条","round":2}')
    assert err == "" and c.klass == "idor_read" and c.round == 2      # BOM + 别名
    _, e1 = parse_claim('{"class":"idor","evidence":"x","marker":"m"}')   # 缺 distinct_from
    assert "distinct_from" in e1
    _, e2 = parse_claim('{"class":"rce","distinct_from":"x","evidence":"y"}')  # 不在词表
    assert "词表" in e2
    _, e3 = parse_claim('not json at all')
    assert e3


def test_parse_evidence_variants():
    txt = "﻿## Request:\nGET /a\n\n## Response\n200 ok\n\n## 佐证\nb 点\n\n## 来源命令\ncurl"
    seg = parse_evidence(txt)
    assert "GET /a" in seg["request"] and "200 ok" in seg["response"]
    # 附录E#3：worker 实际形态——括号注记标题
    txt2 = ("# SQLi — /search\n\n## 请求（基线）\ncurl q=test\n\n## 响应（基线）\n{\"data\":[]}\n\n"
            "## 验证\n- 第二来源: OR 1=1 → 全量")
    seg2 = parse_evidence(txt2)
    assert "q=test" in seg2["request"] and '{"data":[]}' in seg2["response"], seg2
    seg3 = parse_evidence("没有段的裸文本")                       # 无段兜底 → 整文当响应
    assert "裸文本" in seg3["response"]


def test_negative_oracle_narrowed():
    # 附录E#2 + 中期审核④：expect_denied 已删——负 oracle 只认状态行；
    # 500 报错页不再被误杀（canary F-001 教训）
    ev = _ev(response="HTTP/1.1 500 INTERNAL SERVER ERROR\n\n<h1>Debug</h1>"
                      "<p>You have an error in your SQL syntax; near '%1'%'</p>")
    v = gate1(_claim(klass="sqli_error"), ev, "")
    assert v.verdict == "pass", v.reasons

    # 200 + denied 字样不触发（无状态行信号）
    v3 = gate1(_claim(), _ev(response='{"code":0,"msg":"denied"}'), "")
    assert v3.verdict != "immune"


def test_parse_llm_json_three_layers():
    assert parse_llm_json('{"refuted": true, "reason": "x"}')["refuted"] is True
    assert parse_llm_json('```json\n{"refuted": false}\n```')["refuted"] is False
    assert parse_llm_json('我认为不对。\n{"refuted": true, "reason": "buyer=userA"} 就这些')["refuted"] is True
    assert parse_llm_json("完全是废话没有结构") is None


def test_gate2_retry_and_degrade():
    calls = []

    def flaky(msgs):
        calls.append(1)
        return "垃圾" if len(calls) < 2 else '{"refuted": false, "reason": "ok"}'

    # 单票模式（votes=1）：第一次垃圾→重试→ok
    v = gate2(_claim(), _ev(), "", llm_chat=flaky, votes=1)
    assert v.verdict == "pass" and len(calls) == 2

    def always_bad(msgs):
        return "还是垃圾"

    v2 = gate2(_claim(), _ev(), "", llm_chat=always_bad, votes=1)
    assert v2.verdict == "tentative" and "不可解析" in v2.reasons[0]

    v3 = gate2(_claim(), _ev(), "", llm_chat=None)
    assert v3.verdict == "tentative" and "safe default" in v3.reasons[0]


def test_gate2_majority_vote():
    # 3 票 2:1 放行 → pass（实测 verifier 自我不一致场景的解药）
    seq = ['{"refuted": false}', '{"refuted": true}', '{"refuted": false}']
    it = iter(seq)
    v = gate2(_claim(), _ev(), "", llm_chat=lambda m: next(it), votes=3)
    assert v.verdict == "pass" and "2/3" in v.reasons[0]

    # 3 票 2:1 否决 → rejected
    it2 = iter(['{"refuted": true}', '{"refuted": true}', '{"refuted": false}'])
    v2 = gate2(_claim(), _ev(), "", llm_chat=lambda m: next(it2), votes=3)
    assert v2.verdict == "rejected" and "2/3" in v2.reasons[0]

    # 2 票平票 → tentative（保守挂起）
    it3 = iter(['{"refuted": false}', '{"refuted": true}'])
    v3 = gate2(_claim(), _ev(), "", llm_chat=lambda m: next(it3), votes=2)
    assert v3.verdict == "tentative" and "未过半" in v3.reasons[0]

    # 废票参与分母：1 放行 1 拒 1 废 → 未过半 → tentative
    it4 = iter(['{"refuted": false}', '{"refuted": true}', "垃圾"])
    v4 = gate2(_claim(), _ev(), "", llm_chat=lambda m: next(it4), votes=3)
    assert v4.verdict == "tentative"


def test_gate3_escape_and_decode(tmp_path):
    # needle 经 JSON 转义（含引号）写进 transcript → 解码后必须命中
    needle = 'curl -s -H "Cookie: sid=A" https://t.example/api/order/detail?id=8823'
    tp = tmp_path / "t.jsonl"
    tp.write_text(json.dumps({"command": needle}) + "\n", encoding="utf-8")
    ev = _ev(request=needle)
    v = gate3(_claim(), ev, str(tp))
    assert v.verdict == "pass"

    # 中文经 \uXXXX 转义 → 解码命中
    needle2 = "curl 请求 含中文"
    tp2 = tmp_path / "t2.jsonl"
    tp2.write_text(json.dumps({"command": needle2}, ensure_ascii=True) + "\n", encoding="utf-8")
    v2 = gate3(_claim(klass="logic_race"), _ev(request=needle2), str(tp2))
    assert v2.verdict == "pass"

    # 空请求段 → 跳过记录（不假装验证）
    v3 = gate3(_claim(), _ev(response="only response"), str(tp))
    assert v3.verdict == "tentative" and "跳过" in v3.reasons[0]


def test_missing_evidence_file(tmp_path):
    vs = verify_claims([_claim()], str(tmp_path), str(tmp_path / "nope.jsonl"), gate2_fn=MOCK_PASS)
    assert vs[0].verdict == "rejected" and "不存在" in vs[0].reasons[0]
