"""noreport 硬拒单测（P4.0c）+ Observer 接线测试。

正例 = 纯现象类 → 硬拒；负例 = 同类现象但带真实数据/凭证/影响声明 → 不硬拒。
原则：宁可漏拒（观察者 prompt 第零步兜底），不可误杀真洞。
"""

import json

from src.noreport import check
from src.observer import Observer


def _f(summary, endpoint="/x", **kw):
    d = {"id": "F-001", "endpoint": endpoint, "summary": summary, "evidence": "e.md"}
    d.update(kw)
    return d


# ── 五类正例 ───────────────────────────────────────────────────────────────

def test_sourcemap_endpoint_rejected():
    r = check(_f("app.js.map 泄露源码映射", endpoint="/static/app.js.map"))
    assert r["match"] and r["category"] == "sourcemap"

def test_sourcemap_summary_rejected():
    r = check(_f("发现 sourcemap 文件可访问", endpoint="/static/app.js"))
    assert r["match"] and r["category"] == "sourcemap"

def test_version_fingerprint_rejected():
    r = check(_f("Server header 版本指纹披露: nginx/1.20.1"))
    assert r["match"] and r["category"] == "version_fingerprint"

def test_missing_headers_rejected():
    r = check(_f("缺少 CSP/X-Frame-Options 等安全头 (missing security headers)"))
    assert r["match"] and r["category"] == "missing_headers"

def test_instance_id_rejected():
    r = check(_f("metadata endpoint returns instance-id i-0abc123def45678ab"))
    assert r["match"] and r["category"] == "instance_id"

def test_metadata_endpoint_rejected():
    r = check(_f("可访问云元数据 169.254.169.254（无凭证）", endpoint="/fetch"))
    assert r["match"] and r["category"] == "metadata_or_internal"

def test_cors_wildcard_rejected():
    r = check(_f("CORS 配置为 *，任意源可读", endpoint="/api/data"),
              evidence_text="HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n{}")
    assert r["match"] and r["category"] == "cors_wildcard"


# ── 负例保护：同类但带实害 → 不硬拒 ───────────────────────────────────────

def test_sourcemap_as_recon_vehicle_not_rejected():
    # sourcemap 只是载体，实际发现未授权接口——summary 声明影响
    r = check(_f("sourcemap 泄露 /api/admin/debug，该接口未授权可写入 config"))
    assert not r["match"]

def test_instance_id_with_credentials_not_rejected():
    # A4 的 F-002 类场景：instance-id 伴随 AKIA 凭证 → 留给观察者
    r = check(_f("metadata endpoint leaks instance-id i-0abc123def45678ab"),
              evidence_text="i-0abc123def45678ab\nAKIAIOSFODNN7EXAMPLE")
    assert not r["match"]

def test_cors_with_actual_exfil_not_rejected():
    # CORS * 且证据含真实 PII → 留给观察者（可能真是高危）
    r = check(_f("CORS 配置为 *，任意源可读该接口数据", endpoint="/api/user"),
              evidence_text="Access-Control-Allow-Origin: *\n{\"phone\":\"13800138000\",\"name\":\"张三\"}")
    assert not r["match"]

def test_redirect_not_hard_rejected():
    # D2：开放重定向是语义类（单独 vs 链式），不代码硬拒——观察者第零步判
    r = check(_f("open redirect: 302 to arbitrary url", endpoint="/redirect"),
              evidence_text="HTTP/1.1 302\nLocation: https://evil.com")
    assert not r["match"]

def test_idor_sqli_xss_not_rejected():
    for s in ("idor: userA cookie reads userB order with phone",
              "UNION SQL injection dumped users table",
              "reflected XSS in debug page executes in browser"):
        assert not check(_f(s))["match"], s

def test_plain_server_header_in_evidence_not_rejected():
    # 关键负例：证据里正常带 Server 头（几乎每份 HTTP 证据都有），不得触发版本指纹硬拒
    r = check(_f("endpoint returns interesting JSON with admin data", endpoint="/api/cfg"),
              evidence_text="HTTP/1.1 200 OK\nServer: nginx/1.20.1\nX-Powered-By: Flask\n{\"admin\":true}")
    assert not r["match"]


# ── Observer 接线：硬拒不进 judge LLM、不被会话级翻案 ────────────────────

def _mock_chat(resp_by_call=None):
    calls = []

    def chat(msgs):
        calls.append(msgs)
        if resp_by_call:
            return resp_by_call[min(len(calls) - 1, len(resp_by_call) - 1)]
        return json.dumps({"is_vulnerability": True, "severity": "high", "reason": "mock"})

    return chat, calls


def test_observer_hard_rejected_skips_judge_llm():
    # 两条 finding：一条硬拒（sourcemap），一条正常——judge LLM 只该被调 1 次
    session_resp = json.dumps({
        "final_assessments": [{"id": "F-001", "assessment": "confirmed",
                               "severity": "high", "reason": "llm 试图翻案"}],
        "coverage_gaps": [], "effective_patterns": [], "suggestions": [],
        "notable_attempts": [], "intel_summary": "x"})
    chat, calls = _mock_chat([json.dumps({"is_vulnerability": True, "severity": "high",
                                          "reason": "judge ok"}),
                              session_resp])
    ob = Observer(chat_fn=chat)
    result = ob.run(
        findings=[_f("app.js.map 泄露源码映射", endpoint="/static/app.js.map"),
                  _f("idor: A reads B order", endpoint="/api/order", id="F-002")],
        evidence_texts={"F-002": "phone 13800138000 of userB"},
        previous_confirmed=[], board_summary="", handoff="")
    judge_calls = [c for c in calls if "待审发现" in c[1]["content"]]   # 会话级 prompt 不含此标记
    assert len(judge_calls) == 1                     # 硬拒条目没进 judge
    by_id = {f["id"]: f for f in result["findings"]}
    # 硬拒不被会话级 confirmed 翻案（mock 会话级对 F-001 说 confirmed——必须被压住）
    assert by_id["F-001"]["assessment"] == "likely_false_positive"
    assert "硬拒·sourcemap" in by_id["F-001"]["reason"]
    assert by_id["F-002"]["assessment"] == "confirmed"
