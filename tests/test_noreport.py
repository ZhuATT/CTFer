"""noreport 预检单测（P4.0c 建立，2026-08-31 方案 A 重构）+ Observer 接线测试。

方案 A 语义：verdict ∈ reject（形状即现象终审）/ suspect（定性类公诉，可翻案）/ pass。
正例 = 现象类；负例 = 同类现象但带真实数据/凭证/影响声明 → pass（豁免）。
原则：宁可漏拒（观察者第零步+公诉兜底），不可误杀真洞。
"""

import json

from src.noreport import check


def _f(summary, endpoint="/x", **kw):
    d = {"id": "F-001", "endpoint": endpoint, "summary": summary, "evidence": "e.md"}
    d.update(kw)
    return d


# ── 终审类（reject：形状即现象） ──────────────────────────────────────────

def test_sourcemap_endpoint_rejected():
    r = check(_f("app.js.map 泄露源码映射", endpoint="/static/app.js.map"))
    assert r["verdict"] == "reject" and r["category"] == "sourcemap"

def test_instance_id_rejected():
    r = check(_f("metadata endpoint returns instance-id i-0abc123def45678ab"))
    assert r["verdict"] == "reject" and r["category"] == "instance_id"

def test_metadata_endpoint_rejected():
    r = check(_f("可访问云元数据 169.254.169.254（无凭证）", endpoint="/fetch"))
    assert r["verdict"] == "reject" and r["category"] == "metadata_endpoint"


# ── 预检类（suspect：定性公诉，观察者裁决——方案 A 降级） ─────────────────

def test_sourcemap_summary_suspect_not_reject():
    r = check(_f("发现 sourcemap 文件可访问", endpoint="/static/app.js"))
    assert r["verdict"] == "suspect" and r["category"] == "sourcemap"

def test_version_fingerprint_suspect():
    r = check(_f("Server header 版本指纹披露: nginx/1.20.1"))
    assert r["verdict"] == "suspect" and r["category"] == "version_fingerprint"

def test_missing_headers_suspect():
    r = check(_f("缺少 CSP/X-Frame-Options 等安全头 (missing security headers)"))
    assert r["verdict"] == "suspect" and r["category"] == "missing_headers"

def test_cors_wildcard_suspect():
    r = check(_f("CORS 配置为 *，任意源可读", endpoint="/api/data"),
              evidence_text="HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n{}")
    assert r["verdict"] == "suspect" and r["category"] == "cors_wildcard"

def test_internal_ip_summary_suspect():
    r = check(_f("响应泄露内网 IP 10.2.3.4", endpoint="/debug"))
    assert r["verdict"] == "suspect" and r["category"] == "internal_ip"


# ── 负例保护：同类但带实害 → pass ────────────────────────────────────────

def test_sourcemap_as_recon_vehicle_pass():
    r = check(_f("sourcemap 泄露 /api/admin/debug，该接口未授权可写入 config"))
    assert r["verdict"] == "pass"

def test_instance_id_with_credentials_pass():
    # instance-id 伴随 AKIA 凭证 → 有实害豁免，进观察者
    r = check(_f("metadata endpoint leaks instance-id i-0abc123def45678ab"),
              evidence_text="i-0abc123def45678ab\nAKIAIOSFODNN7EXAMPLE")
    assert r["verdict"] == "pass"

def test_cors_with_actual_exfil_pass():
    r = check(_f("CORS 配置为 *，任意源可读该接口数据", endpoint="/api/user"),
              evidence_text="Access-Control-Allow-Origin: *\n{\"phone\":\"13800138000\",\"name\":\"张三\"}")
    assert r["verdict"] == "pass"

def test_redirect_not_rejected():
    # 开放重定向是语义类（单独 vs 链式）——预检都不该碰（第零步判）
    r = check(_f("open redirect: 302 to arbitrary url", endpoint="/redirect"),
              evidence_text="HTTP/1.1 302\nLocation: https://evil.com")
    assert r["verdict"] == "pass"

def test_idor_sqli_xss_pass():
    for s in ("idor: userA cookie reads userB order with phone",
              "UNION SQL injection dumped users table",
              "reflected XSS in debug page executes in browser"):
        assert check(_f(s))["verdict"] == "pass", s

def test_plain_server_header_in_evidence_pass():
    # 证据里正常带 Server 头（几乎每份 HTTP 证据都有），不得触发版本指纹
    r = check(_f("endpoint returns interesting JSON with admin data", endpoint="/api/cfg"),
              evidence_text="HTTP/1.1 200 OK\nServer: nginx/1.20.1\nX-Powered-By: Flask\n{\"admin\":true}")
    assert r["verdict"] == "pass"
