"""AT1 noreport —— 绝对不报表的代码化硬拒（P4.0c，phase3.5 §十一 + D2 拍板）。

背景：A4 实测观察者把"单独开放重定向"confirmed 了——绝对不报表写在 prompt 里
是软约束，LLM 会漏。确定性类别在这里硬拒，不进观察者 LLM（零 token）。

分工（D2）：
- 本模块 = 确定性硬拒：sourcemap / 安全头缺失 / 版本指纹 / 裸 instance-id·
  元数据端点·内网 IP / CORS *（无数据实害）。铁律代码化。
- 语义类（开放重定向 / self-XSS / CSRF / rate limit）不在此硬拒——"单独"与
  "链式"的区分是语义判断，强化进观察者 prompt 第零步硬否决。

判定哲学——**worker 自己的定性优先**：summary 是 worker 对发现的一句话定性，
纯现象类发现（"CORS 配置为 *"）summary 必然围绕现象；结果类发现（越权/注入）
summary 必然声明影响（已被实害豁免放行）。所以类目信号主要查 summary，
证据形状只对 instance-id/元数据这类"形状即现象"的做辅助。

负例保护（宁可漏拒不可误杀）：实害豁免先行——summary 声明结果类影响
（越权/注入/未授权/RCE/写入/泄露/链式）或证据含凭证形状（与 board 抽取
正则同源）/ 中国手机号 PII → 永不硬拒，留给观察者。
漏拒无害：观察者 prompt 第零步有同一张表兜底。
"""

from __future__ import annotations

import re

# 正则同源（phase3 §1.2 原则）：凭证形状与 board 抽取共用一份定义
from .board import _CRED_RXS

# ── 实害豁免：命中任一 → 永不硬拒 ─────────────────────────────────────────
_PHONE_RX = re.compile(r"\b1[3-9]\d{9}\b")                       # 中国手机号（PII 信号）
# summary 声明结果类影响——worker 自己的话最有说服力，它说有影响就不是纯现象。
# 设计要点：裸"泄露/凭证"不算（"sourcemap 泄露源码"、"（无凭证）"是现象自述）——
# 泄露须搭配敏感对象；凭证/密钥须非否定语境（无凭证/没密钥）；
# rce 加拉丁守卫防 "sou-rce-map" 子串误命中。
_IMPACT_RX = re.compile(
    r"越权|注入|未授权|横向|提权|idor|injection|sqli|unauth|(?<![a-z])rce(?![a-z])|takeover|escalat|"
    r"(?<![无没])凭证|credential|akia|sk-[a-z0-9]|private.?key|(?<![无没])密钥|"
    r"(?:泄露|暴露|盗取|窃取|dump|读取|返回|含)[^。\n]{0,10}(?:数据|手机|电话|身份证|姓名|地址|用户|"
    r"密码|cookie|token|pii|personal|sensitive)|"
    r"写入|篡改|overwrite|toggle|修改成功|"
    r"chain|callback|窃取|steal", re.IGNORECASE)

# ── 硬拒类目信号（查 summary；证据辅助仅限形状即现象的两类） ──────────────
_INSTANCE_ID_RX = re.compile(r"\bi-[0-9a-f]{8,17}\b")            # 云 instance-id
_PRIVATE_IP_RX = re.compile(
    r"\b(?:(?:10|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
_CORS_RX = re.compile(r"cors|access-control-allow", re.IGNORECASE)
_CORS_STAR_RX = re.compile(r"access-control-allow-origin\s*:\s*\*|\*\s*的?\s*cors|"
                           r"cors.{0,20}\*", re.IGNORECASE)
_VERSION_FP_RX = re.compile(
    r"版本指纹|指纹|version.{0,14}(disclos|leak|fingerprint|reveal)|"
    r"x-powered-by.{0,30}(disclos|leak|reveal| expos)|server\s*header.{0,20}(disclos|leak|reveal)",
    re.IGNORECASE)
_HEADER_MISS_RX = re.compile(
    r"安全头|security.?header|missing.{0,14}header|header.{0,14}miss|"
    r"(csp|x-frame|hsts|x-content-type|content-security|strict-transport)"
    r".{0,20}(缺失|missing|absent|not set)", re.IGNORECASE)
_SOURCEMAP_RX = re.compile(r"sourcemap|source.?mapping|\.js\.map", re.IGNORECASE)


def _has_real_impact(finding: dict, evidence_text: str) -> bool:
    """实害豁免：summary 声明影响 / 证据含凭证或 PII → 不硬拒。"""
    if _IMPACT_RX.search(str(finding.get("summary", ""))):
        return True
    ev = evidence_text or ""
    for rx in _CRED_RXS:                     # 凭证形状（同源正则）
        if rx.search(ev):
            return True
    if _PHONE_RX.search(ev):                 # PII
        return True
    return False


def check(finding: dict, evidence_text: str = "") -> dict:
    """确定性硬拒判定。返回 {match, category, reason}。
    match=True → assessment=likely_false_positive，跳过观察者 LLM。"""
    if _has_real_impact(finding, evidence_text):
        return {"match": False, "category": None, "reason": ""}

    summary = str(finding.get("summary", ""))
    blob = (summary + "\n" + (evidence_text or "")).lower()
    endpoint = str(finding.get("endpoint", ""))

    # ① sourcemap：端点即 .map 文件（形状即现象），或 summary 自述 sourcemap
    if endpoint.rstrip("/").endswith(".map") or _SOURCEMAP_RX.search(summary):
        return {"match": True, "category": "sourcemap",
                "reason": "sourcemap 泄露属绝对不报表——用它做侦察，报你用它找到的东西"}

    # ② 裸 instance-id / 元数据 / 内网 IP：侦察信息无攻击价值
    #    形状即现象类——summary 定性（instance/metadata/内网语境）或证据含形状
    if (_INSTANCE_ID_RX.search(blob)
            and ("instance" in blob or "metadata" in blob or "元数据" in summary)):
        return {"match": True, "category": "instance_id",
                "reason": "instance-id 是侦察信息无攻击价值——元数据的价值在凭证"}
    if ("169.254" in blob or _PRIVATE_IP_RX.search(summary)) and (
            "metadata" in blob or "内网" in summary or "internal" in summary.lower()
            or "169.254" in summary):
        return {"match": True, "category": "metadata_or_internal",
                "reason": "云元数据/内网 IP 无凭证跟随 = 侦察信息；元数据的价值在 IAM/RAM 凭证"}

    # ③ CORS *：summary 自述 CORS 且呈通配形态（无实害——豁免已过）
    if _CORS_RX.search(summary) and _CORS_STAR_RX.search(blob):
        return {"match": True, "category": "cors_wildcard",
                "reason": "CORS 配置属绝对不报表——除非证明窃取了具体敏感数据（本条无）"}

    # ④ 安全头缺失（summary 自述）
    if _HEADER_MISS_RX.search(summary):
        return {"match": True, "category": "missing_headers",
                "reason": "安全头缺失是理论风险，0 元"}

    # ⑤ 版本指纹（summary 自述披露，无凭证）
    if _VERSION_FP_RX.search(summary):
        return {"match": True, "category": "version_fingerprint",
                "reason": "版本号/中间件指纹是信息收集副产品"}

    return {"match": False, "category": None, "reason": ""}
