"""AT1 noreport —— 绝对不报表的代码预检（P4.0c 建立，2026-08-31 方案 A 重构）。

**检察官/法官分工**（用户拍板方案 A：代码从"法官"降级为"检察官"）：
- **reject（终审判死）——只留"形状即现象"类**：端点本身是 .map 文件、
  裸 instance-id / 169.254 元数据形状且无凭证跟随。这些连人看都无异议，
  且实害豁免先行保证"有凭证/PII 形状的一律放行"，误杀通道物理关闭。
- **suspect（预检标注）——定性类全部降级**：CORS / 安全头缺失 / 版本指纹 /
  summary 自述的 sourcemap / 内网 IP。代码不判死，只产出一行公诉意见
  注入观察者 prompt——观察者是法官，证据显示实际影响可翻案。
- **pass**：无信号，正常走观察者。

重构依据（2026-08-31 讨论定论）：
1. 死规则匹配真实场景天然脆弱——PII 豁免只认手机号/凭证形状（邮箱、身份证、
   英文 "disclosure" 均缺口），代码读不懂证据语义；
2. 实测：P4.9 两次实战里代码硬拒一次都没触发过（F-002 的"未授权"一词
   触发了豁免，真正杀掉它的是观察者第零步）——prompt 强化后代码终审的
   必要性没有实证，而误杀风险真实存在。

判定哲学（沿用）：worker 自己的定性优先——summary 是 worker 的一句话定性，
类目信号主要查 summary；证据形状只对"形状即现象"的终审类做判据。

实害豁免（门 0，先于一切）：summary 声明结果类影响 或 证据含凭证形状
（与 board 抽取正则同源）/ 中国手机号 → 永远 pass。宁可漏拒不可误杀。
"""

from __future__ import annotations

import re

# 凭证形状（v2 与 board 抽取同源；v3 被动抽取死，此处为唯一定义——只做实害豁免判据）
_CRED_RXS = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                        # AWS 固定前缀
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),                            # sk- 类（发行方命名约定）
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                   # PEM 块头
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),  # JWT 三段
)

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

# ── 类目信号 ──────────────────────────────────────────────────────────────
_INSTANCE_ID_RX = re.compile(r"\bi-[0-9a-f]{8,17}\b")            # 云 instance-id
_PRIVATE_IP_RX = re.compile(
    r"\b(?:(?:10|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
_CORS_RX = re.compile(r"cors|access-control-allow", re.IGNORECASE)
_CORS_STAR_RX = re.compile(r"access-control-allow-origin\s*:\s*\*|\*\s*的?\s*cors|"
                           r"cors.{0,20}\*", re.IGNORECASE)
_VERSION_FP_RX = re.compile(
    r"版本指纹|指纹|version.{0,14}(disclos|leak|fingerprint|reveal)|"
    r"x-powered-by.{0,30}(disclos|leak|reveal| expos)|server\s+header.{0,20}(disclos|leak|reveal)",
    re.IGNORECASE)
_HEADER_MISS_RX = re.compile(
    r"安全头|security.?header|missing.{0,14}header|header.{0,14}miss|"
    r"(csp|x-frame|hsts|x-content-type|content-security|strict-transport)"
    r".{0,20}(缺失|missing|absent|not set)", re.IGNORECASE)
_SOURCEMAP_RX = re.compile(r"sourcemap|source.?mapping|\.js\.map", re.IGNORECASE)

_PASS = {"verdict": "pass", "category": None, "reason": ""}


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
    """代码预检。返回 {verdict, category, reason}：
    reject = 形状即现象，终审判死（不进观察者 LLM）；
    suspect = 定性类疑似，产出公诉意见给观察者（可翻案）；
    pass = 无信号。"""
    if _has_real_impact(finding, evidence_text):
        return _PASS

    summary = str(finding.get("summary", ""))
    blob = (summary + "\n" + (evidence_text or "")).lower()
    endpoint = str(finding.get("endpoint", ""))

    # ── 终审类（形状即现象——豁免已过 = 无凭证/PII 形状跟随）────────────────
    # ① 端点本身就是 .map 文件
    if endpoint.rstrip("/").endswith(".map"):
        return {"verdict": "reject", "category": "sourcemap",
                "reason": "端点即 sourcemap 文件——用它做侦察，报你用它找到的东西"}
    # ② 裸 instance-id：形状 + 语境（豁免已过 = 无凭证跟随）
    if (_INSTANCE_ID_RX.search(blob)
            and ("instance" in blob or "metadata" in blob or "元数据" in summary)):
        return {"verdict": "reject", "category": "instance_id",
                "reason": "instance-id 是侦察信息无攻击价值——元数据的价值在凭证"}
    # ③ 169.254 元数据端点形状（豁免已过 = 无 IAM/RAM 凭证）
    if "169.254" in blob and ("metadata" in blob or "元数据" in summary or "169.254" in summary):
        return {"verdict": "reject", "category": "metadata_endpoint",
                "reason": "元数据端点可达但无凭证跟随 = 无影响；元数据的价值在 IAM/RAM 凭证"}

    # ── 预检类（定性疑似——公诉意见给观察者，法官裁决）─────────────────────
    if _SOURCEMAP_RX.search(summary):
        return {"verdict": "suspect", "category": "sourcemap",
                "reason": "sourcemap 泄露属绝对不报表——除非它是载体，实际报的是用它找到的东西"}
    if _PRIVATE_IP_RX.search(summary) and ("内网" in summary or "internal" in summary.lower()):
        return {"verdict": "suspect", "category": "internal_ip",
                "reason": "内网 IP 泄露属侦察信息——除非证明可达内网目标（SSRF 链）"}
    if _CORS_RX.search(summary) and _CORS_STAR_RX.search(blob):
        return {"verdict": "suspect", "category": "cors_wildcard",
                "reason": "CORS 配置属绝对不报表——除非证据显示已实际窃取具体敏感数据"}
    if _HEADER_MISS_RX.search(summary):
        return {"verdict": "suspect", "category": "missing_headers",
                "reason": "安全头缺失是理论风险，0 元——除非与其他缺陷构成链"}
    if _VERSION_FP_RX.search(summary):
        return {"verdict": "suspect", "category": "version_fingerprint",
                "reason": "版本号/中间件指纹是信息收集副产品——除非该版本有已知识别链"}

    return _PASS
