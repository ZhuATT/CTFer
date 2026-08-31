"""AT1 observer —— 轮间观察者（替代旧四门漏斗，phase3.5 §十 定稿）。

两个职责彻底分离（用户质询后修正）：
  judge_finding：小输入快判（一条发现+证据+业务上下文）→ 不看历史
  observe_session：大输入全局观察（全部发现+历史 confirmed+黑板）→ 判重/覆盖/建议

无工具（不进环境）；事实层由 controller 的 transcript 定点比对完成（evidence_verified 标记传入）。
"""

from __future__ import annotations

import json
from typing import Callable, Optional

from . import noreport
from .json_utils import parse_llm_json   # 三层剥取复用（P4.11 verify 迁出）

# ── 发现级 prompt（小输入：一条发现 + 证据 + 业务上下文）──

JUDGE_SYSTEM = "你是安全发现审阅者。按第零步硬否决+四步框架思考，输出严格JSON。不要输出其他内容。"

# 第零步（P4.0c 强化）：绝对不报表从"框架内的一条"提为前置硬否决——A4 实测
# 开放重定向在旧 prompt 位置下被 confirmed，此改动 + noreport.py 代码硬拒双层拦截。
JUDGE_PROMPT = """请判断以下渗透测试发现是否为真实漏洞。

【第零步：绝对不报——硬否决，先于一切判断】
以下类型无论证据多确凿，直接判 is_vulnerability=false（仅当满足"但书"时才可继续四步）：
- 单独的开放重定向（无链式利用证明——OAuth 回调/token 窃取/绕过 allowlist）
- CORS 配置问题（除非证据显示已实际窃取到具体敏感数据）
- Self-XSS / 无投递链的 XSS（仅自己可见、无受害者路径）
- sourcemap / 版本指纹 / 安全头缺失 / rate limit 缺失
- 裸 instance-id / 内网 IP / 元数据端点（无 IAM·RAM·AK/SK 凭证跟随）
但书：该现象只是载体，实际影响是凭证泄露/越权/注入/RCE → 判 true 并在 reason 说明链路。

【系统预检——检察官公诉，你是法官】
以下是对本条的代码预检意见（正则形状匹配，不懂语义）。它与第零步同源：
除非证据显示实际影响（凭证/数据窃取/越权/注入/RCE/链式利用），否则应判 false；
证据充分时按证据判，不受公诉意见约束。
{precheck}

【四步影响框架】
第一步：影响是什么？
  攻击者能做什么本来不该做的事？
  → 影响不存在（只是现象/配置）→ 不是漏洞

第二步：是设计内行为吗？
  在证据中查找请求者身份字段（buyer/orderer/user/uid）：
  → 如果 buyer 等于请求者 → 合法关联方 → 设计内行为 → 不是漏洞
  → 如果无任何关联字段 → 继续第三步
  【参考目标的业务上下文判断——同样"能看到手机号"在电商和社交含义不同】

第三步：影响有多大？
  凭证类（AK/SK/密码对）→ high
  个人标识组合（姓名+手机+地址等≥3元组）→ high
  单字段个人信息 → medium
  非敏感业务状态 → low/不是漏洞

第四步：有没有利用条件让影响归零？
  需要受害者主动操作 → 影响归零 → 不是漏洞
  内网完全过滤 → 影响归零 → 不是漏洞

【绝对不报表】
CORS 配置、sourcemap、安全头缺失、版本指纹、单独开放重定向、
self/PDF XSS、无敏感操作的 CSRF、裸 instance-id/内网 IP、纯猜测

【目标业务上下文】
{business_context}

【待审发现】
端点: {endpoint}
摘要: {summary}

【证据】（已通过 transcript 事实验证，内容为真实）
{evidence}

输出严格 JSON（无其他内容）：
{{"is_vulnerability": true/false, "severity": "high/medium/low/null", "reason": "一句话"}}"""


# ── 会话级 prompt（大输入：全部发现 + 历史 confirmed + 黑板）──

SESSION_SYSTEM = "你是安全会话观察者。看全局，输出严格JSON。不要输出其他内容。"

SESSION_PROMPT = """请从全局视角审阅本轮渗透测试会话。

【判重规则】
比较本轮发现与历史已确认发现：同端点+同根因 = 重复。
重复的发现标 assessment 为 "duplicate" 而非 "confirmed"。
（参考 SRC 标准：同一功能越权只确认 1 个；同根因只收第 1 个）

【绝对不报——硬否决】
发现级已标注"硬拒"（noreport 代码判定）的条目：assessment 保持
likely_false_positive，不得改为 confirmed。以下类型同理，无论证据多确凿：
单独开放重定向（无链式利用）/ CORS 配置 / Self-XSS 无投递链 /
sourcemap / 安全头缺失 / 版本指纹 / 裸 instance-id·内网 IP·元数据（无凭证）。
例外：现象只是载体、实际影响为凭证泄露/越权/注入/RCE 的链式发现。

【目标业务上下文】
{business_context}

【历史已确认发现】
{previous_confirmed}

【本轮全部发现（含发现级评判结果）】
{current_findings}

【黑板状态摘要】
{board_summary}

【Worker 交接】
{handoff}

请输出严格 JSON（无其他内容）：
{{
  "final_assessments": [
    {{"id": "F-001", "assessment": "confirmed/likely_false_positive/uncertain/duplicate",
      "severity": "high/medium/low/null", "reason": "一句话"}}
  ],
  "coverage_gaps": ["哪些攻击面没测到"],
  "effective_patterns": ["什么攻击模式在此站有效"],
  "suggestions": ["下一轮值得关注什么（标记式，不命令）"],
  "notable_attempts": ["worker 做了但没交 FINDINGS 的有价值尝试"],
  "intel_summary": "一段情报摘要"
}}"""


class Observer:
    """轮间观察者。无工具，LLM 调用经注入的 chat 函数（测试用 mock）。"""

    def __init__(self, chat_fn: Callable[[list[dict]], str],
                 business_context: str = ""):
        self.chat = chat_fn
        self.business_context = business_context or "（未提供——判断设计内行为时请保守，不确定标 uncertain）"

    def judge_finding(self, finding: dict, evidence_text: str,
                      precheck: str = "") -> dict:
        """发现级评判：小输入快判。precheck = noreport 预检公诉意见（方案 A）。"""
        prompt = JUDGE_PROMPT.format(
            business_context=self.business_context,
            endpoint=finding.get("endpoint", ""),
            summary=finding.get("summary", ""),
            evidence=evidence_text[:2000],
            precheck=precheck or "（无公诉——本条无预检信号）")
        msgs = [{"role": "system", "content": JUDGE_SYSTEM},
                {"role": "user", "content": prompt}]
        result = parse_llm_json(self.chat(msgs))
        if result is None:
            return {"is_vulnerability": None, "severity": None,
                    "reason": "观察者输出不可解析"}
        return {
            "is_vulnerability": result.get("is_vulnerability"),
            "severity": result.get("severity"),
            "reason": str(result.get("reason", ""))[:200],
        }

    def observe_session(self, current_findings: list[dict],
                        previous_confirmed: list[dict],
                        board_summary: str, handoff: str) -> dict:
        """会话级观察：判重 + 覆盖 + 建议 + 情报。返回完整 session_intel + final_assessments。"""
        prev_fmt = "\n".join(
            f"- {f.get('id')}: {f.get('endpoint')} {f.get('summary')}"
            for f in previous_confirmed) or "（无）"
        cur_fmt = json.dumps(current_findings, ensure_ascii=False, indent=1)
        prompt = SESSION_PROMPT.format(
            business_context=self.business_context,
            previous_confirmed=prev_fmt,
            current_findings=cur_fmt,
            board_summary=board_summary[:3000],
            handoff=handoff[:500])
        msgs = [{"role": "system", "content": SESSION_SYSTEM},
                {"role": "user", "content": prompt}]
        result = parse_llm_json(self.chat(msgs))
        if result is None:
            return {"final_assessments": [], "coverage_gaps": [],
                    "effective_patterns": [], "suggestions": [],
                    "notable_attempts": [], "intel_summary": "",
                    "error": "观察者输出不可解析"}
        return result

    def run(self, findings: list[dict], evidence_texts: dict[str, str],
            previous_confirmed: list[dict], board_summary: str,
            handoff: str) -> dict:
        """完整流程：noreport 预检（reject 终审 / suspect 公诉）→ 逐条 judge →
        一次 observe → 合并可直入黑板。方案 A：代码是检察官，观察者是法官。"""
        # 0. 代码预检（方案 A，2026-08-31）：
        #    reject（形状即现象）→ 终审 likely_false_positive，不进 LLM，不可翻案
        #    suspect（定性类）→ 公诉意见注入 judge prompt，观察者按证据裁决
        judged = []
        hard_rejected: set[str] = set()
        for f in findings:
            fid = f.get("id", "")
            ev = evidence_texts.get(fid, "")
            nr = noreport.check(f, ev)
            if nr["verdict"] == "reject":
                hard_rejected.add(fid)
                judged.append({**f, "is_vulnerability": False, "severity": None,
                               "reason": f"硬拒·{nr['category']}：{nr['reason']}"})
                continue
            pre = (f"疑似 {nr['category']}：{nr['reason']}" if nr["verdict"] == "suspect"
                   else "")
            r = self.judge_finding(f, ev, precheck=pre)
            judged.append({**f, **r})
        # 1. 会话级：全局观察（含判重）
        session = self.observe_session(judged, previous_confirmed,
                                       board_summary, handoff)
        # 2. 合并：会话级 final_assessments 覆盖发现级判定（判重可能改 confirmed→duplicate）
        #    硬拒条目不参与覆盖——代码判定的铁律不受 LLM 翻案
        final = {fa.get("id", ""): fa for fa in session.get("final_assessments", [])}
        merged = []
        for j in judged:
            fid = j.get("id", "")
            if fid in hard_rejected:
                merged.append({**j, "assessment": "likely_false_positive"})
            elif fid in final:
                merged.append({**j, "assessment": final[fid].get("assessment"),
                               "severity": final[fid].get("severity", j.get("severity")),
                               "reason": final[fid].get("reason", j.get("reason"))})
            else:
                # 会话级没覆盖 → 用发现级结果映射
                merged.append({**j,
                               "assessment": ("confirmed" if j.get("is_vulnerability") is True
                                              else "likely_false_positive" if j.get("is_vulnerability") is False
                                              else "uncertain")})
        return {
            "findings": merged,
            "session_intel": {k: v for k, v in session.items() if k != "final_assessments"},
        }
