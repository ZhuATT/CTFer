"""
advisor.py - CTF Agent 统一建议模块

Phase 1 实现：
- review() - 策略审查入口
- get_suggestions() - 生成建议文本
- analyze_failure() - 失败分析

所有函数共享：
- 状态读取：state.json, failures.json
- 知识库：skills/ + experiences/
- LLM 调用：call_llm()
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

# 路径配置
WORKSPACE = Path("workspace")
ADVISOR_DIR = WORKSPACE / "advisor"
STATE_FILE = WORKSPACE / "state.json"
FAILURES_FILE = WORKSPACE / "failures.json"


# ============ Prompt 模板 ============

ADVISOR_PROMPT = """你是一个严格的 CTF 策略审查专家。

审查原则：
1. 不完全信任主 Agent 的判断
2. 关注被忽略的可能性
3. 识别思维定式和重复失败模式

## 知识库参考
{knowledge}

## 当前状态
{state_summary}

## 失败记录
{failures_summary}

审查类型：{review_type}

最终必须给出明确的 verdict：
- proceed: 当前策略合理，可以继续
- pause: 需要暂停检查某些问题
- pivot: 需要换方向

输出格式（JSON）：
{{
  "verdict": "proceed" | "pause" | "pivot",
  "reasoning": "分析理由",
  "suggestions": ["建议1", "建议2", "建议3"],
  "priority": 1-3
}}
"""

SUGGESTION_PROMPT = """请为这个 CTF 挑战生成简洁的状态摘要和建议。

## 状态
{state_summary}

## 知识库
{knowledge}

## 触发场景：{trigger}

输出格式（直接输出文本，不需要 JSON）：

## 当前进度评估
[2-3句话说明当前进度]

## 关键发现
- [发现1]
- [发现2]

## 下一步建议
1. [具体动作1]
2. [具体动作2]
3. [具体动作3]（可选）

## 状态标记
verdict: proceed | pause | pivot
"""

FAILURE_ANALYSIS_PROMPT = """分析以下 CTF 失败案例，判断是否应该换方向，并给出下一步建议。

## 当前失败
- 方法: {method}
- 失败原因: {reason}
- Payload: {payload}
- 题型: {category}

## 历史失败
{failures_summary}

## 知识库
{knowledge}

输出格式（JSON）：
{{
    "reason_type": "defense|filter|path|waf|auth|unknown",
    "reason_type_detail": "具体分类描述",
    "bypass_suggestion": "如果继续当前方向，如何绕过当前障碍",
    "alternative_methods": ["替代方法1", "替代方法2"],
    "should_pivot": true/false,
    "pivot_reason": "换方向或不换方向的原因",
    "next_method": "建议尝试的下一个方法",
    "alternative_vector": "完全不同的攻击向量"
}}
"""


# ============ 辅助函数 ============

def _load_state() -> dict:
    """从 state.json 加载状态"""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _load_failures() -> list:
    """从 failures.json 加载失败记录"""
    if FAILURES_FILE.exists():
        try:
            with open(FAILURES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return []


def _get_knowledge(challenge_type: str) -> str:
    """加载知识库内容"""
    try:
        from core.rag_knowledge import get_all_type_knowledge
        knowledge = get_all_type_knowledge(challenge_type)
        if knowledge and len(knowledge) > 100:
            return knowledge[:3000]
        return "（暂无相关知识）"
    except Exception:
        return "（知识库加载失败）"


def _summarize_state(state: dict) -> str:
    """生成状态摘要"""
    lines = [
        f"目标: {state.get('target', 'unknown')}",
        f"题型: {state.get('type', 'unknown')}",
        f"阶段: {state.get('phase', 'unknown')}",
        f"当前假设: {state.get('current_hypothesis', 'none')}",
        f"假设状态: {state.get('hypothesis_status', 'unverified')}",
        f"发现: {', '.join(state.get('findings', [])) or '（暂无）'}",
        f"已尝试方法: {', '.join(state.get('methods_tried', [])) or '（暂无）'}",
        f"失败特征: {', '.join(state.get('failed_patterns', [])) or '（暂无）'}",
    ]
    return "\n".join(lines)


def _summarize_failures(failures: list) -> str:
    """生成失败记录摘要"""
    if not failures:
        return "（暂无失败记录）"
    lines = []
    for entry in failures[-10:]:
        method = entry.get('method', '未知')
        reason = entry.get('reason', '')
        payload = entry.get('payload', '')
        lines.append(f"- {method}: {reason}" + (f" (payload: {payload[:50]}...)" if payload else ""))
    return "\n".join(lines)


def _save_advice(advice: dict) -> None:
    """保存顾问建议到 latest.json"""
    ADVISOR_DIR.mkdir(parents=True, exist_ok=True)
    latest_file = ADVISOR_DIR / "latest.json"
    with open(latest_file, "w", encoding="utf-8") as f:
        json.dump(advice, f, ensure_ascii=False, indent=2)


# ============ 核心函数 ============

def review(review_type: str, question: str = None, state_override: dict = None) -> dict:
    """
    策略审查入口

    Args:
        review_type: 审查类型 (initial/periodic/post_failure/phase_transition/question)
        question: 主动提问时的具体问题
        state_override: 可选的状态覆盖

    Returns:
        dict: {verdict, reasoning, suggestions, priority, timestamp, review_type}
    """
    from core.llm_client import call_llm, is_configured

    if not is_configured():
        raise RuntimeError(
            "LLM API 未配置，请检查 config.json 或设置环境变量\n"
            "LLM_API_URL, LLM_API_KEY, LLM_MODEL"
        )

    state = state_override or _load_state()
    failures = _load_failures()

    state_summary = _summarize_state(state)
    failures_summary = _summarize_failures(failures)
    knowledge = _get_knowledge(state.get('type', ''))

    prompt = ADVISOR_PROMPT.format(
        knowledge=knowledge,
        state_summary=state_summary,
        failures_summary=failures_summary,
        review_type=review_type
    )

    if question:
        prompt += f"\n\n主 Agent 提问: {question}"

    response = call_llm(prompt, system="你是一个严格的 CTF 策略顾问。")

    try:
        # 去除 markdown 代码块标记
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```", 2)[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

        advice = json.loads(cleaned)
    except json.JSONDecodeError:
        advice = {
            "verdict": "proceed",
            "reasoning": response[:200] if response else "LLM响应解析失败",
            "suggestions": [],
            "priority": 2
        }

    advice["timestamp"] = datetime.now().isoformat()
    advice["review_type"] = review_type

    _save_advice(advice)

    return advice


def get_suggestions(state: dict, trigger: str) -> str:
    """
    生成建议文本（给 get_context_summary_intelligent 用）

    Args:
        state: 当前状态字典
        trigger: 触发场景 (general/stuck/phase_transition/post_failure)

    Returns:
        str: 格式化建议文本
    """
    from core.llm_client import call_llm, is_configured

    if not is_configured():
        raise RuntimeError(
            "LLM API 未配置，请检查 config.json 或设置环境变量\n"
            "LLM_API_URL, LLM_API_KEY, LLM_MODEL"
        )

    state_summary = _summarize_state(state)
    knowledge = _get_knowledge(state.get('type', ''))

    prompt = SUGGESTION_PROMPT.format(
        state_summary=state_summary,
        knowledge=knowledge,
        trigger=trigger
    )

    response = call_llm(prompt, system="你是 CTF 辅助专家，负责分析解题状态并给出建议。")
    return response


def analyze_failure(method: str, reason: str, payload: str = "",
                    category: str = "", target: str = "") -> dict:
    """
    失败分析（给 analyze_failure_with_llm 用）

    Args:
        method: 失败的方法名
        reason: 失败原因
        payload: 使用的 payload
        category: 题型
        target: 目标 URL

    Returns:
        dict: {reason_type, bypass_suggestion, should_pivot, next_method, ...}
    """
    from core.llm_client import call_llm, is_configured

    if not is_configured():
        raise RuntimeError(
            "LLM API 未配置，请检查 config.json 或设置环境变量\n"
            "LLM_API_URL, LLM_API_KEY, LLM_MODEL"
        )

    failures = _load_failures()
    # 只取同目标同方法的失败记录
    same_target_failures = [f for f in failures if f.get('target') == target]
    failures_summary = _summarize_failures(same_target_failures)
    knowledge = _get_knowledge(category)

    prompt = FAILURE_ANALYSIS_PROMPT.format(
        method=method,
        reason=reason,
        payload=payload[:100] if payload else "",
        category=category,
        failures_summary=failures_summary,
        knowledge=knowledge
    )

    response = call_llm(prompt, system="你是 CTF 失败分析专家，擅长归类失败原因并给出替代方案。")

    try:
        # 去除 markdown 代码块标记
        cleaned = response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```", 2)[1]  # 去掉开头的 ```
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]  # 去掉 json
            cleaned = cleaned.strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "reason_type": "unknown",
            "reason_type_detail": "LLM响应解析失败",
            "bypass_suggestion": "无法分析",
            "alternative_methods": [],
            "should_pivot": False,
            "pivot_reason": "",
            "next_method": "",
            "alternative_vector": ""
        }


# ============ 便捷函数 ============

def review_phase_transition(from_phase: str, to_phase: str) -> dict:
    """审查阶段转换"""
    return review("phase_transition", question=f"从 {from_phase} 转换到 {to_phase} 是否合理？")


def review_initial() -> dict:
    """初始审查（新任务开始）"""
    return review("initial", question="这是新任务，请提供初始攻击建议和注意事项")


def review_periodic() -> dict:
    """定期审查（每5次尝试）"""
    return review("periodic")


def review_post_failure() -> dict:
    """失败后审查（连续失败 3/6/9 次）"""
    return review("post_failure")


def ask(question: str) -> dict:
    """主动提问"""
    return review("question", question=question)


# ============ 兼容旧接口 ============

def analyze(extra_context: str = "") -> str:
    """
    分析当前状态并生成建议（兼容旧接口）

    Args:
        extra_context: 额外的上下文信息

    Returns:
        结构化分析报告
    """
    state = _load_state()
    return get_suggestions(state, "general")


def suggest_next() -> str:
    """快速建议下一步行动（简化版）"""
    state = _load_state()
    phase = state.get("phase", "recon")

    suggestions = {
        "recon": "建议使用 curl 访问目标页面，同时用 dirsearch 扫描目录结构",
        "identify": "建议根据发现的信息确定漏洞类型，声明假设后进入 Exploit 阶段",
        "exploit": "建议基于假设执行攻击，尝试获取 flag",
        "flag": "建议调用 set_flag() 保存经验",
    }

    base = suggestions.get(phase, "未知阶段")
    hypothesis = state.get("current_hypothesis", "")

    if hypothesis and state.get("hypothesis_status") == "unverified":
        base += f"\n当前假设: {hypothesis}（待验证）"

    findings_count = len(state.get("findings", []))
    if findings_count < 2 and phase == "recon":
        base += f"\n⚠️ 发现不足（{findings_count}/2），建议收集更多目标信息"

    return base
