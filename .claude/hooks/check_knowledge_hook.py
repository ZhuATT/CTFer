#!/usr/bin/env python3
"""
check_knowledge_hook.py - 解题状态上下文提供者

Phase 1 增强版：
- PreToolUse Hook 增强检查：
  1. 假设声明检查
  2. 方法失败检查
  3. 预算检查
  4. 阶段工具白名单检查
- PostToolUse 自动记录：在执行攻击命令前，自动记录上一次命令的结果

Hook 返回的 additionalContext 包含：
- 当前题目和已尝试的方法
- 失败记录和建议
- 可用的解题知识位置
- 循环检测警告
- 失败阈值触发时的强制重查消息
"""
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta

# 工作目录
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
STATE_FILE = WORKSPACE / "state.json"
FAILURES_FILE = WORKSPACE / "failures.json"
LAST_COMMAND_FILE = WORKSPACE / ".last_command"
POST_RECORD_MARKER = WORKSPACE / ".post_record_pending"
KNOWLEDGE_LOG = WORKSPACE / ".knowledge_log"

# 导入核心模块
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.loop_detector import (
    check_loop, LOOP_WARNING_MESSAGE, LOOP_BREAK_FORCE_MESSAGE
)
from core.failure_tracker import (
    should_trigger_rag, get_failure_count, get_failures_list,
    record_failure, get_tracker
)
from core.state_manager import (
    get_state_manager, Phase, PHASE_CONFIG,
    is_tool_allowed, check_budget as check_budget_func,
    get_phase as get_phase_func, get_hypothesis as get_hypothesis_func
)


def load_json(path: Path) -> Optional[Dict]:
    """加载 JSON 文件"""
    if not path.exists():
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def get_state_summary() -> str:
    """获取解题状态摘要"""
    state = load_json(STATE_FILE)
    if not state:
        return ""

    lines = []
    target = state.get("target", "未知")
    ctype = state.get("type", "未知")
    flag = state.get("flag", "")

    lines.append(f"【当前状态】")
    lines.append(f"- 靶机: {target}")
    lines.append(f"- 题型: {ctype}")
    lines.append(f"- Flag: {'已找到 ' + flag if flag else '未找到'}")

    findings = state.get("findings", [])
    if findings:
        lines.append(f"\n【已有发现】({len(findings)} 条)")
        for f in findings[-3:]:  # 只显示最近 3 条
            lines.append(f"  - {f}")

    methods = state.get("methods_tried", [])
    if methods:
        lines.append(f"\n【已尝试方法】({len(methods)} 条)")
        for m in methods[-3:]:
            lines.append(f"  - {m}")

    return "\n".join(lines)


def get_failures_summary() -> str:
    """获取失败记录摘要"""
    failures = load_json(FAILURES_FILE)
    if not failures or not isinstance(failures, list):
        return ""

    lines = []
    lines.append(f"\n【失败记录】({len(failures)} 条)")

    for f in failures[-5:]:  # 只显示最近 5 条
        method = f.get("method", "未知")
        reason = f.get("reason", "")
        lines.append(f"  - {method}: {reason}")

    return "\n".join(lines)


def get_knowledge_info() -> str:
    """获取知识库信息"""
    knowledge_files = []

    # 技能知识
    skills_dir = Path(__file__).parent.parent.parent / "skills"
    if skills_dir.exists():
        for skill_file in skills_dir.glob("*/SKILL.md"):
            knowledge_files.append(f"skills/{skill_file.parent.name}/SKILL.md")

    # 经验知识
    experiences_dir = Path(__file__).parent.parent.parent / "memories" / "experiences"
    if experiences_dir.exists():
        for exp_file in experiences_dir.glob("*.md"):
            knowledge_files.append(f"memories/experiences/{exp_file.name}")

    if not knowledge_files:
        return ""

    lines = []
    lines.append(f"\n【可用知识库】({len(knowledge_files)} 个文件)")
    for kf in knowledge_files[:10]:  # 只显示前 10 个
        lines.append(f"  - {kf}")

    return "\n".join(lines)


def get_failures_for_target(target: str) -> list:
    """获取指定目标的所有失败记录"""
    failures = load_json(FAILURES_FILE)
    if not failures or not isinstance(failures, list):
        return []
    if not target:
        return []
    return [f for f in failures if f.get("target") == target]


def parse_command_signature(command: str) -> Tuple[Optional[str], Optional[str]]:
    """
    从完整命令字符串解析出工具名和参数字符串

    Args:
        command: 完整命令，如 "curl -s -k http://target.com" 或 "python -c \"import os\""

    Returns:
        (tool_name, args_str) 如 ("curl", "-s -k http://target.com")
    """
    if not command:
        return None, None

    command = command.strip()

    # 处理 python -c "..." 的情况
    if command.startswith("python"):
        parts = command.split(" ", 1)
        if len(parts) > 1:
            return "python", parts[1]
        return "python", ""

    # 处理各种工具调用
    simple_tools = [
        "curl", "sqlmap", "dirsearch", "python3", "php", "node", "ruby", "perl",
        "bash", "sh", "grep", "cat", "ls", "cd", "pwd", "mkdir", "rm", "cp",
        "mv", "tar", "gzip", "gunzip", "unzip", "wget", "nc", "netcat", "nmap",
        "git", "docker", "pip", "uv", "docker", "docker-compose"
    ]

    for tool in simple_tools:
        if command.startswith(tool + " "):
            args = command[len(tool) + 1:].strip()
            return tool, args

    # 如果没有空格，整个命令就是工具名
    parts = command.split()
    if parts:
        return parts[0], " ".join(parts[1:]) if len(parts) > 1 else ""

    return None, None


def check_loop_detection(command: str) -> Optional[Tuple[str, str]]:
    """
    检测循环并返回状态和消息

    Returns:
        (status, message) 或 None
    """
    if not command:
        return None

    tool_name, args_str = parse_command_signature(command)
    if not tool_name:
        return None

    result = check_loop(tool_name, args_str if args_str else None)

    if result == "break":
        return "break", LOOP_BREAK_FORCE_MESSAGE
    elif result == "warn":
        return "warn", LOOP_WARNING_MESSAGE

    return None


def get_current_target() -> str:
    """获取当前靶机 URL"""
    state = load_json(STATE_FILE)
    return state.get("target", "") if state else ""


# ==================== 新增：上一次命令结果读写 ====================

def save_last_command(command: str, output: str, return_code: int = 0):
    """保存上一次命令结果，供下次 Hook 调用时分析"""
    LAST_COMMAND_FILE.write_text(
        json.dumps({
            "command": command,
            "output": output[:2000],  # 截断避免过大
            "return_code": return_code,
            "timestamp": datetime.now().isoformat()
        }, ensure_ascii=False),
        encoding="utf-8"
    )


def get_last_command_result() -> Optional[Dict[str, Any]]:
    """获取上一次命令结果"""
    if not LAST_COMMAND_FILE.exists():
        return None
    try:
        return json.loads(LAST_COMMAND_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return None


# ==================== 新增：检查命令是否包含已失败的方法 ====================

def check_command_for_failed_methods(command: str, failures: list) -> List[str]:
    """
    检查命令是否包含已失败的方法，返回警告信息

    Args:
        command: curl 命令内容
        failures: 当前目标的失败记录列表

    Returns:
        警告字符串列表，如果有匹配的话
    """
    if not failures or not command:
        return []

    command_lower = command.lower()
    warnings = []

    # 方法名到 URL 参数/关键词的映射（帮助识别哪些方法可能被用在命令中）
    method_indicators = {
        "system": ["system", "cmd=", "c=", "exec=", "command="],
        "exec": ["exec", "cmd=", "c=", "command="],
        "shell_exec": ["shell_exec", "sh=", "bash="],
        "popen": ["popen", "pipe="],
        "copy": ["copy", "cp=", "move="],
        "file_put_contents": ["file_put_contents", "write=", "fwrite="],
        "file_get_contents": ["file_get_contents", "read=", "include=", "require="],
        "unserialize": ["unserialize", "deserialize", "data="],
        "sqlmap": ["sqlmap", "sql_injection", "--dbs"],
        "路径遍历": ["../", "..%2f", "traversal", "path="],
        "lfi": ["../../", "..%2f", "include=", "file="],
    }

    for failure in failures:
        method = failure.get("method", "").lower()
        reason = failure.get("reason", "")
        payload = failure.get("payload", "")

        # 直接检查方法名是否在命令中
        if method in command_lower:
            warnings.append(f'方法 "{method}" 已失败（原因: {reason}）')
            continue

        # 检查 method_indicators 中的关键词
        if method in method_indicators:
            for indicator in method_indicators[method]:
                if indicator in command_lower:
                    warnings.append(f'方法 "{method}" 已失败（原因: {reason}），命令中检测到 "{indicator}"')
                    break

        # 检查 payload 是否在命令中（payload 可能包含关键特征）
        if payload and len(payload) > 3 and payload.lower() in command_lower:
            warnings.append(f'Payload "{payload[:30]}..." 已失败（原因: {reason}）')

    return warnings


# ==================== Phase 1 增强：假设声明检查 ====================

def check_hypothesis_declared() -> Tuple[bool, str]:
    """
    检查是否已声明当前假设

    Returns:
        (needs_declaration, message) - needs_declaration=True 表示需要声明
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""  # 没有状态，不拦截

    hypothesis = state.get("current_hypothesis", "")
    phase = state.get("phase", Phase.RECON)

    # Identify 和 Exploit 阶段必须声明假设
    if phase in [Phase.IDENTIFY, Phase.EXPLOIT] and not hypothesis:
        return True, HYPOTHESIS_REQUIRED_MESSAGE

    return False, ""


HYPOTHESIS_REQUIRED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【Phase Gate】请先声明当前假设

在继续攻击之前，必须明确回答：

1. 目标漏洞类型：______
2. 攻击向量：______
3. 预期结果：______

格式示例：
假设：LFI漏洞，通过日志文件包含执行代码
向量：注入PHP到UA头，包含access.log
预期：日志包含后执行id命令

请在回答前不要执行任何攻击工具。
═══════════════════════════════════════════════════════════════════════
"""


# ==================== Phase 1 增强：方法失败检查 ====================

def check_method_failed(tool_name: str, args_str: str, target: str) -> Tuple[bool, str]:
    """
    检查方法是否在 failures.json 中已记录失败

    Returns:
        (is_failed, message) - is_failed=True 表示方法已失败
    """
    if not target:
        return False, ""

    failures = load_json(FAILURES_FILE)
    if not failures:
        return False, ""

    target_failures = [f for f in failures if f.get("target") == target]
    if not target_failures:
        return False, ""

    # 检查方法是否已失败
    for f in target_failures:
        method = f.get("method", "").lower()
        if method == tool_name.lower():
            reason = f.get("reason", "未知原因")
            analysis = f.get("analysis", {})
            alternatives = analysis.get("alternative_methods", []) if analysis else []

            msg = METHOD_FAILED_MESSAGE.format(
                method=method,
                reason=reason,
                alternatives="\n".join([f"  {i+1}. {a}" for i, a in enumerate(alternatives[:3])]) if alternatives else "  无明确替代建议，请查看经验库"
            )
            return True, msg

    return False, ""


METHOD_FAILED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【失败检测】该方法已确认无效

方法：{method}
失败原因：{reason}

建议尝试替代方向：
{alternatives}

请选择一个新方向继续攻击。
═══════════════════════════════════════════════════════════════════════
"""


# ==================== Phase 1 增强：预算检查 ====================

def check_phase_budget() -> Tuple[bool, str]:
    """
    检查当前阶段预算是否耗尽

    Returns:
        (budget_exceeded, message)
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""

    phase = state.get("phase", Phase.RECON)
    step_count = state.get("step_count", 0)
    budget = PHASE_CONFIG.get(phase, {}).get("budget", 8)
    hypothesis = state.get("current_hypothesis", "未声明")
    hypothesis_status = state.get("hypothesis_status", "unverified")

    if step_count >= budget:
        msg = BUDGET_EXCEEDED_MESSAGE.format(
            phase=phase,
            step_count=step_count,
            budget=budget,
            hypothesis=hypothesis,
            hypothesis_status=hypothesis_status
        )
        return True, msg

    return False, ""


BUDGET_EXCEEDED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【预算耗尽】{phase} 阶段预算已用完（{step_count}/{budget}）

当前进度：
- 假设：{hypothesis}
- 假设状态：{hypothesis_status}

请评估：
- 是否已确定攻击向量？
- 是否需要返回 Recon 重新收集？
- 还是切换到 Exploit 尝试新方法？
═══════════════════════════════════════════════════════════════════════
"""


# ==================== Phase 1 增强：阶段工具白名单检查 ====================

def check_tool_whitelist(tool_name: str) -> Tuple[bool, str]:
    """
    检查工具是否在当前阶段白名单中

    Returns:
        (not_allowed, message)
    """
    state = load_json(STATE_FILE)
    if not state:
        return False, ""

    phase = state.get("phase", Phase.RECON)
    allowed_tools = PHASE_CONFIG.get(phase, {}).get("allowed_tools", [])

    # Flag 阶段没有工具限制
    if phase == Phase.FLAG or not allowed_tools:
        return False, ""

    if tool_name not in allowed_tools:
        msg = TOOL_NOT_ALLOWED_MESSAGE.format(
            tool=tool_name,
            phase=phase,
            allowed=", ".join(allowed_tools)
        )
        return True, msg

    return False, ""


TOOL_NOT_ALLOWED_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【阶段工具检查】{tool} 不在当前阶段白名单中

当前阶段：{phase}
允许的工具：{allowed}

请：
1. 使用该阶段允许的工具继续攻击
2. 或者切换到正确的阶段
═══════════════════════════════════════════════════════════════════════
"""


# ==================== Phase 1 增强：语义级循环检测 ====================

# 动作家族分类
ACTION_FAMILIES = {
    "php_protocol": ["php://filter", "php://input", "data://", "expect://"],
    "log_poison": ["UA注入", "Referer注入", "日志包含", "User-Agent"],
    "path_traversal": ["../", "....//", "%2e%2e", "..%2f", "....%2f"],
    "session": ["session", "SESSION", "/tmp/sess_"],
    "read_file": ["cat", "base64", "读取", "type", "more", "less"],
    "sql_injection": ["union", "select", "or 1=1", "order by", "--", "sleep"],
}

# 方法名到动作家族的映射
METHOD_TO_FAMILY = {
    "php://filter": "php_protocol",
    "php://input": "php_protocol",
    "data://": "php_protocol",
    "expect://": "php_protocol",
    "UA注入": "log_poison",
    "Referer注入": "log_poison",
    "User-Agent注入": "log_poison",
    "../": "path_traversal",
    "..%2f": "path_traversal",
    "....//": "path_traversal",
    "session包含": "session",
    "session污染": "session",
    "cat": "read_file",
    "base64": "read_file",
    "union": "sql_injection",
    "select": "sql_injection",
    "or 1=1": "sql_injection",
}


def get_action_family(method: str) -> Optional[str]:
    """根据方法名返回动作家族"""
    return METHOD_TO_FAMILY.get(method)


def check_semantic_loop(tool_name: str, args_str: str, target: str) -> Tuple[bool, str]:
    """
    语义级循环检测：检测同一动作家族是否重复尝试

    Returns:
        (is_loop, message)
    """
    if not target:
        return False, ""

    failures = load_json(FAILURES_FILE)
    if not failures:
        return False, ""

    target_failures = [f for f in failures if f.get("target") == target]

    # 统计每个动作家族的失败次数
    family_counts = {}
    family_methods = {}

    for f in target_failures:
        method = f.get("method", "")
        family = METHOD_TO_FAMILY.get(method)
        if family:
            family_counts[family] = family_counts.get(family, 0) + 1
            if family not in family_methods:
                family_methods[family] = []
            family_methods[family].append(method)

    # 检查是否有动作家族失败 >= 3 次
    for family, count in family_counts.items():
        if count >= 3:
            methods = ", ".join(set(family_methods[family]))
            msg = SEMANTIC_LOOP_MESSAGE.format(
                family=family,
                count=count,
                methods=methods
            )
            return True, msg

    return False, ""


SEMANTIC_LOOP_MESSAGE = """
═══════════════════════════════════════════════════════════════════════
🛑 【循环检测】检测到同类方法重复尝试

动作家族：{family}
失败次数：{count}
方法列表：{methods}

继续尝试同类方法可能是无效的。
请选择完全不同的攻击向量。
═══════════════════════════════════════════════════════════════════════
"""


# ==================== 重写：Hook 主函数 ====================

def get_context_for_llm(command: str) -> Dict[str, Any]:
    """
    Phase 1 增强版 Hook 上下文生成器

    流程：
    0. 自动记录上一次命令结果（PostToolUse 模拟）
    1. 解析命令获取工具名和参数
    2. Phase 1 增强检查：
       - 假设声明检查
       - 方法失败检查
       - 预算检查
       - 阶段工具白名单检查
       - 语义级循环检测
    3. 原有检查：
       - 循环检测（签名级）
       - 失败阈值检查
    4. 注入所有警告和建议到 additionalContext
    """
    # ========== 0. PostToolUse: 自动记录上一次命令 ==========
    record_result = auto_record_last_command()
    # record_result 只用于调试，不直接输出（会在后续上下文中体现）

    context_parts = []
    target = get_current_target()

    # ========== 0. 解析命令 ==========
    tool_name, args_str = parse_command_signature(command)

    # ========== Phase 1 增强：PreToolUse 检查 ==========

    # 1. 检查假设声明（Identify/Exploit 阶段必须声明假设）
    needs_hypothesis, hypothesis_msg = check_hypothesis_declared()
    if needs_hypothesis:
        context_parts.append(hypothesis_msg)
        return {
            "continue": False,
            "hookSpecificOutput": {
                "additionalContext": "\n".join(context_parts)
            }
        }

    # 2. 检查工具白名单
    if tool_name:
        not_allowed, tool_msg = check_tool_whitelist(tool_name)
        if not_allowed:
            context_parts.append(tool_msg)
            return {
                "continue": False,
                "hookSpecificOutput": {
                    "additionalContext": "\n".join(context_parts)
                }
            }

    # 3. 检查预算
    budget_exceeded, budget_msg = check_phase_budget()
    if budget_exceeded:
        context_parts.append(budget_msg)
        # 预算耗尽不强制中断，但注入警告

    # 4. 检查方法是否已知失败
    if tool_name and target:
        method_failed, failed_msg = check_method_failed(tool_name, args_str, target)
        if method_failed:
            context_parts.append(failed_msg)
            # 方法已知失败，注入警告但继续执行

    # 5. 语义级循环检测
    if tool_name and target:
        semantic_loop, loop_msg = check_semantic_loop(tool_name, args_str, target)
        if semantic_loop:
            context_parts.append(loop_msg)
            # 语义循环，注入警告但继续执行

    # ========== 原有检查 ==========

    # 6. 检查失败阈值（3次失败触发强制重查）
    if target:
        rerag_triggered, rerag_msg, count = should_trigger_rag(target)
        if rerag_triggered:
            context_parts.append(rerag_msg)
            # 失败阈值达到，强制重查

    # 7. 检查签名级循环
    loop_result = check_loop_detection(command)
    if loop_result:
        loop_status, loop_msg = loop_result
        context_parts.append(loop_msg)

        # break 级别强制中断
        if loop_status == "break":
            return {
                "continue": False,
                "hookSpecificOutput": {
                    "additionalContext": "\n".join(context_parts)
                }
            }

    # ========== 8. 注入上一次命令结果 ==========
    last_result = get_last_command_result()
    if last_result:
        last_output = last_result.get("output", "")[:500]
        if last_output:
            context_parts.append(f"【上次命令输出】\n{last_output}")

    # ========== 9. 状态摘要 ==========
    state_summary = get_state_summary()
    if state_summary:
        context_parts.insert(0, state_summary)

    # ========== 10. 失败记录摘要（未达阈值时） ==========
    if target and not rerag_triggered:
        failures = get_failures_list(target, max_rows=5)
        if failures and "（暂无" not in failures:
            context_parts.append(f"\n【已有失败记录】\n{failures}")

    # ========== 11. 检查命令是否包含已失败的方法（额外警告） ==========
    failures_list = get_failures_for_target(target)
    if failures_list and command:
        failed_warnings = check_command_for_failed_methods(command, failures_list)
        if failed_warnings:
            context_parts.append("\n【Hook 警告 - 方法已失败】")
            for w in failed_warnings:
                context_parts.append(f"  ⚠️ {w}")
            context_parts.append("建议：换用其他方法，或基于失败原因调整 bypass 策略")

    # ========== 12. 知识库提示 ==========
    if not target:
        context_parts.append("\n📋 提示：这是新的解题任务，请先用 curl 访问目标识别题型。")

    return {
        "continue": True,
        "hookSpecificOutput": {
            "additionalContext": "\n".join(context_parts)
        }
    }


# ==================== 重写：main 函数 ====================

# ==================== Phase 1 PostToolUse: 自动记录上一次命令结果 ====================

def parse_tool_name_from_command(command: str) -> str:
    """从命令中解析工具名"""
    if not command:
        return ""

    command = command.strip()

    # python -c "..." 的情况
    if command.startswith("python"):
        return "python"

    # 简单工具名列表
    simple_tools = [
        "curl", "sqlmap", "dirsearch", "python3", "php", "node", "ruby", "perl",
        "bash", "sh", "grep", "cat", "ls", "cd", "pwd", "mkdir", "rm", "cp",
        "mv", "tar", "gzip", "gunzip", "unzip", "wget", "nc", "netcat", "nmap",
        "git", "docker", "pip", "uv", "docker-compose", "java", "ruby"
    ]

    for tool in simple_tools:
        if command.startswith(tool + " "):
            return tool
        if command == tool:
            return tool

    # 如果没有匹配，返回第一个单词
    parts = command.split()
    if parts:
        return parts[0]

    return ""


def analyze_command_success(output: str, return_code: int) -> Tuple[bool, str]:
    """
    分析命令是否成功执行

    Returns:
        (is_success, reason)
    """
    # 检查返回码
    if return_code != 0:
        return False, f"命令返回非零退出码: {return_code}"

    # 检查输出中的常见失败标志
    output_lower = output.lower()

    failure_indicators = [
        ("not found", "404 Not Found"),
        ("forbidden", "403 Forbidden"),
        ("error", "输出包含 error"),
        ("invalid", "输出包含 invalid"),
        ("empty", "输出为空"),
        ("no such", "文件或目录不存在"),
        ("permission denied", "权限拒绝"),
        ("connection refused", "连接被拒绝"),
        ("timeout", "连接超时"),
        ("parse error", "解析错误"),
        ("denied", "访问被拒绝"),
    ]

    for indicator, desc in failure_indicators:
        if indicator in output_lower:
            return False, desc

    # 检查是否有成功标志
    success_indicators = [
        "flag{", "flag{",  # CTF flag
        "200 ok", "200 OK",
        "<html",  # HTML 响应
        "{",  # JSON 响应
        "[",  # 数组响应
    ]

    for indicator in success_indicators:
        if indicator in output_lower:
            return True, "命令正常执行"

    # 默认认为成功（因为 curl 200 就是成功）
    return True, "命令正常执行"


def auto_record_last_command() -> str:
    """
    自动记录上一次命令执行结果（PostToolUse Hook 模拟）

    在 PreToolUse Hook 执行前调用，检查是否需要记录上一次命令的结果。
    这样可以在下一次命令执行前自动：
    1. add_method() - 记录已使用的方法
    2. record_failure() - 分析失败原因并记录（如果失败）
    3. increment_step() - 更新当前阶段步数

    Returns:
        记录结果描述（用于调试）
    """
    last_result = get_last_command_result()
    if not last_result:
        return "无上一次命令结果，跳过记录"

    # 检查是否已记录（避免重复记录）
    if POST_RECORD_MARKER.exists():
        try:
            marker = json.loads(POST_RECORD_MARKER.read_text(encoding="utf-8"))
            last_recorded_time = marker.get("timestamp", "")
            last_command = marker.get("command", "")

            # 如果上次记录的命令和当前一致，跳过
            if last_recorded_time == last_result.get("timestamp", "") and last_command == last_result.get("command", ""):
                return "已记录过，跳过"
        except (json.JSONDecodeError, IOError):
            pass
    else:
        marker = {"timestamp": "", "command": "", "recorded": False}

    command = last_result.get("command", "")
    output = last_result.get("output", "")
    return_code = last_result.get("return_code", 0)

    # 解析工具名
    tool_name = parse_tool_name_from_command(command)
    if not tool_name:
        return f"无法识别工具名: {command[:50]}"

    # 分析是否成功
    is_success, reason = analyze_command_success(output, return_code)

    # 1. 添加方法到状态
    state = load_json(STATE_FILE)
    if state:
        methods_tried = state.get("methods_tried", [])
        if tool_name not in methods_tried:
            methods_tried.append(tool_name)
            state["methods_tried"] = methods_tried

        # 2. 增加步数
        step_count = state.get("step_count", 0) + 1
        state["step_count"] = step_count

        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    # 3. 如果失败，记录到 failures.json
    if not is_success:
        failures = load_json(FAILURES_FILE) or []
        target = state.get("target", "") if state else ""
        category = state.get("type", "") if state else ""

        # 检查是否已存在相同记录
        found = False
        for f in failures:
            if f.get("target") == target and f.get("method") == tool_name:
                f["reason"] = reason
                f["payload"] = command
                f["updated_at"] = datetime.now().isoformat()
                found = True
                break

        if not found:
            failures.append({
                "target": target,
                "method": tool_name,
                "reason": reason,
                "payload": command,
                "category": category,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
            })

        FAILURES_FILE.write_text(json.dumps(failures, ensure_ascii=False, indent=2), encoding="utf-8")

    # 标记已记录
    marker = {
        "timestamp": last_result.get("timestamp", ""),
        "command": last_result.get("command", ""),
        "recorded": True,
        "tool": tool_name,
        "success": is_success
    }
    POST_RECORD_MARKER.write_text(json.dumps(marker, ensure_ascii=False), encoding="utf-8")

    if is_success:
        return f"✓ PostRecord: {tool_name} 成功 (step: {step_count if state else '?'})"
    else:
        return f"✗ PostRecord: {tool_name} 失败 - {reason}"


def main():
    """
    Hook 入口

    流程：
    1. 读取当前命令
    2. 检查循环和失败阈值
    3. 将上一次命令结果注入额外上下文
    4. 返回给 LLM
    """
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        print("{}", flush=True)
        return

    # 提取命令
    command = ""
    if isinstance(input_data, dict):
        tool_input = input_data.get("tool_input", {})
        if isinstance(tool_input, dict):
            command = tool_input.get("command", "")
        elif isinstance(tool_input, str):
            command = tool_input

    # 获取上下文（包含上一次命令失败分析）
    result = get_context_for_llm(command)

    # 将上一次命令结果注入 additionalContext（让 LLM 知道上一次的输出）
    last_result = get_last_command_result()
    if last_result:
        output_snippet = last_result.get("output", "")[:500]
        if output_snippet:
            result["hookSpecificOutput"]["additionalContext"] += (
                f"\n\n【上次命令输出】\n{output_snippet}"
            )

    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
