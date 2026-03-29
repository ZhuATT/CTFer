#!/usr/bin/env python3
"""
check_knowledge_hook.py - 解题状态上下文提供者

当执行 Bash 工具时，提供当前解题状态和可用知识摘要，
帮助 LLM 做出明智的决策，而不是强制执行特定流程。

Hook 返回的 additionalContext 包含：
- 当前题目和已尝试的方法
- 失败记录和建议 bypass
- 可用的解题知识位置
- 循环检测警告
"""
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

# 工作目录
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
STATE_FILE = WORKSPACE / "state.json"
FAILURES_FILE = WORKSPACE / "failures.json"
KNOWLEDGE_LOG = WORKSPACE / ".knowledge_log"

# 添加工具模块路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.loop_detector import check_loop, LOOP_WARNING_MESSAGE, LOOP_BREAK_MESSAGE


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


def check_loop_detection(command: str) -> Tuple[Optional[str], str]:
    """
    检测命令是否陷入循环

    Args:
        command: 完整命令字符串

    Returns:
        (status, message)
        - status 为 None 时无循环
        - status 为 "warn" 时接近阈值
        - status 为 "break" 时超过阈值
    """
    if not command:
        return None, ""

    tool_name, args_str = parse_command_signature(command)
    if not tool_name:
        return None, ""

    # 使用 LoopDetector 检查
    result = check_loop(tool_name, args_str if args_str else None)

    if result == "break":
        return "break", LOOP_BREAK_MESSAGE
    elif result == "warn":
        return "warn", LOOP_WARNING_MESSAGE

    return None, ""


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


def get_context_for_llm(command: str) -> Dict[str, Any]:
    """
    为 LLM 生成上下文信息

    根据当前状态，返回 LLM 需要知道的信息，
    帮助它自主决策下一步应该做什么。
    """
    context_parts = []

    # 1. 状态摘要
    state_summary = get_state_summary()
    if state_summary:
        context_parts.append(state_summary)

    # 2. 失败记录
    failures_summary = get_failures_summary()
    if failures_summary:
        context_parts.append(failures_summary)

    # 3. 知识库信息
    knowledge_info = get_knowledge_info()
    if knowledge_info:
        context_parts.append(knowledge_info)

    # 4. 根据状态给出建议
    state = load_json(STATE_FILE)
    suggestions = []

    if not state:
        suggestions.append("【建议】这是新的解题任务，请先用 curl 访问目标页面识别题型。")
    elif not state.get("flag"):
        suggestions.append("【建议】Flag 尚未找到，继续尝试其他方法。")
        if state.get("methods_tried"):
            suggestions.append("【建议】可以查看 memories/experiences/ 目录下的成功经验作为参考。")
    else:
        suggestions.append("【建议】Flag 已找到，任务完成！")

    if suggestions:
        context_parts.append("\n".join(suggestions))

    # 5. 检查命令是否包含已失败的方法
    target = state.get("target", "") if state else ""
    failures = get_failures_for_target(target)
    if failures and command:
        failed_warnings = check_command_for_failed_methods(command, failures)
        if failed_warnings:
            context_parts.append("\n【Hook 警告 - 方法已失败】")
            for w in failed_warnings:
                context_parts.append(f"  ⚠️ {w}")
            context_parts.append("建议：换用其他方法，或基于失败原因调整 bypass 策略")

    # 6. 循环检测
    if command:
        loop_status, loop_message = check_loop_detection(command)
        if loop_status:
            context_parts.append(f"\n【Hook 警告 - {loop_status.upper()}】")
            context_parts.append(loop_message)

    return {
        "continue": True,  # 不阻止执行，让 LLM 自己决定
        "hookSpecificOutput": {
            "additionalContext": "\n".join(context_parts) if context_parts else ""
        }
    }


def main():
    """Hook 入口"""
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

    # 提供上下文（不阻止执行）
    result = get_context_for_llm(command)
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
