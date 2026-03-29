#!/usr/bin/env python3
"""
check_knowledge_hook.py - 解题状态上下文提供者

当执行 Bash 工具时，提供当前解题状态和可用知识摘要，
帮助 LLM 做出明智的决策。

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
from datetime import datetime

# 工作目录
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
STATE_FILE = WORKSPACE / "state.json"
FAILURES_FILE = WORKSPACE / "failures.json"
LAST_COMMAND_FILE = WORKSPACE / ".last_command"
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


# ==================== 重写：Hook 主函数 ====================

def get_context_for_llm(command: str) -> Dict[str, Any]:
    """
    生成 Hook 上下文（核心逻辑）

    流程：
    1. 注入上一次命令结果到上下文
    2. 检查循环（check_loop）
    3. 检查失败阈值（should_trigger_rag）
    4. 注入所有警告和建议到 additionalContext
    """
    context_parts = []
    target = get_current_target()

    # ========== 1. 注入上一次命令结果到上下文 ==========
    last_result = get_last_command_result()
    if last_result:
        # 将上一次命令的输出片段注入 additionalContext，供 LLM 参考
        last_output = last_result.get("output", "")[:500]
        if last_output:
            context_parts.append(f"【上次命令输出】\n{last_output}")

    # ========== 2. 检查失败阈值 ==========
    if target:
        rerag_triggered, rerag_msg, count = should_trigger_rag(target)
        if rerag_triggered:
            context_parts.append(rerag_msg)

    # ========== 3. 检查循环 ==========
    loop_result = check_loop_detection(command)
    if loop_result:
        loop_status, loop_msg = loop_result
        context_parts.append(loop_msg)

        # break 级别尝试阻止
        if loop_status == "break":
            return {
                "continue": False,
                "hookSpecificOutput": {
                    "additionalContext": "\n".join(context_parts)
                }
            }

    # ========== 4. 状态摘要 ==========
    state_summary = get_state_summary()
    if state_summary:
        context_parts.insert(0, state_summary)

    # ========== 5. 失败记录摘要（未达阈值时） ==========
    if target and not rerag_triggered:
        failures = get_failures_list(target, max_rows=5)
        if failures and "（暂无" not in failures:
            context_parts.append(f"\n【已有失败记录】\n{failures}")

    # ========== 6. 检查命令是否包含已失败的方法 ==========
    failures_list = get_failures_for_target(target)
    if failures_list and command:
        failed_warnings = check_command_for_failed_methods(command, failures_list)
        if failed_warnings:
            context_parts.append("\n【Hook 警告 - 方法已失败】")
            for w in failed_warnings:
                context_parts.append(f"  ⚠️ {w}")
            context_parts.append("建议：换用其他方法，或基于失败原因调整 bypass 策略")

    # ========== 7. 知识库提示 ==========
    if not target:
        context_parts.append("\n📋 提示：这是新的解题任务，请先用 curl 访问目标识别题型。")

    return {
        "continue": True,
        "hookSpecificOutput": {
            "additionalContext": "\n".join(context_parts)
        }
    }


# ==================== 重写：main 函数 ====================

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
