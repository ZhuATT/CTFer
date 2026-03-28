#!/usr/bin/env python3
"""
check_knowledge_hook.py - 强制知识检查的 PreToolUse Hook
在执行 curl/sqlmap/dirsearch 前验证是否已完成知识准备

Windows/Linux 兼容
"""
import os
import sys
import json
import time
from pathlib import Path

# 需要知识准备的命令模式
NEED_KNOWLEDGE_PATTERNS = ["curl", "sqlmap", "dirsearch"]
MARKER_FILE = Path(__file__).parent.parent.parent / "workspace" / ".knowledge_checked"
MARKER_EXPIRE_SECONDS = 1800  # 30分钟


def check_command_needs_knowledge(command: str) -> bool:
    """检查命令是否需要知识准备"""
    command_lower = command.lower()
    return any(p in command_lower for p in NEED_KNOWLEDGE_PATTERNS)


def is_marker_valid() -> bool:
    """检查 marker 是否存在且未过期"""
    if not MARKER_FILE.exists():
        return False

    try:
        mtime = MARKER_FILE.stat().st_mtime
        now = time.time()
        age = now - mtime
        return age < MARKER_EXPIRE_SECONDS
    except OSError:
        return False


def get_additional_context() -> str:
    """生成提醒文本"""
    return """【知识检查提醒】你即将执行攻击工具但尚未完成知识准备！

请按以下顺序完成：

1. 【识别题型】根据页面结构识别是什么类型（rce/sqli/auth/lfi/xss/upload）
2. 【加载技能知识】Read skills/<type>/SKILL.md
   - 例如: Read skills/rce/SKILL.md
3. 【RAG 检索】python -c "from core.rag_knowledge import search_knowledge; search_knowledge('关键字', top_k=5)"
   - search_knowledge 会自动创建 .knowledge_checked 标记
4. 【参考经验】Read memories/experiences/<type>.md

完成以上步骤后再重试此命令。"""


def main():
    try:
        # 从 stdin 读取 hook 输入 (JSON)
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # 无法解析，放行
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

    if not command:
        # 无法提取命令，放行
        print("{}", flush=True)
        return

    # 检查命令是否需要知识准备
    if not check_command_needs_knowledge(command):
        # 不需要知识的命令，放行
        print("{}", flush=True)
        return

    # 这是需要知识的工具命令，检查 marker
    marker_exists = MARKER_FILE.exists()
    marker_valid = is_marker_valid()

    if not marker_exists or not marker_valid:
        # 没有 marker 或已过期，阻止执行（除非是知识查询命令）
        result = {
            "continue": False,
            "hookSpecificOutput": {
                "additionalContext": get_additional_context() if not marker_exists else
                    "【知识检查提醒】距离上次查询知识已超过 30 分钟，请确认当前思路是否仍然有效。\n\n建议重新执行：python mark_knowledge_checked.py"
            },
            "systemMessage": "请先完成知识准备！" if not marker_exists else "知识查询已过期，请重新查询"
        }
        print(json.dumps(result), flush=True)
        return

    # 放行
    print("{}", flush=True)


if __name__ == "__main__":
    main()
