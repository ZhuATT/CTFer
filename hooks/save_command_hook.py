#!/usr/bin/env python3
"""
save_command_hook.py - PostToolUse Hook 自动保存命令结果

在每次工具执行后自动调用，保存：
1. 命令本身
2. 命令输出
3. 返回码

这些数据会被 check_knowledge_hook.py 的 PreToolUse 读取并注入上下文

使用方式：
Claude Code 的 PostToolUse Hook 自动调用
"""
import json
import sys
from pathlib import Path
from datetime import datetime

# 工作目录
WORKSPACE = Path(__file__).parent.parent.parent / "workspace"
LAST_COMMAND_FILE = WORKSPACE / ".last_command"
DEBUG_LOG = WORKSPACE / "hook_debug.log"


def log_debug(msg: str) -> None:
    """调试日志"""
    try:
        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception:
        pass


def save_command_result(command: str, output: str, return_code: int = 0) -> None:
    """保存命令结果到文件（原子写入）"""
    LAST_COMMAND_FILE.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "command": command,
        "output": output[:5000] if output else "",
        "return_code": return_code,
        "timestamp": datetime.now().isoformat()
    }

    # 原子写入：先写临时文件再 rename
    tmp_file = LAST_COMMAND_FILE.with_suffix('.tmp')
    tmp_file.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    tmp_file.rename(LAST_COMMAND_FILE)


def main():
    """主入口 - 读取 PostToolUse Hook 输入并保存命令结果"""
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # 如果没有输入，尝试从参数读取（调试模式）
        print("{}", flush=True)
        return

    # 调试：记录原始输入
    log_debug(f"PostToolUse received: {json.dumps(input_data, ensure_ascii=False)[:500]}")

    # 提取命令信息
    command = ""
    output = ""
    return_code = 0

    if isinstance(input_data, dict):
        # PostToolUse 输入格式
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", {})

        if isinstance(tool_input, dict):
            command = tool_input.get("command", "")

        if isinstance(tool_response, dict):
            # Claude Code Bash 工具传递 exit_code，不是 return_code
            if "exit_code" in tool_response:
                return_code = tool_response.get("exit_code", 0)
            elif "return_code" in tool_response:
                return_code = tool_response.get("return_code", 0)

            # 解析输出（Bash 工具输出在 stdout 字段）
            if "stdout" in tool_response:
                output = str(tool_response.get("stdout", ""))
            elif "output" in tool_response:
                output = str(tool_response.get("output", ""))
            elif isinstance(tool_response, str):
                output = tool_response
            # stderr 也可能有用，但暂不处理

    # 保存命令结果
    if command:
        save_command_result(command, output, return_code)
        log_debug(f"Saved command: {command[:100]}, return_code: {return_code}, output_len: {len(output)}")

    # 返回空 JSON（PostToolUse Hook 不需要返回额外内容）
    print("{}", flush=True)


if __name__ == "__main__":
    main()
