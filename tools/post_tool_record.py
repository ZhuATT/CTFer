#!/usr/bin/env python3
"""
post_tool_record.py - PostToolUse Hook 自动记录模块

在每次攻击命令执行后自动调用，记录：
1. add_method() - 记录已使用的方法
2. record_failure() - 分析失败原因并记录（如果失败）
3. increment_step() - 更新当前阶段步数

使用方式：
在 curl/sqlmap 等攻击命令后，Bash 调用：
python post_tool_record.py <tool_name> [args]

示例：
python post_tool_record.py curl "http://target.com?id=1"
python post_tool_record.py sqlmap "--dbs"
"""
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# 工作目录
WORKSPACE = Path(__file__).parent.parent / "workspace"
STATE_FILE = WORKSPACE / "state.json"
FAILURES_FILE = WORKSPACE / "failures.json"
LAST_COMMAND_FILE = WORKSPACE / ".last_command"


def load_json(path: Path) -> Optional[Dict]:
    """加载 JSON 文件"""
    if not path.exists():
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def save_json(path: Path, data: Any) -> None:
    """保存 JSON 文件"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_last_command_result() -> Optional[Dict[str, Any]]:
    """获取上一次命令结果"""
    if not LAST_COMMAND_FILE.exists():
        return None
    try:
        return json.loads(LAST_COMMAND_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return None


def analyze_command_success(command: str, output: str, return_code: int) -> Tuple[bool, str]:
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


def add_method_to_state(tool_name: str) -> None:
    """将方法添加到状态"""
    state = load_json(STATE_FILE)
    if not state:
        return

    methods_tried = state.get("methods_tried", [])
    if tool_name not in methods_tried:
        methods_tried.append(tool_name)
        state["methods_tried"] = methods_tried
        save_json(STATE_FILE, state)


def increment_step_count() -> int:
    """增加步数计数"""
    state = load_json(STATE_FILE)
    if not state:
        return 0

    step_count = state.get("step_count", 0) + 1
    state["step_count"] = step_count
    save_json(STATE_FILE, state)
    return step_count


def record_failure_to_tracker(
    tool_name: str,
    reason: str,
    payload: str = "",
    target: str = "",
    category: str = ""
) -> None:
    """记录失败到 failures.json"""
    if not target:
        state = load_json(STATE_FILE)
        if state:
            target = state.get("target", "")
            category = state.get("type", "")

    if not target:
        return

    # 加载现有失败记录
    failures = load_json(FAILURES_FILE) or []

    # 检查是否已存在相同记录
    for f in failures:
        if f.get("target") == target and f.get("method") == tool_name:
            # 更新现有记录
            f["reason"] = reason
            f["payload"] = payload
            from datetime import datetime
            f["updated_at"] = datetime.now().isoformat()
            save_json(FAILURES_FILE, failures)
            return

    # 新增记录
    from datetime import datetime
    failures.append({
        "target": target,
        "method": tool_name,
        "reason": reason,
        "payload": payload,
        "category": category,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    })
    save_json(FAILURES_FILE, failures)


def auto_record() -> str:
    """
    自动记录上一次命令执行结果

    流程：
    1. 读取上一次的命令结果
    2. 分析是否成功
    3. 如果失败，记录到 failures.json
    4. 增加步数
    5. 添加方法到状态

    Returns:
        记录结果描述
    """
    # 获取上一次命令结果
    last_result = get_last_command_result()
    if not last_result:
        return "无上一次命令结果，跳过记录"

    command = last_result.get("command", "")
    output = last_result.get("output", "")
    return_code = last_result.get("return_code", 0)

    # 解析工具名
    tool_name = parse_tool_name(command)
    if not tool_name:
        return f"无法识别工具名: {command[:50]}"

    # 分析是否成功
    is_success, reason = analyze_command_success(command, output, return_code)

    # 记录方法
    add_method_to_state(tool_name)

    # 增加步数
    step_count = increment_step_count()

    if is_success:
        return f"✓ {tool_name} 执行成功 (step: {step_count})"
    else:
        # 失败，记录到 failures.json
        record_failure_to_tracker(tool_name, reason, command)
        return f"✗ {tool_name} 执行失败: {reason} (step: {step_count})"


def parse_tool_name(command: str) -> str:
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


def main():
    """主入口"""
    if len(sys.argv) < 2:
        # 自动记录上一次命令
        result = auto_record()
        print(result)
        return

    # 手动指定工具名
    tool_name = sys.argv[1]

    # 记录方法
    add_method_to_state(tool_name)

    # 增加步数
    step_count = increment_step_count()

    print(f"✓ 已记录方法: {tool_name} (step: {step_count})")


if __name__ == "__main__":
    main()
