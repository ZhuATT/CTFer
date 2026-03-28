"""
Python 工具 - 直接模式下的 Python 代码执行
直接通过 subprocess 执行，不依赖 Docker
"""
import subprocess
import sys
from typing import Dict, Any


def execute_python(code: str, timeout: int = 60) -> str:
    """
    执行 Python 代码

    Args:
        code: Python 代码
        timeout: 超时秒数

    Returns:
        执行结果（stdout + stderr）
    """
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr:
            output += "\n[stderr]\n" + result.stderr
        if not output:
            output = "[No output]"
        return output
    except subprocess.TimeoutExpired:
        return f"[Error] Python execution timeout after {timeout}s"
    except Exception as e:
        return f"[Error] {type(e).__name__}: {e}"


def get_tool_schema() -> Dict[str, Any]:
    """返回工具的 schema（用于 function calling）"""
    return {
        "name": "execute_python",
        "description": "Execute Python code. Use this for HTTP requests (requests library), data processing, or running exploits.",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute. Can use requests, subprocess, etc."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 60
                }
            },
            "required": ["code"]
        }
    }
