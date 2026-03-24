"""
虚拟环境 Python 执行封装
========================

确保所有 Python 脚本始终在 CTFagent 虚拟环境中执行，
避免手动激活和环境切换问题。

用法：
    from utils.python_runner import run_python_script

    result = run_python_script("test_causal_system.py")
"""

import os
from pathlib import Path
from typing import List, Optional

from toolkit.base import get_venv_python, run_subprocess


def run_python_script(script_path: str, args: Optional[List[str]] = None, timeout: int = 120) -> tuple[int, str, str]:
    """
    在虚拟环境中执行 Python 脚本

    参数：
        script_path: 脚本路径
        args: 命令行参数列表
        timeout: 超时时间（秒）

    返回：
        (exit_code, stdout, stderr)
    """
    python_exe = get_venv_python()
    script_abspath = Path(script_path).resolve()

    if not script_abspath.exists():
        raise FileNotFoundError(f"脚本不存在: {script_path}")

    cmd = [python_exe, str(script_abspath)]
    if args:
        cmd.extend(args)

    try:
        result = run_subprocess(
            cmd,
            timeout=timeout,
            cwd=script_abspath.parent,
        )
        return result.returncode, result.stdout, result.stderr

    except Exception as e:
        error_message = str(e)
        if "timed out" in error_message.lower():
            return -1, "", f"超时（{timeout}秒）"
        return -1, "", f"执行错误: {error_message}"


def run_python_code(code: str, timeout: int = 60) -> tuple[int, str, str]:
    """
    在虚拟环境中执行 Python 代码字符串

    参数：
        code: Python 代码字符串
        timeout: 超时时间（秒）

    返回：
        (exit_code, stdout, stderr)
    """
    import tempfile

    get_venv_python()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        temp_file = f.name

    try:
        return run_python_script(temp_file, timeout=timeout)
    finally:
        try:
            os.unlink(temp_file)
        except:
            pass


