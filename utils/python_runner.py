"""
虚拟环境 Python 执行封装
========================

确保所有 Python 脚本始终在 CTFagent 虚拟环境中执行，
避免手动激活和环境切换问题。

用法：
    from utils.python_runner import run_python_script

    result = run_python_script("test_causal_system.py")
"""

import subprocess
import sys
import os
from typing import List, Optional

# Virtualenv Python 路径
VENV_PYTHON = r"C:\Users\Administrator\Envs\CTFagent\Scripts\python.exe"


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
    if not os.path.exists(VENV_PYTHON):
        raise RuntimeError(f"CTFagent 虚拟环境 Python 不存在: {VENV_PYTHON}")

    if not os.path.exists(script_path):
        raise FileNotFoundError(f"脚本不存在: {script_path}")

    # 构建命令
    cmd = [VENV_PYTHON, script_path]
    if args:
        cmd.extend(args)

    # 执行
    try:
        result = subprocess.run(
            cmd,
            cwd=os.path.dirname(os.path.abspath(script_path)),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # 不检查退出码，由调用者处理
        )

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired as e:
        return -1, e.stdout or "", f"超时（{timeout}秒）"

    except Exception as e:
        return -1, "", f"执行错误: {str(e)}"


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

    if not os.path.exists(VENV_PYTHON):
        raise RuntimeError(f"CTFagent 虚拟环境 Python 不存在: {VENV_PYTHON}")

    # 创建临时文件
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(code)
        temp_file = f.name

    try:
        # 执行临时文件
        result = subprocess.run(
            [VENV_PYTHON, temp_file],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return result.returncode, result.stdout, result.stderr

    finally:
        # 清理临时文件
        try:
            os.unlink(temp_file)
        except:
            pass


if __name__ == "__main__":
    # 测试
    print("=" * 60)
    print("虚拟环境 Python 执行器测试")
    print("=" * 60)
    print(f"虚拟环境 Python: {VENV_PYTHON}")
    print()

    # 测试 1：执行简单代码
    print("[测试 1] 执行 Python 代码...")
    code = """
import sys
print(f"Python 路径: {sys.executable}")
print("Hello from virtualenv!")
"""

    exit_code, stdout, stderr = run_python_code(code)
    print(f"退出码: {exit_code}")
    print(f"输出: {stdout}")
    if stderr:
        print(f"错误: {stderr}")

    print()

    # 测试 2：执行脚本
    print("[测试 2] 执行 test_causal_system.py...")
    if os.path.exists("test_causal_system.py"):
        exit_code, stdout, stderr = run_python_script("test_causal_system.py", timeout=300)
        print(f"退出码: {exit_code}")
        print(f"输出长度: {len(stdout)} 字符")

        if exit_code != 0 and stderr:
            print(f"错误: {stderr[:500]}")
    else:
        print("test_causal_system.py 不存在")

    print("\n✅ 测试完成")
