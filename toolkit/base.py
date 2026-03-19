"""
CTF Toolkit - 工具封装基类
==========================

提供统一的工具调用接口，支持虚拟环境执行。
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    command: str
    tool_name: str

    def __str__(self) -> str:
        if self.success:
            return f"[{self.tool_name}] 执行成功\n{self.stdout}"
        else:
            return f"[{self.tool_name}] 执行失败 (exit: {self.exit_code})\n{self.stderr}"

    @property
    def output(self) -> str:
        """获取完整输出"""
        return self.stdout + "\n" + self.stderr


class BaseTool:
    """
    工具基类

    子类需要实现:
        - _build_command(**kwargs) -> str: 构建命令行参数
        - parse_output(output: str) -> Dict: 解析输出结果
    """

    def __init__(self, name: str, config: dict, global_config: dict):
        self.name = name
        self.config = config
        self.global_config = global_config

        # 工具路径
        self.tools_source = Path(global_config.get("tools_source", "./tools_source"))
        if not self.tools_source.is_absolute():
            # 转换为绝对路径
            self.tools_source = Path(__file__).parent.parent / self.tools_source
        self.tool_path = self.tools_source / config["path"]

        # 超时设置
        self.timeout = config.get("timeout", 120)

        # 虚拟环境 Python 路径
        self.venv_python = global_config["venv"]["python_path"]

        # 验证工具存在
        if not self.tool_path.exists():
            raise FileNotFoundError(f"工具不存在: {self.tool_path}")

    def run(self, *args, **kwargs) -> ToolResult:
        """
        执行工具

        Args:
            **kwargs: 工具参数（子类定义）

        Returns:
            ToolResult 执行结果
        """
        # 1. 构建命令
        cmd_args = self._build_command(**kwargs)

        # 处理不同工具类型
        if self.name == "sqlmap":
            # sqlmap 通过 pip 安装，使用 python -m sqlmap 调用
            full_cmd = f'"{self.venv_python}" -m sqlmap {cmd_args}'
        elif self.tool_path.is_file():
            # 可执行文件
            full_cmd = f'"{self.venv_python}" "{self.tool_path}" {cmd_args}'
        else:
            # 目录/模块调用
            full_cmd = f'"{self.venv_python}" -m {self.name} {cmd_args}'

        logging.info(f"[Toolkit] 执行 {self.name}: {full_cmd}")

        # 2. 执行命令
        try:
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=self.timeout,
                cwd=str(self.tool_path.parent)
            )

            success = result.returncode == 0 or self._check_success(result.stdout)

            return ToolResult(
                success=success,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                command=full_cmd,
                tool_name=self.name
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"执行超时 ({self.timeout}秒)",
                command=full_cmd,
                tool_name=self.name
            )
        except Exception as e:
            return ToolResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"执行错误: {str(e)}",
                command=full_cmd,
                tool_name=self.name
            )

    def _build_command(self, **kwargs) -> str:
        """子类实现：构建命令行参数"""
        raise NotImplementedError

    def _check_success(self, output: str) -> bool:
        """检查输出是否表示成功（子类可覆盖）"""
        return False

    def parse_output(self, output: str) -> Dict[str, Any]:
        """子类实现：解析输出结果"""
        return {"raw": output}


def load_config() -> dict:
    """加载配置文件"""
    config_path = Path(__file__).parent.parent / "config.json"
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        raise FileNotFoundError(f"配置文件不存在: {config_path}")


def check_virtualenv_python() -> str:
    """
    检查并返回虚拟环境 Python 路径

    Returns:
        str: 虚拟环境 Python 的完整路径

    Raises:
        RuntimeError: 如果虚拟环境未配置或不存在
    """
    config = load_config()
    venv_path = config.get("virtualenv_path", "")

    if not venv_path:
        raise RuntimeError("虚拟环境路径未配置，请检查 config.json")

    python_exe = Path(venv_path) / "Scripts" / "python.exe"
    if not python_exe.exists():
        raise RuntimeError(f"虚拟环境 Python 不存在: {python_exe}")

    return str(python_exe)


def get_config() -> dict:
    """获取配置文件（兼容 dirsearch 模块的 get_config）"""
    return load_config()


def get_tool(name: str) -> BaseTool:
    """获取工具实例"""
    from . import sqlmap
    from . import dirsearch

    config = load_config()
    tool_config = config["tools"].get(name)

    if not tool_config:
        raise ValueError(f"未知工具: {name}")

    if not tool_config.get("enabled", False):
        raise ValueError(f"工具未启用: {name}")

    if name == "sqlmap":
        return sqlmap.SQLMapTool(tool_config, config)
    elif name == "dirsearch":
        return dirsearch.DirsearchTool(tool_config, config)
    else:
        raise ValueError(f"工具封装未实现: {name}")


__all__ = ["BaseTool", "ToolResult", "load_config", "check_virtualenv_python", "get_tool"]
