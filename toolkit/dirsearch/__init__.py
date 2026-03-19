"""
dirsearch 目录扫描工具封装

提供对 dirsearch 目录爆破工具的封装接口，支持常见的目录扫描功能。
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Union, Any

from ..base import BaseTool, ToolResult


class DirsearchTool(BaseTool):
    """dirsearch 目录扫描工具封装"""

    def __init__(self, config: dict, global_config: dict):
        """
        初始化 dirsearch 工具

        Args:
            config: 工具配置（来自 config.json 的 tools.dirsearch）
            global_config: 全局配置
        """
        super().__init__("dirsearch", config, global_config)

    def _build_command(self, **kwargs) -> str:
        """
        构建命令行参数

        Args:
            url: 目标 URL
            extensions: 扩展名列表或字符串
            wordlist: 字典文件路径
            threads: 线程数
            recursive: 是否递归
            depth: 递归深度
            timeout: 超时时间
            follow_redirects: 跟随重定向
            user_agent: User-Agent
            cookie: Cookie
            headers: 请求头字典
            status_codes: 包含的状态码
            exclude_status: 排除的状态码
            max_time: 最大运行时间
            proxy: 代理
            output_format: 输出格式 (默认: json)

        Returns:
            str: 命令行参数字符串
        """
        args = []

        # 基本参数
        url = kwargs.get("url")
        if url:
            args.extend(["-u", f'"{url}"'])

        # 扩展名
        extensions = kwargs.get("extensions")
        if extensions:
            if isinstance(extensions, list):
                extensions = ",".join(extensions)
            args.extend(["-e", f'"{extensions}"'])

        # 字典
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-w", f'"{wordlist}"'])

        # 线程
        threads = kwargs.get("threads")
        if threads:
            args.extend(["-t", str(threads)])

        # JSON 输出到 stdout
        args.extend(["-o", "-", "-O", "json"])

        # 递归
        if kwargs.get("recursive"):
            args.append("--recursive")
            depth = kwargs.get("depth")
            if depth:
                args.extend(["--max-recursion-depth", str(depth)])

        # 超时
        timeout = kwargs.get("timeout")
        if timeout:
            args.extend(["--timeout", str(timeout)])

        # 跟随重定向
        if kwargs.get("follow_redirects"):
            args.append("--follow-redirects")

        # User-Agent
        user_agent = kwargs.get("user_agent")
        if user_agent:
            args.extend(["--user-agent", f'"{user_agent}"'])

        # Cookie
        cookie = kwargs.get("cookie")
        if cookie:
            args.extend(["--cookie", f'"{cookie}"'])

        # 自定义请求头
        headers = kwargs.get("headers")
        if headers:
            for key, value in headers.items():
                args.extend(["--header", f'"{key}:{value}"'])

        # 包含的状态码
        status_codes = kwargs.get("status_codes")
        if status_codes:
            status_str = ",".join(str(code) for code in status_codes)
            args.extend(["-i", f'"{status_str}"'])

        # 排除的状态码
        exclude_status = kwargs.get("exclude_status")
        if exclude_status:
            exclude_str = ",".join(str(code) for code in exclude_status)
            args.extend(["-x", f'"{exclude_str}"'])

        # 最大运行时间
        max_time = kwargs.get("max_time")
        if max_time:
            args.extend(["--max-time", str(max_time)])

        # 代理
        proxy = kwargs.get("proxy")
        if proxy:
            args.extend(["--proxy", f'"{proxy}"'])

        # 安静模式（可选）
        if kwargs.get("quiet"):
            args.append("-q")

        return " ".join(args)

    def _check_success(self, output: str) -> bool:
        """
        检查输出是否表示成功

        Args:
            output: 命令输出

        Returns:
            bool: True 表示成功
        """
        # dirsearch 在发现结果时返回 0 或 1，都算成功
        return True  # 由基类的 run() 方法处理

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        解析 JSON 输出

        Args:
            output: 命令输出

        Returns:
            Dict: 解析后的结果
        """
        try:
            # dirsearch 的 JSON 输出可能有多行
            results = []
            for line in output.strip().split('\n'):
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        # 非 JSON 行
                        if line and not line.startswith("["):
                            results.append({"text": line})
            return {"results": results, "count": len(results)}
        except Exception as e:
            return {"error": str(e), "raw_output": output}

    # 高阶接口，保持向后兼容
    def scan(self, **kwargs) -> ToolResult:
        """
        执行目录扫描（高阶接口）

        这个接口保持向后兼容，内部调用基类的 run() 方法。
        所有参数都会传递给 _build_command()。

        Returns:
            ToolResult: 包含扫描结果
        """
        # 调用基类的 run() 方法
        return self.run(**kwargs)

    def quick_scan(self, url: str, extensions: Optional[List[str]] = None) -> ToolResult:
        """
        快速默认扫描，使用常用配置

        Args:
            url: 目标 URL
            extensions: 文件扩展名，默认使用常见 Web 扩展

        Returns:
            ToolResult: 扫描结果
        """
        if extensions is None:
            extensions = ["php", "jsp", "asp", "aspx", "html", "js", "css"]

        return self.scan(
            url=url,
            extensions=extensions,
            threads=30,
            recursive=False,
            status_codes=[200, 204, 301, 302, 307, 401, 403],
        )

    def recursive_scan(self, url: str, extensions: Optional[List[str]] = None, depth: int = 3) -> ToolResult:
        """
        递归深度扫描

        Args:
            url: 目标 URL
            extensions: 文件扩展名
            depth: 递归深度 (默认: 3)

        Returns:
            ToolResult: 扫描结果
        """
        return self.scan(
            url=url,
            extensions=extensions,
            recursive=True,
            depth=depth,
            threads=20,
            status_codes=[200, 204, 301, 302, 307, 401, 403],
        )


# 模块级工具实例（用于高阶接口）
_dirsearch_tool = None


def _get_tool_instance() -> DirsearchTool:
    """获取或创建工具实例"""
    global _dirsearch_tool
    if _dirsearch_tool is None:
        from ..base import load_config
        config = load_config()
        tool_config = config["tools"]["dirsearch"]
        _dirsearch_tool = DirsearchTool(tool_config, config)
    return _dirsearch_tool


# 便捷函数接口
def scan(**kwargs) -> ToolResult:
    """
    目录扫描 - 便捷函数

    Example:
        >>> result = scan(url="http://example.com", extensions=["php", "jsp"])
        >>> if result.success:
        ...     parsed = _get_tool_instance().parse_output(result.stdout)
        ...     print(f"发现 {parsed['count']} 个条目")
    """
    return _get_tool_instance().scan(**kwargs)


def quick_scan(url: str, extensions: Optional[List[str]] = None) -> ToolResult:
    """
    快速扫描 - 便捷函数

    Example:
        >>> result = quick_scan(url="http://example.com")
    """
    return _get_tool_instance().quick_scan(url=url, extensions=extensions)


def recursive_scan(url: str, extensions: Optional[List[str]] = None, depth: int = 3) -> ToolResult:
    """
    递归深度扫描 - 便捷函数

    Example:
        >>> result = recursive_scan(url="http://example.com", depth=2)
    """
    return _get_tool_instance().recursive_scan(url=url, extensions=extensions, depth=depth)


__all__ = [
    "DirsearchTool",  # 工具类
    "scan",  # 便捷函数
    "quick_scan",
    "recursive_scan",
]
