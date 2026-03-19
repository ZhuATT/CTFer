"""
CTF Toolkit - 渗透测试工具封装
==============================

提供统一的工具调用接口，封装常用渗透测试工具。

使用示例:
 from toolkit import sqlmap, dirsearch, run_tool

 # 方式1：直接调用便捷函数
 result = sqlmap.scan("http://target.com/page?id=1")
 print(result.stdout)

 # 方式2：高级调用
 result = sqlmap.scan(
 url="http://target.com/page?id=1",
 level=5,
 risk=3,
 tamper="space2comment"
 )

 # 方式3：dirsearch 目录扫描
 result = dirsearch.scan(url="http://target.com", extensions=["php", "jsp"])
 if result.success:
 parsed = dirsearch.DirsearchTool(config, global_config).parse_output(result.stdout)
 print(f"发现 {parsed['count']} 个目录/文件")

 # 方式4：通用接口
 result = run_tool("sqlmap", url="http://target.com/page?id=1", level=3)
"""

from .base import BaseTool, ToolResult, load_config, get_tool
from . import sqlmap
from . import decoder
from . import dirsearch


# Decoder 便捷函数
from .decoder import (
 decode,
 encode,
 auto_decode,
 detect_encoding,
 supported_encodings,
 DecoderTool,
 DecodeResult,
)


# dirsearch 便捷函数
from .dirsearch import (
 scan,
 quick_scan,
 recursive_scan,
 DirsearchTool,
)


def run_tool(name: str, **kwargs) -> ToolResult:
    """
 通用工具调用接口

 Args:
 name: 工具名称 (sqlmap, dirsearch, fengjing)
 **kwargs: 工具参数

 Returns:
 ToolResult 执行结果

 Example:
 result = run_tool("sqlmap", url="http://target.com/page?id=1", level=3)
 """
    tool = get_tool(name)
    return tool.run(**kwargs)


__all__ = [
 # 基类
 "BaseTool",
 "ToolResult",
 "load_config",
 "get_tool",

 # 通用接口
 "run_tool",

 # 工具模块
 "sqlmap",
 "decoder",
 "dirsearch",

 # Decoder 便捷函数
 "decode",
 "encode",
 "auto_decode",
 "detect_encoding",
 "supported_encodings",
 "DecoderTool",
 "DecodeResult",

 # dirsearch 便捷函数
 "scan",
 "quick_scan",
 "recursive_scan",
 "DirsearchTool",
]
