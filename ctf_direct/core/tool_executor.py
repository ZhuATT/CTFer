"""
工具执行器 - 直接模式的核心组件
将 LLM 的工具调用请求路由到具体的工具实现
"""
import time
from typing import Any, Callable, Dict, Optional

from ctf_direct.tools.curl_tool import curl as curl_impl
from ctf_direct.tools.python_tool import execute_python as python_impl
from ctf_direct.tools.dirsearch_tool import scan as dirsearch_impl, quick_scan as dirsearch_quick_impl
from ctf_direct.tools.sqlmap_tool import scan as sqlmap_impl, deep_scan as sqlmap_deep_impl


# 工具注册表
TOOL_REGISTRY: Dict[str, Callable] = {
    "curl": curl_impl,
    "execute_python": python_impl,
    "dirsearch": dirsearch_impl,
    "dirsearch_quick": dirsearch_quick_impl,
    "sqlmap": sqlmap_impl,
    "sqlmap_deep": sqlmap_deep_impl,
}

# 工具 schema（用于 function calling）
TOOL_SCHEMAS = {
    "curl": {
        "name": "curl",
        "description": "Execute HTTP GET/POST requests. Use this to probe URLs, send payloads, or retrieve source code.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "HEAD"],
                    "description": "HTTP method",
                    "default": "GET"
                },
                "data": {
                    "type": "object",
                    "description": "POST data as dict"
                },
                "headers": {
                    "type": "object",
                    "description": "HTTP headers"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 30
                }
            },
            "required": ["url"]
        }
    },
    "execute_python": {
        "name": "execute_python",
        "description": "Execute Python code for HTTP requests, data processing, or running exploits.",
        "parameters": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Python code to execute"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 60
                }
            },
            "required": ["code"]
        }
    },
    "dirsearch": {
        "name": "dirsearch",
        "description": "Directory and file scanner. Use this to discover hidden paths on web servers.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File extensions to scan",
                    "default": ["php", "html", "txt", "js"]
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of threads",
                    "default": 10
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 60
                }
            },
            "required": ["url"]
        }
    },
    "dirsearch_quick": {
        "name": "dirsearch_quick",
        "description": "Quick directory scan with default settings.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                }
            },
            "required": ["url"]
        }
    },
    "sqlmap": {
        "name": "sqlmap",
        "description": "SQL injection detector and exploiter. Use this to test URLs for SQL injection vulnerabilities.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method",
                    "default": "GET"
                },
                "data": {
                    "type": "string",
                    "description": "POST data string"
                },
                "level": {
                    "type": "integer",
                    "description": "Detection level (1-5)",
                    "default": 1
                },
                "risk": {
                    "type": "integer",
                    "description": "Risk level (1-3)",
                    "default": 1
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 60
                },
                "batch": {
                    "type": "boolean",
                    "description": "Batch mode (automatic)",
                    "default": True
                }
            },
            "required": ["url"]
        }
    },
    "sqlmap_deep": {
        "name": "sqlmap_deep",
        "description": "Deep SQL injection scan with higher accuracy and longer timeout.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL"
                },
                "data": {
                    "type": "string",
                    "description": "POST data string"
                }
            },
            "required": ["url"]
        }
    },
}


class ToolExecutor:
    """工具执行器：管理工具注册表，执行工具调用"""

    def __init__(self):
        self.tools = TOOL_REGISTRY.copy()
        self.execution_count = {}  # 工具执行计数（用于循环检测）

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """
        执行工具调用

        Args:
            tool_name: 工具名称
            arguments: 工具参数

        Returns:
            工具执行结果
        """
        if tool_name not in self.tools:
            return f"[Error] Unknown tool: {tool_name}. Available tools: {list(self.tools.keys())}"

        tool_func = self.tools[tool_name]

        # 计数
        self.execution_count[tool_name] = self.execution_count.get(tool_name, 0) + 1

        try:
            start = time.time()
            result = tool_func(**arguments)
            elapsed = time.time() - start

            # 格式化输出
            output = f"[Tool: {tool_name}] ({elapsed:.2f}s)\n{result}"
            return output
        except Exception as e:
            return f"[Error] {tool_name} failed: {type(e).__name__}: {e}"

    def get_schemas(self) -> list:
        """返回所有工具的 schema（用于 function calling）"""
        return list(TOOL_SCHEMAS.values())

    def reset_counts(self) -> None:
        """重置执行计数"""
        self.execution_count.clear()

    def get_counts(self) -> Dict[str, int]:
        """获取工具执行计数"""
        return self.execution_count.copy()
