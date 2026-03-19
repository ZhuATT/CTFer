"""
SQLMap 工具封装
===============

封装 sqlmap 的常用功能，提供简洁的 Python 调用接口。

使用示例:
    from toolkit import sqlmap

    # 基础扫描
    result = sqlmap.scan("http://target.com/page?id=1")

    # 高级扫描
    result = sqlmap.scan(
        url="http://target.com/page?id=1",
        level=5,
        risk=3,
        tamper="space2comment",
        dump=True
    )

    # 检查结果
    if result.success:
        print(result.stdout)
"""

import re
import logging
from typing import Dict, Any, Optional, List
from ..base import BaseTool, ToolResult, load_config


class SQLMapTool(BaseTool):
    """
    SQLMap 工具封装

    支持的参数:
        url: 目标 URL（必需）
        level: 测试等级 1-5（默认 1）
        risk: 风险等级 1-3（默认 1）
        batch: 非交互模式（默认 True）
        tamper: 混淆脚本
        dbms: 指定数据库类型
        technique: 注入技术 (BEUSTQ)
        dump: 是否导出数据
        dump_all: 导出所有数据
        databases: 列出数据库
        tables: 列出表
        columns: 列出列
        cookie: Cookie 字符串
        headers: 自定义请求头
        proxy: 代理地址
        random_agent: 随机 User-Agent
    """

    # 注入点检测成功的关键词
    SUCCESS_PATTERNS = [
        r"sqlmap identified the following injection point",
        r"Parameter: .* is vulnerable",
        r"available databases",
        r"Database: \w+",
        r"Table: \w+",
        r"flag\{[^}]+\}",
        r"ctf\{[^}]+\}",
    ]

    def _build_command(self, **kwargs) -> str:
        """构建 sqlmap 命令行参数"""

        # 必需参数
        url = kwargs.get("url")
        if not url:
            raise ValueError("url 参数是必需的")

        args = [f'-u "{url}"']

        # 测试等级
        level = kwargs.get("level", 1)
        args.append(f"--level={level}")

        # 风险等级
        risk = kwargs.get("risk", 1)
        args.append(f"--risk={risk}")

        # 非交互模式（默认开启）
        if kwargs.get("batch", True):
            args.append("--batch")

        # 混淆脚本
        if kwargs.get("tamper"):
            args.append(f"--tamper={kwargs['tamper']}")

        # 指定数据库类型
        if kwargs.get("dbms"):
            args.append(f"--dbms={kwargs['dbms']}")

        # 注入技术
        if kwargs.get("technique"):
            args.append(f"--technique={kwargs['technique']}")

        # Cookie
        if kwargs.get("cookie"):
            args.append(f'--cookie="{kwargs["cookie"]}"')

        # 自定义请求头
        if kwargs.get("headers"):
            for key, value in kwargs["headers"].items():
                args.append(f'--headers="{key}: {value}"')

        # 代理
        if kwargs.get("proxy"):
            args.append(f'--proxy="{kwargs["proxy"]}"')

        # 随机 User-Agent
        if kwargs.get("random_agent"):
            args.append("--random-agent")

        # 数据操作
        if kwargs.get("databases"):
            args.append("--dbs")

        if kwargs.get("tables"):
            if isinstance(kwargs["tables"], str):
                args.append(f'-D "{kwargs["tables"]}" --tables')
            else:
                args.append("--tables")

        if kwargs.get("columns"):
            if isinstance(kwargs["columns"], dict):
                db = kwargs["columns"].get("db")
                table = kwargs["columns"].get("table")
                if db and table:
                    args.append(f'-D "{db}" -T "{table}" --columns')
            else:
                args.append("--columns")

        if kwargs.get("dump"):
            if isinstance(kwargs["dump"], dict):
                db = kwargs["dump"].get("db")
                table = kwargs["dump"].get("table")
                if db and table:
                    args.append(f'-D "{db}" -T "{table}" --dump')
                elif db:
                    args.append(f'-D "{db}" --dump')
            else:
                args.append("--dump")

        if kwargs.get("dump_all"):
            args.append("--dump-all")

        # 指定要获取的数据
        if kwargs.get("get"):
            args.append(f'--get="{kwargs["get"]}"')

        # POST 数据
        if kwargs.get("data"):
            args.append(f'--data="{kwargs["data"]}"')

        # 延迟
        if kwargs.get("delay"):
            args.append(f"--delay={kwargs['delay']}")

        # 超时
        if kwargs.get("timeout"):
            args.append(f"--timeout={kwargs['timeout']}")

        # 线程数
        if kwargs.get("threads"):
            args.append(f"--threads={kwargs['threads']}")

        return " ".join(args)

    def _check_success(self, output: str) -> bool:
        """检查是否发现注入点或获取到数据"""
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, output, re.IGNORECASE):
                return True
        return False

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        解析 sqlmap 输出

        Returns:
            {
                "injection_found": bool,
                "databases": List[str],
                "tables": List[str],
                "data": str,
                "flags": List[str],
                "vulnerable_param": str,
            }
        """
        result = {
            "injection_found": False,
            "databases": [],
            "tables": [],
            "data": "",
            "flags": [],
            "vulnerable_param": None,
        }

        # 检查注入点
        if re.search(r"sqlmap identified the following injection point", output):
            result["injection_found"] = True

        # 提取漏洞参数
        param_match = re.search(r"Parameter: (\w+)", output)
        if param_match:
            result["vulnerable_param"] = param_match.group(1)

        # 提取数据库名
        db_matches = re.findall(r"\[\*\] (\w+)", output)
        if db_matches:
            result["databases"] = db_matches

        # 提取表名
        table_matches = re.findall(r"\| (\w+) \|", output)
        if table_matches:
            result["tables"] = list(set(table_matches))

        # 提取 Flag
        flag_patterns = [
            r"flag\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"FLAG\{[^}]+\}",
        ]
        for pattern in flag_patterns:
            flags = re.findall(pattern, output, re.IGNORECASE)
            result["flags"].extend(flags)

        return result


# ==================== 便捷函数 ====================

def scan(url: str, **kwargs) -> ToolResult:
    """
    快速扫描 SQL 注入

    Args:
        url: 目标 URL
        level: 测试等级 1-5（默认 1）
        risk: 风险等级 1-3（默认 1）
        **kwargs: 其他 sqlmap 参数

    Returns:
        ToolResult 执行结果

    Example:
        result = sqlmap.scan("http://target.com/page?id=1", level=3)
        if result.success:
            print("发现注入点!")
            print(result.stdout)
    """
    config = load_config()
    tool = SQLMapTool("sqlmap", config["tools"]["sqlmap"], config)
    return tool.run(url=url, **kwargs)


def deep_scan(url: str, **kwargs) -> ToolResult:
    """
    深度扫描（level=5, risk=3）

    适用于简单扫描未发现注入点的情况
    """
    return scan(url, level=5, risk=3, **kwargs)


def dump_database(url: str, db: str = None, table: str = None, **kwargs) -> ToolResult:
    """
    导出数据库内容

    Args:
        url: 目标 URL
        db: 数据库名
        table: 表名
    """
    if db and table:
        return scan(url, dump={"db": db, "table": table}, **kwargs)
    elif db:
        return scan(url, dump={"db": db}, **kwargs)
    else:
        return scan(url, dump_all=True, **kwargs)


def list_databases(url: str, **kwargs) -> ToolResult:
    """列出所有数据库"""
    return scan(url, databases=True, **kwargs)


def list_tables(url: str, db: str, **kwargs) -> ToolResult:
    """列出指定数据库的表"""
    return scan(url, tables=db, **kwargs)


def bypass_waf(url: str, tamper: str = "space2comment", **kwargs) -> ToolResult:
    """
    尝试绕过 WAF

    Args:
        url: 目标 URL
        tamper: 混淆脚本名称
    """
    return scan(url, tamper=tamper, level=3, **kwargs)
