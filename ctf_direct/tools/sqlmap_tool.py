"""
SQLMap 工具 - SQL 注入检测与利用
"""
import subprocess
import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any


# 工具路径
SQLMAP_PATH = Path(__file__).parent.parent.parent / "tools_source" / "sqlmap" / "sqlmap.py"


def scan(
    url: str,
    method: str = "GET",
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    level: int = 1,
    risk: int = 1,
    timeout: int = 60,
    batch: bool = True,
) -> str:
    """
    执行 SQL 注入扫描

    Args:
        url: 目标 URL
        method: HTTP 方法 (GET/POST)
        data: POST 数据
        cookie: Cookie 头
        level: 检测级别 (1-5)
        risk: 风险级别 (1-3)
        timeout: 超时秒数
        batch: 批处理模式（自动选择）

    Returns:
        扫描结果文本
    """
    cmd = [
        "python",
        str(SQLMAP_PATH),
        "-u", url,
        "--level", str(level),
        "--risk", str(risk),
        "--timeout", str(timeout),
    ]

    if method.upper() == "POST":
        cmd.append("--method=POST")

    if data:
        cmd.extend(["--data", data])

    if cookie:
        cmd.extend(["--cookie", cookie])

    if batch:
        cmd.append("--batch")

    # 不使用太暴力的选项
    cmd.extend(["--threads", "5"])
    cmd.append("--keep-alive")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * 2,  # sqlmap 通常需要更长时间
        )
        return result.stdout or result.stderr or ""
    except subprocess.TimeoutExpired:
        return f"[Error] SQLMap timeout after {timeout * 2}s"
    except Exception as e:
        return f"[Error] {type(e).__name__}: {e}"


def deep_scan(
    url: str,
    data: Optional[str] = None,
    cookie: Optional[str] = None,
) -> str:
    """
    深度扫描（更高等级，更全面但更慢）
    """
    return scan(
        url=url,
        data=data,
        cookie=cookie,
        level=3,
        risk=2,
        timeout=120,
        batch=True,
    )


def parse_vulnerabilities(output: str) -> List[Dict[str, Any]]:
    """
    解析 sqlmap 输出，提取发现的漏洞信息
    """
    vulns = []

    # 检查是否发现注入点
    if "is vulnerable" in output.lower() or "vulnerable" in output.lower():
        # 提取 URL 和注入类型
        url_match = re.search(r"URL: (.+)", output)
        if url_match:
            vuln_type_match = re.search(r"Type: (.+)", output)
            payload_match = re.search(r"Payload: (.+)", output)

            vulns.append({
                "url": url_match.group(1) if url_match else "",
                "type": vuln_type_match.group(1) if vuln_type_match else "unknown",
                "payload": payload_match.group(1) if payload_match else "",
            })

    # 检查 SQL 错误
    sql_errors = [
        "mysql", "syntax error", "sql", "odbc", "ora-", "postgresql",
        "sqlite", "microsoft sql server", "oracle", "sybase"
    ]
    for error in sql_errors:
        if error in output.lower() and error not in str(vulns):
            vulns.append({
                "type": "sql_error",
                "error": error,
            })

    return vulns
