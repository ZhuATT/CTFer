"""
Dirsearch 工具 - 目录扫描
"""
import subprocess
import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any


# 工具路径
DIRSEARCH_PATH = Path(__file__).parent.parent.parent / "tools_source" / "dirsearch" / "dirsearch.py"


def scan(
    url: str,
    extensions: Optional[List[str]] = None,
    threads: int = 10,
    timeout: int = 60,
    wordlist: Optional[str] = None,
) -> str:
    """
    执行目录扫描

    Args:
        url: 目标 URL
        extensions: 扩展名列表，如 ["php", "html", "txt"]
        threads: 线程数
        timeout: 超时秒数
        wordlist: 字典路径，默认使用内置

    Returns:
        扫描结果文本
    """
    if extensions is None:
        extensions = ["php", "html", "txt", "js", "xml", "json"]

    cmd = [
        "python",
        str(DIRSEARCH_PATH),
        "-u", url,
        "-e", ",".join(extensions),
        "-t", str(threads),
        "--timeout", str(timeout),
        "--follow-redirects",
        "--quiet",
    ]

    if wordlist:
        cmd.extend(["-w", wordlist])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        return result.stdout or result.stderr or ""
    except subprocess.TimeoutExpired:
        return f"[Error] Dirsearch timeout after {timeout}s"
    except Exception as e:
        return f"[Error] {type(e).__name__}: {e}"


def parse_results(output: str) -> List[Dict[str, Any]]:
    """
    解析 dirsearch 输出，提取发现的路径

    Returns:
        [{"url": str, "status": int, "size": int, "redirect": str}]
    """
    results = []
    # 常见格式: 200 | 3KB | /path/to/file.php
    pattern = re.compile(r"(\d{3})\s+\|\s+(\S+)\s+\|\s+(\S+)")

    for line in output.split("\n"):
        match = pattern.search(line)
        if match:
            status = int(match.group(1))
            size = match.group(2)
            path = match.group(3)
            results.append({
                "url": path,
                "status": status,
                "size": size,
            })

    return results


def quick_scan(url: str, extensions: Optional[List[str]] = None) -> str:
    """快速扫描（默认配置）"""
    return scan(url, extensions=extensions, threads=10, timeout=30)
