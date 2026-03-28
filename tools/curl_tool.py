"""
Curl 工具 - 直接模式下的 HTTP 请求执行
"""
import subprocess
import urllib.parse
from typing import Optional


def curl(url: str, method: str = "GET", data: Optional[dict] = None,
         headers: Optional[dict] = None, timeout: int = 30) -> str:
    """
    执行 HTTP 请求

    Args:
        url: 目标 URL
        method: HTTP 方法 (GET/POST/HEAD)
        data: POST 参数字典
        headers: 请求头字典
        timeout: 超时秒数

    Returns:
        响应文本
    """
    cmd = ["curl", "-s", "-k", "--connect-timeout", str(timeout)]

    if method == "POST":
        cmd.append("-X POST")
    elif method == "HEAD":
        cmd.append("-I")

    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    if data:
        encoded = urllib.parse.urlencode(data)
        if method == "POST":
            cmd.extend(["-d", encoded])
        else:
            url = url + ("?" if "?" not in url else "&") + encoded

    cmd.append(url)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return result.stdout or result.stderr or ""
    except subprocess.TimeoutExpired:
        return f"[Error] Request timeout after {timeout}s"
    except Exception as e:
        return f"[Error] {type(e).__name__}: {e}"
