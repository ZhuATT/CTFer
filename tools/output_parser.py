"""
工具输出解析器 - P4 组件
解析 curl/sqlmap/dirsearch 输出为结构化数据
"""
import re
from typing import Any, Dict, List, Optional, Tuple


# Flag 模式
FLAG_PATTERN = re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE)

# 数据库错误模式
DB_ERROR_PATTERNS = {
    "mysql": [
        r"mysql_fetch",
        r"mysql_error",
        r"You have an error in your SQL syntax",
        r"Warning: mysql_",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"PG::SyntaxError",
    ],
    "sqlite": [
        r"SQLite3::",
        r"sqlite3\.",
        r"SQLITE_ERROR",
    ],
    "mssql": [
        r"Microsoft SQL Server",
        r"Unclosed quotation mark",
        r"Msg \d+, Level \d+",
    ],
    "oracle": [
        r"ORA-\d+:",
        r"oracle.*error",
        r"SQL command not properly ended",
    ],
}

# 技术栈指纹
STACK_FINGERPRINTS = {
    "php": [r"<\?php", r"X-Powered-By:.*PHP", r"\.php(?:[0-9]+)?", r"PHP/[0-9.]+"],
    "apache": [r"Apache/[0-9.]+", r"Server: Apache"],
    "nginx": [r"nginx/[0-9.]+", r"Server: nginx"],
    "python": [r"Python/[0-9.]+", r"Flask", r"Django", r" werkzeug"],
    "nodejs": [r"Express", r"Node\.js", r"X-Powered-By: Express"],
    "java": [r"JSESSIONID", r"Server: Apache-Coyote", r"Tomcat", r"Spring"],
    "asp.net": [r"ASP\.NET", r"X-Powered-By: ASP\.NET", r"IIS/[0-9.]+"],
}


class ParseResult:
    """解析结果容器"""

    def __init__(self, vulnerable: bool = False, findings: Optional[Dict[str, Any]] = None):
        self.vulnerable = vulnerable
        self.findings = findings or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"vulnerable": self.vulnerable, "findings": self.findings}

    def __repr__(self) -> str:
        return f"ParseResult(vulnerable={self.vulnerable}, findings={self.findings})"


def parse_curl_output(output: str) -> ParseResult:
    """
    解析 curl 输出

    Returns:
        ParseResult {
            vulnerable: bool,
            findings: {
                "flags": [...],
                "errors": [...],
                "stack": {...},
                "interesting_strings": [...],
                "status_code": int
            }
        }
    """
    result = ParseResult()
    findings = {
        "flags": [],
        "errors": [],
        "stack": {},
        "interesting_strings": [],
        "status_code": 0,
    }

    # 提取 flag
    flags = FLAG_PATTERN.findall(output)
    if flags:
        findings["flags"] = list(set(flags))  # 去重
        result.vulnerable = True

    # 提取状态码
    status_match = re.search(r"HTTP/[0-9.]+ (\d{3})", output, re.IGNORECASE)
    if status_match:
        findings["status_code"] = int(status_match.group(1))

    # 检测数据库错误
    for db_type, patterns in DB_ERROR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                findings["errors"].append({
                    "type": "sql_error",
                    "db": db_type,
                    "pattern": pattern,
                })
                result.vulnerable = True
                break

    # 检测技术栈
    for stack, patterns in STACK_FINGERPRINTS.items():
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                findings["stack"][stack] = True
                break

    # 检测敏感信息
    sensitive_patterns = {
        "password": r"password[\"']?\s*[:=]\s*[\"']?[^\s\"']+",
        "api_key": r"(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?[^\s\"']+",
        "token": r"(?:token|secret|authorization)[\"']?\s*[:=]\s*[\"']?[^\s\"']+",
        "email": r"[\w.-]+@[\w.-]+\.\w+",
        "ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    }
    for key, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            findings["interesting_strings"].extend(matches[:5])  # 限制数量

    # 检测漏洞提示
    vuln_hints = [
        (r"SQL syntax|mysql syntax|SQL error", "sql_syntax_error"),
        (r"unserialize|unserialize\(\)", "unserialize"),
        (r"eval\(|assert\(|system\(|exec\(|shell_exec\(", "code_execution"),
        (r"file_get_contents|file_put_contents|fopen|readfile", "file_operation"),
        (r"include|require|require_once|include_once", "file_inclusion"),
        (r"Union|UNION|union select", "sql_union"),
        (r"sleep\(|benchmark\(|waitfor", "sql_time_based"),
        (r"admin|login|username|password", "auth_relevant"),
        (r"www\.example\.com|example\.com|attacker|反弹shell", "ctf_hint"),
    ]
    for pattern, vuln_type in vuln_hints:
        if re.search(pattern, output, re.IGNORECASE):
            findings["errors"].append({
                "type": "vulnerability_hint",
                "vuln_type": vuln_type,
                "matched": pattern,
            })

    result.findings = findings
    return result


def parse_sqlmap_output(output: str) -> ParseResult:
    """
    解析 sqlmap 输出

    Returns:
        ParseResult {
            vulnerable: bool,
            findings: {
                "injection_type": str,        # boolean/time-based/union/error-based/stacked
                "db_type": str,              # mysql/postgresql/mssql/etc
                "banner": str,               # 数据库版本信息
                "urls": [...],               # 发现注入点的 URL
                "payloads": [...],            # 使用的 payload
                "parameters": [...],          # 可注入的参数
            }
        }
    """
    result = ParseResult()
    findings = {
        "injection_type": "",
        "db_type": "",
        "banner": "",
        "urls": [],
        "payloads": [],
        "parameters": [],
    }

    output_lower = output.lower()

    # 检测是否发现注入
    vulnerable_indicators = [
        "is vulnerable",
        "vulnerability detected",
        "vulnerable",
        "sql injection vulnerability",
        "injection point",
    ]
    if any(ind in output_lower for ind in vulnerable_indicators):
        result.vulnerable = True

    # 检测注入类型
    injection_types = []
    if "boolean-based" in output_lower or "boolean blind" in output_lower:
        injection_types.append("boolean")
    if "time-based" in output_lower or "time blind" in output_lower or "sleep" in output_lower:
        injection_types.append("time-based")
    if "union" in output_lower:
        injection_types.append("union")
    if "error-based" in output_lower or "error based" in output_lower:
        injection_types.append("error-based")
    if "stacked" in output_lower:
        injection_types.append("stacked")

    if injection_types:
        findings["injection_type"] = "/".join(injection_types)

    # 检测数据库类型
    db_types = {
        "mysql": [r"mysql", r"mariadb"],
        "postgresql": [r"postgresql", r"postgres"],
        "mssql": [r"microsoft sql", r"mssql", r"sql server"],
        "oracle": [r"oracle"],
        "sqlite": [r"sqlite"],
        "firebird": [r"firebird"],
        "maxdb": [r"maxdb"],
        "sybase": [r"sybase"],
        "informix": [r"informix"],
    }

    for db_type, patterns in db_types.items():
        for pattern in patterns:
            if pattern in output_lower:
                findings["db_type"] = db_type
                break

    # 提取 URL
    url_matches = re.findall(r"URL: (.+)", output)
    findings["urls"] = list(set(url_matches))

    # 提取 Payload
    payload_matches = re.findall(r"Payload: (.+)", output)
    findings["payloads"] = list(set(payload_matches))[:10]  # 限制数量

    # 提取参数
    param_matches = re.findall(r"Parameter: ([^ \n]+)", output)
    findings["parameters"] = list(set(param_matches))

    # 提取 banner（数据库版本）
    banner_match = re.search(r"the back-end DBMS is ([^\n]+)", output, re.IGNORECASE)
    if banner_match:
        findings["banner"] = banner_match.group(1).strip()

    # 备用 banner 提取
    if not findings["banner"]:
        banner_match = re.search(r"DBMS: ([^\n]+)", output, re.IGNORECASE)
        if banner_match:
            findings["banner"] = banner_match.group(1).strip()

    result.findings = findings
    return result


def parse_dirsearch_output(output: str) -> ParseResult:
    """
    解析 dirsearch 输出

    Returns:
        ParseResult {
            vulnerable: bool,
            findings: {
                "urls": [...],      # 发现的路径
                "status_codes": {}, # 状态码统计
                "interesting": [...] # 可能有价值的路径
            }
        }
    """
    result = ParseResult()
    findings = {
        "urls": [],
        "status_codes": {},
        "interesting": [],
    }

    # 状态码模式
    status_pattern = re.compile(r"(\d{3})\s+-\s+(.+)")
    for match in status_pattern.finditer(output):
        status_code = match.group(1)
        path = match.group(2).strip()

        findings["urls"].append({"status": status_code, "path": path})

        # 统计
        findings["status_codes"][status_code] = findings["status_codes"].get(status_code, 0) + 1

        # 标记有价值的路径
        interesting_exts = [".php", ".asp", ".aspx", ".jsp", ".env", ".git", ".config", ".bak", ".sql", ".txt", ".md", ".yaml", ".yml"]
        if any(path.lower().endswith(ext) for ext in interesting_exts):
            findings["interesting"].append({"status": status_code, "path": path})

        # 200/301/302 是好的
        if status_code in ["200", "301", "302"]:
            result.vulnerable = True

    result.findings = findings
    return result


def parse_tool_output(output: str, tool: str) -> ParseResult:
    """
    统一解析入口

    Args:
        output: 工具输出文本
        tool: 工具名 ("curl", "sqlmap", "dirsearch")

    Returns:
        ParseResult
    """
    if tool.lower() in ["curl", "http"]:
        return parse_curl_output(output)
    elif tool.lower() in ["sqlmap", "sql"]:
        return parse_sqlmap_output(output)
    elif tool.lower() in ["dirsearch", "dir", "scan"]:
        return parse_dirsearch_output(output)
    else:
        return ParseResult(vulnerable=False, findings={"error": f"Unknown tool: {tool}"})


# 快捷函数
def parse_curl(output: str) -> Dict[str, Any]:
    """解析 curl 输出为字典"""
    return parse_curl_output(output).to_dict()


def parse_sqlmap(output: str) -> Dict[str, Any]:
    """解析 sqlmap 输出为字典"""
    return parse_sqlmap_output(output).to_dict()


def parse_dirsearch(output: str) -> Dict[str, Any]:
    """解析 dirsearch 输出为字典"""
    return parse_dirsearch_output(output).to_dict()
