from __future__ import annotations

from typing import Any, Dict, List

CANONICAL_TYPE_ALIASES: Dict[str, List[str]] = {
    "sqli": ["sqli", "sql", "sql-injection", "sql injection"],
    "xss": ["xss", "cross-site scripting", "cross site scripting"],
    "lfi": ["lfi", "file-inclusion", "file inclusion", "rfi", "path traversal"],
    "rce": ["rce", "command execution", "code execution", "webshell"],
    "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
    "upload": ["upload", "file upload"],
    "auth": ["auth", "auth-bypass", "auth bypass", "authentication", "login"],
    "deserialization": ["deserialization", "deserialize", "unserialize"],
    "xxe": ["xxe", "xml external entity"],
    "ssti": ["ssti", "template injection", "server-side template injection"],
    "recon": ["recon", "web-recon", "web recon", "enumeration"],
    "tornado": ["tornado"],
    "flask": ["flask"],
    "django": ["django"],
    "unknown": ["unknown"],
}

KEYWORD_HINTS: Dict[str, List[str]] = {
    "sqli": ["sql", "sqlmap", "mysql", "postgresql", "database", "注入", "union", "select"],
    "xss": ["xss", "script", "alert", "跨站", "javascript"],
    "lfi": ["lfi", "file inclusion", "文件包含", "读取", "include", "path traversal", "php://filter"],
    "rce": ["rce", "远程代码", "command", "exec", "命令执行", "eval", "system", "shell", "cmd"],
    "ssrf": ["ssrf", "内网", "localhost", "gopher", "fetch"],
    "upload": ["upload", "上传", "文件上传"],
    "auth": ["登录", "login", "auth", "password", "认证", "bypass", "admin"],
    "deserialization": ["serialize", "unserialize", "pickle", "yaml", "反序列化"],
    "tornado": ["tornado", "tornado框架", "template"],
    "flask": ["flask", "jinja", "session"],
    "django": ["django", "django框架"],
    "ssti": ["ssti", "template injection", "模板注入", "jinja2"],
    "xxe": ["xxe", "xml", "entity", "dtd"],
    "recon": ["recon", "scan", "枚举", "指纹", "信息收集"],
}


def canonicalize_problem_type(raw_type: str) -> str:
    normalized = str(raw_type or "").strip().lower().replace("_", "-")
    if not normalized:
        return "unknown"
    for canonical, aliases in CANONICAL_TYPE_ALIASES.items():
        if normalized == canonical or normalized in aliases:
            return canonical
    return normalized if normalized in CANONICAL_TYPE_ALIASES else "unknown"


def problem_type_aliases(canonical_type: str) -> List[str]:
    canonical = canonicalize_problem_type(canonical_type)
    aliases = list(CANONICAL_TYPE_ALIASES.get(canonical, []))
    ordered = [canonical, *aliases]
    seen = set()
    result: List[str] = []
    for item in ordered:
        key = str(item or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result or ["unknown"]


def canonical_skill_names(canonical_type: str) -> List[str]:
    canonical = canonicalize_problem_type(canonical_type)
    names = problem_type_aliases(canonical)
    if canonical == "lfi":
        names.extend(["file-inclusion"])
    if canonical == "auth":
        names.extend(["auth-bypass"])
    if canonical == "recon":
        names.extend(["web-recon"])
    seen = set()
    result: List[str] = []
    for name in names:
        key = str(name or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def build_taxonomy_profile(
    problem_type: str,
    url: str,
    description: str,
    hint: str,
    initial_response: str = "",
) -> Dict[str, Any]:
    canonical = canonicalize_problem_type(problem_type)
    text = " ".join([url or "", description or "", hint or "", initial_response or ""]).lower()
    tags: List[str] = []
    for candidate, keywords in KEYWORD_HINTS.items():
        if any(keyword.lower() in text for keyword in keywords):
            tags.append(candidate)
    if canonical not in tags and canonical != "unknown":
        tags.insert(0, canonical)
    frameworks = [tag for tag in tags if tag in {"tornado", "flask", "django"}]
    vuln_types = [tag for tag in tags if tag not in {"tornado", "flask", "django", "unknown"}]
    return {
        "canonical_problem_type": canonical,
        "type_aliases": problem_type_aliases(canonical),
        "skill_names": canonical_skill_names(canonical),
        "taxonomy_tags": tags,
        "framework_tags": frameworks,
        "vulnerability_tags": vuln_types,
        "resource_hints": {
            "skills": canonical_skill_names(canonical),
            "long_memory_types": problem_type_aliases(canonical),
            "wooyun_terms": problem_type_aliases(canonical) + tags,
        },
    }


def taxonomy_findings_from_profile(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    profile = dict(profile or {})
    findings: List[Dict[str, Any]] = []
    canonical = str(profile.get("canonical_problem_type") or "").strip()
    if canonical:
        findings.append({"kind": "taxonomy_type", "value": canonical, "metadata": {"source": "taxonomy"}})
    for alias in profile.get("type_aliases") or []:
        findings.append({"kind": "taxonomy_alias", "value": alias, "metadata": {"source": "taxonomy"}})
    for tag in profile.get("taxonomy_tags") or []:
        findings.append({"kind": "taxonomy_tag", "value": tag, "metadata": {"source": "taxonomy"}})
    for tag in profile.get("framework_tags") or []:
        findings.append({"kind": "tech_stack", "value": tag, "metadata": {"source": "taxonomy"}})
    return findings
