"""
CTF Agent 工具集 - v2.0 集成双记忆系统
======================================

设计方案：
- 短期记忆：单题防重复、记步骤、自动提取关键信息
- 长期记忆：经验累积、POC复用、解题技巧（手动管理）
- 全自动解题：Claude自主决策，遇到困难才求助

使用：
    from tools import *
    reset_memory()  # 开始新题目

    # 自动记录和执行
    result = execute_command("...")
"""

import re
import json
import subprocess
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path

# 导入短期记忆
from short_memory import get_short_memory, reset_short_memory, ShortMemory

# 导入长期记忆系统
try:
    from long_memory import auto_identify_and_load, auto_save_experience
    LONG_MEMORY_AVAILABLE = True
except ImportError:
    LONG_MEMORY_AVAILABLE = False
    auto_identify_and_load = auto_save_experience = None

# 导入多智能体系统
try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from agents.coordination import ReconCoordinator, run_recon_sync
    MULTI_AGENT_AVAILABLE = True
except ImportError as e:
    MULTI_AGENT_AVAILABLE = False
    ReconCoordinator = None
    run_recon_sync = None
    print(f"[Warn] Multi-agent system not available: {e}")

try:
    from toolkit.sqlmap import scan as sqlmap_scan, deep_scan as sqlmap_deep_scan
    from toolkit.dirsearch import scan as dirsearch_scan, quick_scan as dirsearch_quick_scan
    TOOLKIT_AVAILABLE = True
except ImportError:
    TOOLKIT_AVAILABLE = False
    sqlmap_scan = sqlmap_deep_scan = dirsearch_scan = dirsearch_quick_scan = None

# 全局记忆实例
_short_memory_instance: Optional[ShortMemory] = None


def get_memory() -> ShortMemory:
    """获取当前短期记忆实例"""
    global _short_memory_instance
    if _short_memory_instance is None:
        _short_memory_instance = get_short_memory()
    return _short_memory_instance


def reset_memory():
    """开始新题目时重置记忆"""
    global _short_memory_instance
    reset_short_memory()
    _short_memory_instance = get_short_memory()


def init_problem(target_url: str, description: str = "", hint: str = ""):
    """
    初始化题目并自动识别类型、加载资源
    """
    # 重置记忆
    reset_memory()
    memory = get_memory()

    # 设置目标信息
    memory.update_target(url=target_url)

    # 尝试自动识别题目类型
    problem_type = "unknown"

    # 基于URL和描述自动识别
    url_lower = target_url.lower()
    desc_lower = description.lower()
    hint_lower = hint.lower()

    # 扩展关键词列表，包含框架名称和更多变体
    type_keywords = {
        "sqli": ["sql", "injection", "inject", "select", "union", "database", "注入", "mysql", "mariadb", "sqlmap"],
        "xss": ["xss", "script", "alert", "跨站", "javascript"],
        "lfi": ["lfi", "local file", "文件包含", "读取", "file inclusion", "include", "path traversal"],
        "rce": ["rce", "远程代码", "command", "exec", "命令执行", "eval", "system", "shell"],
        "ssrf": ["ssrf", "内网", "localhost", "gopher", "fetch"],
        "upload": ["upload", "上传", "文件上传"],
        "auth": ["登录", "login", "auth", "password", "认证", "bypass", "admin"],
        "deserialization": ["serialize", "unserialize", "pickle", "yaml", "反序列化"],
        "tornado": ["tornado", "tornado框架", "template"],
        "flask": ["flask", "jinja", "session"],
        "django": ["django", "django框架"],
        "ssti": ["ssti", "template injection", "模板注入", "jinja2"],
        "xxe": ["xxe", "xml", "entity", "dtd"],
    }

    for ptype, keywords in type_keywords.items():
        if any(k in url_lower or k in desc_lower or k in hint_lower for k in keywords):
            problem_type = ptype
            break

    # 如果还是识别不到，尝试访问网站获取更多信息
    if problem_type == "unknown":
        try:
            import requests
            resp = requests.get(target_url, timeout=10)
            page_content = resp.text.lower()

            # 从页面内容中提取关键词
            for ptype, keywords in type_keywords.items():
                if any(k in page_content for k in keywords):
                    problem_type = ptype
                    print(f"[Auto-detect] 从页面内容识别出类型: {ptype}")
                    break

            # 额外检测：检查 Server header
            server = resp.headers.get("Server", "").lower()
            if "tornado" in server:
                problem_type = "tornado"
                print(f"[Auto-detect] 从Server header识别出类型: tornado")
        except Exception as e:
            print(f"[Auto-detect] 访问目标失败: {e}")

    # 更新题目类型
    memory.update_target(problem_type=problem_type)

    # ========== 自动加载并展示知识资源 ==========
    print(f"\n{'='*60}")
    print(f"[Knowledge] 自动加载解题资源...")
    print(f"{'='*60}")

    # 1. 加载 skills 知识库
    skill_content = ""
    if problem_type != "unknown":
        skill_path = Path(__file__).parent / "skills" / problem_type / "SKILL.md"
        if skill_path.exists():
            skill_content = skill_path.read_text(encoding="utf-8")
            # 打印关键部分（前1500字符）
            print(f"\n>>> Skills知识库 [{problem_type}]:")
            print("-" * 40)
            # 提取关键部分
            lines = skill_content.split('\n')[:50]  # 只显示前50行
            print('\n'.join(lines))
            if len(skill_content) > 2000:
                print(f"\n... [知识库内容过长，已截断，共{len(skill_content)}字符]")

    # 2. 加载长期记忆（经验/POC）
    loaded_resources = {}
    if LONG_MEMORY_AVAILABLE and auto_identify_and_load:
        try:
            loaded_resources = auto_identify_and_load(
                url=target_url,
                description=description,
                hint=hint
            )
            # 打印加载的资源
            if loaded_resources.get("probable_types"):
                print(f"\n>>> 识别类型: {loaded_resources['probable_types']}")

            for ptype, resources in loaded_resources.get("resources", {}).items():
                if resources.get("experiences"):
                    print(f"\n>>> 历史经验 [{ptype}]: {len(resources['experiences'])} 条")
                    for exp in resources["experiences"][:2]:
                        print(f"    - {exp.get('file', 'unknown')}")

                if resources.get("pocs"):
                    print(f"\n>>> CVE POC [{ptype}]: {len(resources['pocs'])} 个")
                    for poc in resources["pocs"][:3]:
                        print(f"    - {poc.get('cve', 'unknown')}: {poc.get('description', '')[:40]}")

                if resources.get("tips"):
                    print(f"\n>>> 建议操作:")
                    print(resources["tips"])

        except Exception as e:
            print(f"[Memory] auto load failed: {e}")

    # 3. 尝试检索WooYun知识
    wooyun_ref = ""
    if problem_type != "unknown":
        try:
            wooyun_ref = _retrieve_wooyun_knowledge(problem_type, description, hint, target_url)
            if wooyun_ref:
                print(f"\n>>> WooYun知识:")
                print(wooyun_ref[:500])
        except Exception as e:
            pass

    print(f"\n{'='*60}")
    print(f"[Problem Init Complete] Type: {problem_type}")
    print(f"{'='*60}\n")

    return {
        "type": problem_type,
        "url": target_url,
        "description": description,
        "hint": hint,
        "loaded_resources": loaded_resources,
        "wooyun_ref": wooyun_ref,
        "skill_content": skill_content  # 新增：返回skill内容
    }


def get_available_resources() -> Dict[str, Any]:
    """
    获取当前题目可用的资源（POC、经验、知识）
    Agent 可在任何时候调用查看可用资源
    """
    memory = get_memory()
    prob_type = memory.target.problem_type or "unknown"
    target_url = memory.target.url or ""

    result = {
        "problem_type": prob_type,
        "target": target_url,
        "pocs": [],
        "experiences": [],
        "wooyun_knowledge": []
    }

    # 加载长期记忆 POC
    if LONG_MEMORY_AVAILABLE:
        try:
            from long_memory import auto_memory
            result["pocs"] = auto_memory.find_pocs_by_type(prob_type)
            result["experiences"] = auto_memory.load_experiences_by_type(prob_type)
        except Exception as e:
            result["error"] = str(e)

    # 加载 WooYun 知识
    try:
        import sys
        from pathlib import Path
        rag_path = Path(__file__).parent / "skills" / "wooyun"
        if str(rag_path) not in sys.path:
            sys.path.insert(0, str(rag_path))

        from wooyun_rag import retrieve_knowledge as wooyun_retrieve
        rag_result = wooyun_retrieve(
            query=f"{prob_type}漏洞利用",
            context={"current_vuln_type": prob_type, "target_url": target_url},
            top_k=3
        )
        result["wooyun_knowledge"] = rag_result.get("retrieved_knowledge", [])
    except Exception as e:
        result["wooyun_error"] = str(e)

    # 打印摘要
    print(f"\n{'='*60}")
    print(f"[Available Resources] Type: {prob_type}")
    print(f"{'='*60}")

    if result["pocs"]:
        print(f"\n>> CVE POC ({len(result['pocs'])}个):")
        for p in result["pocs"][:5]:
            print(f"   - {p.get('cve', 'unknown')}: {p.get('description', '')[:50]}")

    if result["experiences"]:
        print(f"\n>> 历史经验 ({len(result['experiences'])}条):")
        for e in result["experiences"][:3]:
            print(f"   - {e.get('file', 'unknown')}")

    if result["wooyun_knowledge"]:
        print(f"\n>> WooYun知识 ({len(result['wooyun_knowledge'])}条):")
        for k in result["wooyun_knowledge"]:
            print(f"   - [{k.get('type', '')}] {k.get('content', '')[:60]}...")

    print(f"{'='*60}\n")

    return result



def update_problem_type(problem_type: str) -> str:
    memory = get_memory()
    memory.update_target(problem_type=problem_type)
    print(f'[Update] 题目类型已更新为: {problem_type}')
    get_available_resources()
    return problem_type

# ===================== WooYun RAG Integration =====================

def retrieve_rag_knowledge(query: str = "", vuln_type: str = "", target_url: str = "", attempted_methods: List[str] = None) -> Dict[str, Any]:
    """
    解题过程中主动检索 WooYun 知识库
    Agent 可在任何时候调用此函数获取相关知识

    Args:
        query: 当前问题描述，如"如何绕过WAF"
        vuln_type: 漏洞类型，如"sqli", "lfi", "rce"
        target_url: 目标URL
        attempted_methods: 已尝试的方法列表

    Returns:
        检索结果字典，包含:
        - retrieved_knowledge: 相关知识列表
        - suggested_approach: 建议做法
    """
    if attempted_methods is None:
        attempted_methods = []

    try:
        import sys
        from pathlib import Path
        rag_path = Path(__file__).parent / "skills" / "wooyun"
        if str(rag_path) not in sys.path:
            sys.path.insert(0, str(rag_path))

        from wooyun_rag import retrieve_knowledge as wooyun_retrieve

        context = {
            "current_vuln_type": vuln_type,
            "target_url": target_url,
            "tech_stack": [],
            "attempted_methods": attempted_methods,
            "problem_description": query
        }

        result = wooyun_retrieve(query=query, context=context, top_k=5)

        # 格式化输出
        if result.get("retrieved_knowledge"):
            print(f"\n{'='*60}")
            print(f"[RAG] 检索到 {len(result['retrieved_knowledge'])} 条相关知识")
            print(f"{'='*60}")

            for i, item in enumerate(result["retrieved_knowledge"], 1):
                item_type = item.get("type", "unknown")
                content = item.get("content", "")[:200]
                score = item.get("relevance_score", 0)
                print(f"{i}. [{item_type}] (相关性:{score}) {content}...")

            if result.get("suggested_approach"):
                print(f"\n>> 建议: {result['suggested_approach']}")
            print(f"{'='*60}\n")

        return result

    except Exception as e:
        return {"error": str(e), "retrieved_knowledge": [], "suggested_approach": ""}

def _format_wooyun_ref(wooyun_context: dict) -> str:
    """格式化WooYun检索结果"""
    if not wooyun_context or "retrieved_knowledge" not in wooyun_context:
        return ""
    
    lines = ["【WooYun真实案例参考】"]
    for i, item in enumerate(wooyun_context["retrieved_knowledge"], 1):
        item_type = item.get("type", "unknown")
        content = item.get("content", "")[:150]
        
        if item_type == "payload":
            lines.append(f"{i}. Payload样例: {content}...")
        elif item_type == "technique":
            lines.append(f"{i}. 攻击技术: {content}...")
        elif item_type == "case":
            lines.append(f"{i}. 类似案例: {content}...")
        elif item_type == "parameter":
            lines.append(f"{i}. 高频参数: {content}...")
    
    if wooyun_context.get("suggested_approach"):
        lines.append(f"建议做法: {wooyun_context['suggested_approach']}")
    
    return "  ".join(lines)

def _retrieve_wooyun_knowledge(primary_type: str, description: str, hint: str, target_url: str) -> str:
    """WooYun RAG: AI自动检索知识（集成在init_problem中）"""
    wooyun_ref = ""
    try:
        from skills.wooyun.wooyun_rag import retrieve_knowledge
        wooyun_context = retrieve_knowledge(
            query=f"{description} {hint}",
            context={
                "current_vuln_type": primary_type,
                "target_url": target_url,
                "tech_stack": [],
                "attempted_methods": [],
                "problem_description": description
            },
            top_k=3
        )
        wooyun_ref = _format_wooyun_ref(wooyun_context)
        if wooyun_ref:
            print(f"=== 【WooYun知识】AI自动加载 ===")
            print(wooyun_ref[:400])
    except Exception as e:
        print(f"[Agent] WooYun检索出错: {e}")
    return wooyun_ref

# ==================== 原函数的其余部分 ====================


# ==================== 内部工具函数 ====================

def _http_request_with_retry(method: str, url: str, max_retries: int = 3, 
                              backoff_factor: float = 1.0, **kwargs) -> requests.Response:
    """
    带重试机制的HTTP请求
    
    Args:
        method: GET/POST
        url: 目标URL
        max_retries: 最大重试次数
        backoff_factor: 重试间隔增长因子
        **kwargs: 传递给requests的参数
    
    Returns:
        Response对象
    """
    import time
    
    for attempt in range(max_retries):
        try:
            if method.upper() == 'GET':
                response = requests.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = requests.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            # 429: Too Many Requests - 限流，等待后重试
            if response.status_code == 429:
                wait_time = backoff_factor * (2 ** attempt)
                print(f"[Retry] 触发限流，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
                time.sleep(wait_time)
                continue
            
            # 5xx 服务器错误 - 重试
            if 500 <= response.status_code < 600:
                wait_time = backoff_factor * (2 ** attempt)
                print(f"[Retry] 服务器错误 {response.status_code}，等待 {wait_time}秒后重试")
                time.sleep(wait_time)
                continue
            
            return response
            
        except requests.Timeout:
            wait_time = backoff_factor * (2 ** attempt)
            print(f"[Retry] 请求超时，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
            time.sleep(wait_time)
            continue
            
        except requests.ConnectionError:
            wait_time = backoff_factor * (2 ** attempt)
            print(f"[Retry] 连接错误，等待 {wait_time}秒后重试 (尝试 {attempt+1}/{max_retries})")
            time.sleep(wait_time)
            continue
            
        except Exception as e:
            # 其他错误直接抛出
            raise
    
    # 所有重试都失败
    raise Exception(f"请求失败，已重试 {max_retries} 次")


# ==================== HTTP请求工具 ====================

def http_get(url: str, params: Dict = None, headers: Dict = None,
             timeout: int = 30, allow_redirects: bool = True) -> str:
    """
    发送GET请求（自动记录到短期记忆）

    Args:
        url: 目标URL
        params: URL参数
        headers: 请求头
        timeout: 超时时间
        allow_redirects: 是否跟随重定向

    Returns:
        响应内容
    """
    memory = get_memory()

    # 检查是否已尝试相同请求（简化检测：只比较URL+params）
    check_params = {"params": params} if params else None
    if memory.has_tried("http_get", url, check_params):
        return f"[Skip] 已尝试过该请求: {url}"

    try:
        response = _http_request_with_retry(
            'GET', url,
            params=params, headers=headers,
            timeout=timeout, allow_redirects=allow_redirects
        )

        output = f"""Status: {response.status_code}
Headers: {dict(response.headers)}
Content-Length: {len(response.text)}

--- Content ---
{response.text}"""

        # 提取flag
        flags = extract_flags(response.text)
        success = response.status_code == 200
        findings = flags if flags else _extract_findings(response.text)

        # 记录到短期记忆
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url, "params": params, "headers": headers},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except requests.Timeout:
        error_msg = f"请求超时 ({timeout}秒)"
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"请求错误: {str(e)}"
        memory.add_step(
            tool="http_get",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg


def http_post(url: str, data: Dict = None, json: Dict = None,
              headers: Dict = None, timeout: int = 30) -> str:
    """
    发送POST请求（自动记录到短期记忆）

    Args:
        url: 目标URL
        data: 表单数据
        json: JSON数据
        headers: 请求头
        timeout: 超时时间

    Returns:
        响应内容
    """
    memory = get_memory()

    # 检查是否已尝试相同请求（简化检测：只比较URL+data/json）
    check_params = {"data": data, "json": json} if (data or json) else None
    if memory.has_tried("http_post", url, check_params):
        return f"[Skip] 已尝试过该请求: {url}"

    try:
        response = _http_request_with_retry(
            'POST', url,
            data=data, json=json, headers=headers, timeout=timeout
        )

        output = f"""Status: {response.status_code}
Headers: {dict(response.headers)}
Content-Length: {len(response.text)}

--- Content ---
{response.text}"""

        # 提取flag
        flags = extract_flags(response.text)
        success = response.status_code == 200
        findings = flags if flags else _extract_findings(response.text)

        # 记录到短期记忆
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url, "data": data, "json": json},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except requests.Timeout:
        error_msg = f"请求超时 ({timeout}秒)"
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"请求错误: {str(e)}"
        memory.add_step(
            tool="http_post",
            target=url[:100],
            params={"url": url},
            result=error_msg,
            success=False
        )
        return error_msg


# ==================== 核心执行工具（带记忆） ====================

def execute_command(cmd: str, timeout: int = 120,
                    skip_if_failed: bool = True, max_failures: int = 2) -> str:
    """
    执行shell命令（自动防重复 + 失败追踪）

    Args:
        cmd: 要执行的命令
        timeout: 超时时间
        skip_if_failed: 是否跳过已多次失败的命令
        max_failures: 最大失败次数

    Returns:
        执行结果
    """
    memory = get_memory()

    # 检查是否已多次失败
    if skip_if_failed and memory.should_skip("command", cmd, None, max_failures):
        fail_count = memory.fail_count("command", cmd)
        return f"[Skip] 该命令已失败 {fail_count} 次，跳过执行"

    try:
        # 先激活虚拟环境再执行
        full_cmd = f'workon CTFagent && {cmd}'
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout
        )

        output = f"""Exit Code: {result.returncode}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}"""

        success = result.returncode == 0

        # 记录到短期记忆
        findings = _extract_findings(output)
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd, "timeout": timeout},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except subprocess.TimeoutExpired:
        error_msg = f"执行超时 ({timeout}秒)"
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        error_msg = f"执行错误: {str(e)}"
        memory.add_step(
            tool="command",
            target=cmd[:100],
            params={"cmd": cmd},
            result=error_msg,
            success=False
        )
        return error_msg


def execute_python_poc(code: str, timeout: int = 120,
                       skip_if_failed: bool = True, max_failures: int = 2,
                       keep: bool = False) -> str:
    """
    执行Python PoC代码（自动防重复 + 失败追踪 + 自动清理）

    Args:
        code: Python代码
        timeout: 超时时间
        skip_if_failed: 是否跳过已多次失败的代码
        max_failures: 最大失败次数
        keep: 是否保留文件（用于调试，默认自动删除）

    Returns:
        执行结果
    """
    memory = get_memory()
    code_summary = code[:100] + "..." if len(code) > 100 else code

    # 检查是否已尝试过（成功的不重复执行）
    if memory.has_tried("python_poc", code_summary, None):
        return f"[Skip] 该PoC已执行过"

    # 检查是否已多次失败
    if skip_if_failed and memory.should_skip("python_poc", code_summary, None, max_failures):
        fail_count = memory.fail_count("python_poc", code_summary)
        return f"[Skip] 该PoC已失败 {fail_count} 次，跳过执行"

    import os
    import io
    import sys
    from datetime import datetime

    # 使用 workspace 目录
    workspace = Path(__file__).parent / "workspace"
    workspace.mkdir(exist_ok=True)

    # 生成唯一文件名（时间戳+随机数）
    timestamp = datetime.now().strftime("%H%M%S")
    temp_file = workspace / f"poc_{timestamp}_{os.urandom(2).hex()}.py"

    temp_file_str = str(temp_file)

    # 保存原始stdout以便恢复（避免与调用者的stdout修改冲突）
    _original_stdout = sys.stdout

    try:
        # 写入代码到 workspace/
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(code)

        # 使用虚拟环境Python执行
        venv_python = r"C:\Users\Administrator\Envs\CTFagent\Scripts\python.exe"
        result = subprocess.run(
            [venv_python, temp_file_str],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout
        )

        # 执行完成后自动清理文件（除非keep=True）
        if not keep:
            try:
                os.unlink(temp_file_str)
            except:
                pass

        output = f"""Exit Code: {result.returncode}

--- STDOUT ---
{result.stdout}

--- STDERR ---
{result.stderr}"""

        success = result.returncode == 0

        # 记录到短期记忆
        findings = _extract_findings(output)
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=output,
            success=success,
            key_findings=findings
        )

        return output

    except subprocess.TimeoutExpired:
        try:
            os.unlink(temp_file)
        except:
            pass
        error_msg = f"执行超时 ({timeout}秒)"
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=error_msg,
            success=False
        )
        return error_msg

    except Exception as e:
        try:
            os.unlink(temp_file)
        except:
            pass
        error_msg = f"执行错误: {str(e)}"
        memory.add_step(
            tool="python_poc",
            target=code_summary,
            params={},
            result=error_msg,
            success=False
        )
        return error_msg


# ==================== Web辅助工具 ====================

def extract_form_fields(html: str, form_index: int = 0) -> Dict[str, Any]:
    """提取HTML表单字段"""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return {"error": "未找到表单", "action": "", "method": "GET",
                    "fields": {}, "field_order": []}

        form = forms[form_index]
        result = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'fields': {},
            'field_order': [],
            'error': None
        }

        # 提取input字段
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            if not name or 'disabled' in input_tag.attrs:
                continue
            field_type = input_tag.get('type', 'text').lower()
            if field_type in ['submit', 'button', 'reset', 'image']:
                continue
            result['fields'][name] = {
                'value': input_tag.get('value', ''),                'type': field_type,
                'hidden': field_type == 'hidden',
                'required': 'required' in input_tag.attrs
            }
            result['field_order'].append(name)

        return result

    except ImportError:
        return {"error": "BeautifulSoup未安装: pip install beautifulsoup4",
                "action": "", "method": "GET", "fields": {}, "field_order": []}
    except Exception as e:
        return {"error": str(e), "action": "", "method": "GET",
                "fields": {}, "field_order": []}


# ==================== 工具封装（带记忆） ====================

def sqlmap_scan_url(url: str, **kwargs) -> str:
    """SQLMap扫描（防重复）"""
    memory = get_memory()

    # 检查是否已尝试
    if memory.has_tried("sqlmap", url, kwargs):
        return f"[Skip] SQLMap已扫描过 {url}"

    if not TOOLKIT_AVAILABLE or sqlmap_scan is None:
        return "[Error] SQLMap工具未安装"

    result = sqlmap_scan(url, **kwargs)

    # 记录
    success = result.success
    findings = ["发现注入点"] if "injection" in result.stdout.lower() else []
    memory.add_step(
        tool="sqlmap",
        target=url,
        params=kwargs,
        result=result.stdout[:500] if success else result.stderr,
        success=success,
        key_findings=findings
    )

    return f"[SQLMap] {url}\n{result.stdout if success else result.stderr}"


def sqlmap_deep_scan_url(url: str, **kwargs) -> str:
    """SQLMap深度扫描"""
    return sqlmap_scan_url(url, level=5, risk=3, **kwargs)


def dirsearch_scan_url(url: str, **kwargs) -> str:
    """Dirsearch扫描（防重复）"""
    memory = get_memory()

    if memory.has_tried("dirsearch", url, kwargs):
        return f"[Skip] Dirsearch已扫描过 {url}"

    if not TOOLKIT_AVAILABLE or dirsearch_scan is None:
        return "[Error] Dirsearch工具未安装"

    result = dirsearch_scan(url=url, **kwargs)

    success = result.success
    findings = ["发现目录"] if success and "200" in result.stdout else []
    memory.add_step(
        tool="dirsearch",
        target=url,
        params=kwargs,
        result=result.stdout[:500] if success else result.stderr,
        success=success,
        key_findings=findings
    )

    return f"[Dirsearch] {url}\n{result.stdout if success else result.stderr}"


def quick_dir_scan(url: str, extensions: List[str] = None) -> str:
    """快速目录扫描"""
    if extensions is None:
        extensions = ["php", "html", "js", "css", "txt"]
    return dirsearch_scan_url(url=url, extensions=extensions, threads=30)


# ==================== 记忆查询 ====================

def get_memory_summary() -> str:
    """获取当前解题摘要（包含步数统计）"""
    memory = get_memory()
    summary = memory.get_summary()

    # 添加步数统计
    step_count = len(memory.steps) if hasattr(memory, 'steps') else 0
    if step_count > 0:
        summary = f"[进度] 已有 {step_count} 步操作\n\n" + summary

    # 步数过多警告
    if step_count >= 20:
        summary = f"[!] 警告：已进行 {step_count} 步，可能陷入僵局，建议更换策略\n\n" + summary

    return summary


def get_step_count() -> int:
    """获取当前解题步数"""
    memory = get_memory()
    return len(memory.steps) if hasattr(memory, 'steps') else 0


def get_status() -> str:
    """快速获取当前解题状态（一行）"""
    memory = get_memory()
    step_count = len(memory.steps) if hasattr(memory, 'steps') else 0
    prob_type = memory.target.problem_type or "未知"
    url = memory.target.url or "无"
    flags = memory.target.flags or []

    status = f"[状态] 类型:{prob_type} | 步数:{step_count} | URL:{url[:40]}"
    if flags:
        status += f" | Flag:{flags[0]}"
    return status


def analyze_result(result: str) -> Dict[str, str]:
    """
    智能分析工具执行结果，判断成功/失败/需进一步分析
    
    Args:
        result: 工具执行输出
    
    Returns:
        dict: {"status": "success/failure/uncertain", "reason": "原因", "details": ["详情"]}
    """
    result_lower = result.lower()
    details = []
    
    # 检查明显成功标志
    success_keywords = ['successful', 'success!', 'found', 'flag{', 'correct', 'right!']
    for kw in success_keywords:
        if kw in result_lower:
            details.append(f"发现成功关键字: {kw}")
    
    # 检查明显失败标志
    failure_keywords = [
        ('error', '错误'),
        ('failed', '失败'),
        ('not found', '未找到'),
        ('denied', '拒绝访问'),
        ('incorrect', '不正确'),
        ('timeout', '超时'),
        ('forbidden', '禁止访问'),
        ('unauthorized', '未授权'),
    ]
    for kw, desc in failure_keywords:
        if kw in result_lower:
            details.append(f"发现失败关键字: {desc}")
    
    # 检查HTTP状态码
    import re
    status_match = re.search(r'Status:\s*(\d+)', result)
    if status_match:
        status_code = int(status_match.group(1))
        if 200 <= status_code < 300:
            details.append(f"HTTP状态码成功: {status_code}")
        elif 400 <= status_code < 500:
            details.append(f"HTTP客户端错误: {status_code}")
        elif 500 <= status_code < 600:
            details.append(f"HTTP服务器错误: {status_code}")
    
    # 综合判断
    if any(kw in result_lower for kw in ['flag{', 'successful', 'success!']):
        status = 'success'
        reason = '发现成功标志'
    elif any(kw in result_lower for kw in ['error:', 'failed', 'not found', 'timeout', 'denied']):
        status = 'failure'
        reason = '发现失败标志'
    elif status_match and int(status_match.group(1)) >= 400:
        status = 'failure'
        reason = f'HTTP错误 {status_match.group(1)}'
    else:
        status = 'uncertain'
        reason = '结果不明确，需人工判断'
    
    return {'status': status, 'reason': reason, 'details': details}


def get_suggested_next() -> List[str]:
    """获取建议的下一步"""
    return get_memory().get_suggested_next()


def has_tried(tool: str, target: str, params: Dict = None) -> bool:
    """检查是否已尝试过"""
    return get_memory().has_tried(tool, target, params)


def check_flag() -> Optional[str]:
    """Check if flag found, save experience and generate report"""
    memory = get_memory()
    flags = memory.target.flags
    if flags:
        flag = flags[0]
        print(f"[Agent] Flag found: {flag}")

        # Save experience
        prob_type = "unknown"
        target = ""
        steps = []
        
        if LONG_MEMORY_AVAILABLE and auto_save_experience:
            try:
                prob_type = memory.target.problem_type or "unknown"
                target = memory.target.url or ""
                steps = [
                    {"tool": step.tool, "target": step.target, "success": step.success}
                    for step in memory.steps
                ]
                techniques = list(set([step.tool for step in memory.steps if step.success]))

                exp_file = auto_save_experience(
                    problem_type=prob_type,
                    target=target,
                    steps=steps,
                    flag=flag,
                    key_techniques=techniques
                )
                print(f"[Memory] Experience saved: {exp_file}")
            except Exception as e:
                print(f"[Memory] Save failed: {e}")

        # Generate solution report
        try:
            from long_memory import auto_memory
            report = auto_memory.generate_report(problem_type=prob_type, target=target, steps=steps, flag=flag)
            print('')
            print(report)
        except Exception as re:
            print(f"[Report] Error: {re}")

        print("[Memory] Done, clearing short memory")
        reset_memory()
        clean_workspace()
        return flag
    return None

# ==================== 长期记忆 ====================

def load_long_memory(category: str, name: str) -> Optional[str]:
    """
    加载长期记忆

    Args:
        category: 类别 (experiences, pocs, patterns)
        name: 记忆名称

    Returns:
        记忆内容
    """
    path = Path(__file__).parent / "long_memory" / category / f"{name}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")

    # 尝试skills目录
    path = Path(__file__).parent / "skills" / name / "SKILL.md"
    if path.exists():
        return path.read_text(encoding="utf-8")

    return None


def save_long_memory(category: str, name: str, content: str):
    """保存到长期记忆"""
    dir_path = Path(__file__).parent / "long_memory" / category
    dir_path.mkdir(parents=True, exist_ok=True)

    path = dir_path / f"{name}.md"
    path.write_text(content, encoding="utf-8")
    print(f"[Memory] 已保存到长期记忆: {category}/{name}")


def list_long_memory(category: str = "") -> List[str]:
    """列出长期记忆"""
    base_path = Path(__file__).parent / "long_memory"

    if category:
        path = base_path / category
        if path.exists():
            return [f.stem for f in path.glob("*.md")]
        return []

    # 列出所有
    result = []
    for cat in ["experiences", "pocs", "patterns"]:
        cat_path = base_path / cat
        if cat_path.exists():
            for f in cat_path.glob("*.md"):
                result.append(f"{cat}/{f.stem}")
    return result


# ==================== 辅助函数 ====================

def _extract_findings(output: str) -> List[str]:
    """从输出中提取关键发现"""
    findings = []

    patterns = {
        "开放端口": r'(\d+/tcp\s+open)',
        "发现目录": r'(200|301|302)\s+(/[^\s]+)',
        "SQL注入": r'(injection|injection|union|select)',
        "Flag": r'(flag\{[^}]+\}|ctf\{[^}]+\})',
    }

    for desc, pattern in patterns.items():
        if re.search(pattern, output, re.IGNORECASE):
            findings.append(desc)

    return findings


def extract_flags(text: str) -> List[str]:
    """从文本中提取flag"""
    patterns = [
        r'flag\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'HCTF\{[^}]+\}',
        r'ctfshow\{[^}]+\}',  # 添加CTFshow格式
        r'tfshow\{[^}]+\}',    # 添加截断的ctfshow格式
    ]
    flags = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        flags.extend(matches)
    return list(set(flags))


def summarize_output(output: str, max_length: int = 2000) -> str:
    """截断过长输出"""
    if len(output) <= max_length:
        return output
    head_len = max_length // 2
    tail_len = max_length - head_len - 100
    return f"""{output[:head_len]}

... [输出过长，共 {len(output)} 字符] ...

{output[-tail_len:]}"""


# ==================== Fenjing SSTI工具 ====================

_fenjing_available = False
_fenjing_path = Path(__file__).parent / "tools_source" / "Fenjing"

def _init_fenjing():
    """初始化fenjing模块路径"""
    global _fenjing_available
    if str(_fenjing_path) not in sys.path:
        sys.path.insert(0, str(_fenjing_path))
    try:
        from fenjing import exec_cmd_payload, config_payload
        from fenjing.const import EVAL, STRING
        _fenjing_available = True
        return True
    except ImportError:
        return False

def fenjing_generate_payload(command: str = "id", blacklist: list = None) -> dict:
    """
    生成绕过WAF的SSTI payload

    Args:
        command: 要执行的命令，默认为"id"
        blacklist: 自定义黑名单，为None时使用默认

    Returns:
        dict: {"success": bool, "payload": str, "will_print": bool, "error": str}
    """
    if not _init_fenjing():
        return {"success": False, "error": "fenjing module not available", "payload": "", "will_print": False}

    memory = get_memory()
    cache_key = f"{command}_{str(blacklist)}"

    # 检查是否已生成过
    if memory.has_tried("fenjing_gen", cache_key, None):
        return {"success": True, "payload": "[Cached]", "will_print": True, "error": ""}

    try:
        from fenjing import exec_cmd_payload

        # 默认黑名单
        if blacklist is None:
            blacklist = [
                "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
                "[", '"', "'", "_", ".", "+", "~", "{{",
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                "0","1","2","3","4","5","6","7","8","9"
            ]

        def waf(s: str) -> bool:
            return all(word not in s for word in blacklist)

        payload, will_print = exec_cmd_payload(waf, command)

        memory.add_step(
            tool="fenjing_gen",
            target=f"cmd:{command}",
            params={"command": command},
            result=f"payload generated, will_print={will_print}",
            success=True
        )

        return {
            "success": True,
            "payload": payload,
            "will_print": will_print,
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_gen",
            target=f"cmd:{command}",
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "error": str(e), "payload": "", "will_print": False}


def fenjing_crack_form(
    url: str,
    method: str = "GET",
    inputs: str = "name",
    command: str = "id",
    detect_mode: str = "fast",
    timeout: int = 300,
    extra_params: dict = None,
    extra_data: dict = None,
    headers: dict = None
) -> dict:
    """
    使用fenjing攻击指定表单，自动绕过WAF

    Args:
        url: 目标URL
        method: HTTP方法 GET/POST
        inputs: 要攻击的输入字段名，多个用逗号分隔
        command: 要执行的命令
        detect_mode: 检测模式 fast/accurate
        timeout: 超时时间
        extra_params: 额外GET参数
        extra_data: 额外POST参数
        headers: 自定义请求头

    Returns:
        dict: {"success": bool, "output": str, "flag": str or None, "error": str}
    """
    memory = get_memory()
    cache_key = f"{url}:{method}:{inputs}:{command}"

    # 防重复检查
    if memory.has_tried("fenjing_crack", cache_key, None):
        return {"success": True, "output": "[Cached] Already cracked", "flag": None, "error": ""}

    # 检查失败次数
    if memory.should_skip("fenjing_crack", cache_key, None, max_failures=2):
        return {"success": False, "output": "", "flag": None, "error": "Too many failures, skipping"}

    if not _init_fenjing():
        return {"success": False, "output": "", "flag": None, "error": "fenjing not available"}

    try:
        import requests

        # 先尝试自动生成payload并发送
        payload_result = fenjing_generate_payload(command)
        if not payload_result["success"]:
            return {"success": False, "output": "", "flag": None, "error": payload_result["error"]}

        payload = payload_result["payload"]
        will_print = payload_result["will_print"]

        # 发送payload
        input_fields = inputs.split(",")
        responses = []

        for field in input_fields:
            field = field.strip()
            if method.upper() == "GET":
                params = {field: payload}
                if extra_params:
                    params.update(extra_params)
                resp = requests.get(url, params=params, headers=headers or {}, timeout=30)
            else:
                data = {field: payload}
                if extra_data:
                    data.update(extra_data)
                resp = requests.post(url, data=data, headers=headers or {}, timeout=30)

            responses.append(f"[{field}] Status: {resp.status_code}\n{resp.text[:500]}")

        output = "\n---\n".join(responses)

        # 提取flag
        flags = extract_flags(output)
        if flags:
            memory.target.add_flag(flags[0])

        success = "error" not in output.lower() and resp.status_code == 200

        memory.add_step(
            tool="fenjing_crack",
            target=url,
            params={"method": method, "inputs": inputs, "command": command},
            result=output[:500],
            success=success,
            key_findings=["SSTI exploit"] if success else []
        )

        return {
            "success": success,
            "output": output,
            "flag": flags[0] if flags else None,
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_crack",
            target=url,
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "output": "", "flag": None, "error": str(e)}


def fenjing_scan(url: str, detect_mode: str = "fast", timeout: int = 300) -> dict:
    """
    扫描目标网站自动发现SSTI漏洞

    Args:
        url: 目标URL
        detect_mode: 检测模式 fast/accurate
        timeout: 扫描超时

    Returns:
        dict: {"success": bool, "forms": list, "output": str, "error": str}
    """
    memory = get_memory()

    if memory.has_tried("fenjing_scan", url, None):
        return {"success": True, "forms": [], "output": "[Cached] Already scanned", "error": ""}

    if not _init_fenjing():
        return {"success": False, "forms": [], "output": "", "error": "fenjing not available"}

    try:
        import requests
        from bs4 import BeautifulSoup

        # 获取页面并分析表单
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        form_info = []
        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]

            if inputs:
                form_info.append({
                    "index": i,
                    "action": action,
                    "method": method,
                    "inputs": inputs
                })

        # 记录发现
        memory.update_target(endpoints=[f"form_{f['index']}" for f in form_info])

        memory.add_step(
            tool="fenjing_scan",
            target=url,
            params={},
            result=f"Found {len(form_info)} forms",
            success=True,
            key_findings=[f"发现{len(form_info)}个表单"] if form_info else []
        )

        return {
            "success": True,
            "forms": form_info,
            "output": f"发现 {len(form_info)} 个表单，建议逐一测试",
            "error": ""
        }

    except Exception as e:
        memory.add_step(
            tool="fenjing_scan",
            target=url,
            params={},
            result=f"error: {str(e)}",
            success=False
        )
        return {"success": False, "forms": [], "output": "", "error": str(e)}


__all__ = [
    # 记忆管理
    "reset_memory",
 "get_memory",
    "init_problem",
    "get_memory_summary",
    "get_suggested_next",
    "has_tried",
    "check_flag",
    "load_long_memory",
    "save_long_memory",
    "list_long_memory",
    "clean_workspace",  # 新增清理函数

    # 核心工具
    "execute_command",
    "execute_python_poc",

    # Web辅助
    "extract_form_fields",
    "extract_flags",

    # 封装工具
    "sqlmap_scan_url",
    "sqlmap_deep_scan_url",
    "dirsearch_scan_url",
    "quick_dir_scan",

    # SSTI工具
    "fenjing_generate_payload",
    "fenjing_crack_form",
    "fenjing_scan",

    # RAG 检索
    "retrieve_rag_knowledge",
    "update_problem_type",
    "get_available_resources",

    # 辅助
    "summarize_output",
]



# ==================== 检查点功能 ====================

import hashlib

_CHECKPOINT_DIR = Path(__file__).parent / "checkpoints"

def save_checkpoint(name: str = "default") -> str:
    """
    保存当前解题进度到检查点文件
    
    Args:
        name: 检查点名称，默认"default"
    
    Returns:
        检查点文件路径
    """
    global _short_memory_instance
    if _short_memory_instance is None:
        return "[Error] 无解题进度可保存"
    
    _CHECKPOINT_DIR.mkdir(exist_ok=True)
    
    # 生成唯一文件名
    md5 = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]
    ckpt_file = _CHECKPOINT_DIR / f"ckpt_{md5}.json"
    
    # 保存记忆数据
    data = {
        "name": name,
        "memory": _short_memory_instance.to_dict() if hasattr(_short_memory_instance, 'to_dict') else {},
        "timestamp": str(__import__("datetime").datetime.now()),
    }
    
    import json
    with open(ckpt_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    return f"[Checkpoint] 已保存: {ckpt_file}"

def load_checkpoint(name: str = "default") -> str:
    """
    从检查点文件恢复解题进度
    
    Args:
        name: 检查点名称，默认"default"
    
    Returns:
        恢复结果信息
    """
    global _short_memory_instance
    
    md5 = hashlib.md5(name.encode("utf-8")).hexdigest()[:8]
    ckpt_file = _CHECKPOINT_DIR / f"ckpt_{md5}.json"
    
    if not ckpt_file.exists():
        return f"[Error] 检查点不存在: {name}"
    
    import json
    try:
        with open(ckpt_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 恢复记忆
        if _short_memory_instance and "memory" in data:
            mem_data = data["memory"]
            # 恢复到短期记忆
            if "steps" in mem_data:
                for step in mem_data["steps"]:
                    _short_memory_instance.add_step(
                        tool=step.get("tool", "unknown"),
                        target=step.get("target", ""),
                        params=step.get("params"),
                        result=step.get("result", ""),
                        success=step.get("success", False),
                        key_findings=step.get("key_findings")
                    )
        
        return f"[Checkpoint] 已恢复: {name} (时间: {data.get('timestamp', 'unknown')})"
    except Exception as e:
        return f"[Error] 恢复失败: {str(e)}"

def list_checkpoints() -> List[str]:
    """
    列出所有检查点
    
    Returns:
        检查点名称列表
    """
    _CHECKPOINT_DIR.mkdir(exist_ok=True)
    import os
    files = [f.name for f in _CHECKPOINT_DIR.glob("ckpt_*.json")]
    return files


def clean_workspace():
    """
    清理工作区中的临时脚本文件
    在解题成功后调用，保持环境整洁
    """
    import shutil
    workspace = Path(__file__).parent / "workspace"
    if not workspace.exists():
        return

    deleted = 0
    for f in workspace.glob("poc_*.py"):
        try:
            f.unlink()
            deleted += 1
        except:
            pass

    # 清理 pycache
    pycache = workspace / "__pycache__"
    if pycache.exists():
        try:
            shutil.rmtree(pycache)
        except:
            pass

    if deleted > 0:
        print(f"[Workspace] 清理 {deleted} 个临时脚本")

# ============================================================
# AWD (Attack With Defense) 板块
# ============================================================

def init_awd(target_url: str = None, target_code: str = None, description: str = "", hint: str = "") -> dict:
    """
    初始化 AWD 题目
    
    Args:
        target_url: 攻击目标的 URL
        target_code: 待分析的代码（防御阶段用）
        description: 题目描述
        hint: 提示
    
    Returns:
        初始化信息
    """
    reset_memory()
    memory = get_memory()
    
    # 标记为 AWD 模式
    memory.update_target(problem_type="awdp")
    memory.target.awd_mode = True
    memory.target.awd_phase = "attack"
    
    # 攻击目标 URL
    if target_url:
        memory.update_target(url=target_url)
    
    # 代码（防御阶段分析用）
    if target_code:
        memory.target.target_code = target_code
    
    return {
        "phase": "attack",
        "target_url": target_url,
        "message": "AWD 题目已初始化，当前为攻击阶段，可用 switch_awd_phase('defense') 切换到防御阶段"
    }


def switch_awd_phase(new_phase: str) -> dict:
    """
    切换 AWD 阶段
    
    Args:
        new_phase: "attack" 或 "defense"
    """
    memory = get_memory()
    
    if not memory.target.awd_mode:
        return {"error": "当前不是 AWD 模式，请先调用 init_awd()"}
    
    if new_phase not in ["attack", "defense"]:
        return {"error": f"无效阶段: {new_phase}，请使用 'attack' 或 'defense'"}
    
    old_phase = memory.target.awd_phase
    memory.target.awd_phase = new_phase
    
    return {
        "old_phase": old_phase,
        "new_phase": new_phase,
        "message": f"已从 {old_phase} 切换到 {new_phase}"
    }


def get_awd_status() -> dict:
    """
    获取 AWD 状态
    """
    memory = get_memory()
    
    if not getattr(memory.target, 'awd_mode', False):
        return {"mode": "normal", "phase": None}
    
    return {
        "mode": "awd",
        "phase": memory.target.awd_phase,
        "target_url": memory.target.url,
        "flags": memory.target.flags,
        "patch_count": len(memory.target.patches),
    }


def detect_vulnerabilities(code: str) -> List[Dict]:
    """
    检测代码中的常见漏洞
    
    Args:
        code: 待分析的代码
    
    Returns:
        漏洞列表
    """
    vulns = []
    
    # SQL 注入检测
    sqli_patterns = [
        (r'execute\s*\(\s*["\'].*?%s', "SQL注入 - 字符串拼接"),
        (r'query\s*\(\s*["\'].*?\+', "SQL注入 - 变量拼接"),
        (r'mysql_query\s*\(.*?\+', "SQL注入 - MySQL直接拼接"),
    ]
    for pattern, desc in sqli_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "sqli",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # XSS 检测
    xss_patterns = [
        (r'echo\s*\$_(?:GET|POST|REQUEST)', "XSS - 直接输出用户输入"),
        (r'\$.*\.innerHTML\s*=', "XSS - innerHTML 赋值"),
        (r'print\s*\$_(?:GET|POST|REQUEST)', "XSS - print 输出用户输入"),
    ]
    for pattern, desc in xss_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "xss",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # 命令执行检测
    rce_patterns = [
        (r'(?:exec|system|shell_exec|popen)\s*\(\s*\$', "RCE - 危险函数"),
        (r'eval\s*\(\s*\$', "RCE - eval 使用用户输入"),
        (r'assert\s*\(\s*\$', "RCE - assert 使用用户输入"),
        (r'call_user_func\s*\(\s*\$', "RCE - 动态函数调用"),
    ]
    for pattern, desc in rce_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "rce",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    # 文件操作漏洞
    file_patterns = [
        (r'include\s*\(\s*\$', "LFI - 文件包含"),
        (r'require\s*\(\s*\$', "LFI - 文件包含"),
        (r'file_get_contents\s*\(\s*\$', "LFI - 文件读取"),
    ]
    for pattern, desc in file_patterns:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:m.start()].count('\n') + 1
            vulns.append({
                "type": "lfi",
                "description": desc,
                "location": f"line {line_num}",
                "match": m.group()[:50]
            })
    
    return vulns


def generate_fix_suggestion(vuln_type: str) -> str:
    """生成修复建议"""
    suggestions = {
        "sqli": "使用预处理语句(Prepared Statements)或 ORM 框架",
        "xss": "使用 htmlspecialchars() 转义输出，或设置 CSP 头",
        "rce": "避免使用危险函数，使用白名单限制输入",
        "lfi": "使用 basename() 过滤路径，禁止 ../ 跳转",
        "ssrf": "限制可访问的 URL 白名单",
    }
    return suggestions.get(vuln_type, "参考安全编码规范")


def search_awd_patch(vuln_type: str, language: str = None) -> Optional[Dict]:
    """
    检索 AWD 修补建议（优先 awd_patches）
    """
    from pathlib import Path
    
    # 1. 优先从 awd_patches 检索
    awd_base = Path(__file__).parent / "long_memory" / "awd_patches"
    
    if awd_base.exists():
        type_dir = awd_base / vuln_type
        if type_dir.exists():
            for exp_file in sorted(type_dir.glob("*.md")):
                content = exp_file.read_text(encoding="utf-8")
                return {
                    "source": "awd_patches",
                    "file": exp_file.name,
                    "content": content[:1000]
                }
    
    return None


def analyze_code(code: str) -> dict:
    """
    分析代码找出漏洞点和修补建议
    """
    memory = get_memory()
    memory.target.target_code = code
    
    # 1. 检测漏洞
    vulns = detect_vulnerabilities(code)
    
    # 2. 为每个漏洞检索修复建议
    for vuln in vulns:
        patch_info = search_awd_patch(vuln["type"])
        if patch_info:
            vuln["fix_source"] = patch_info.get("source", "unknown")
            vuln["fix_reference"] = patch_info.get("content", "")[:200]
        
        vuln["fix_suggestion"] = generate_fix_suggestion(vuln["type"])
        
        memory.add_patch(
            location=vuln.get("location", "unknown"),
            vuln_type=vuln.get("type", "unknown"),
            fix_suggestion=vuln["fix_suggestion"],
            code_snippet=vuln.get("match", "")
        )
    
    return {
        "vulnerabilities": vulns,
        "total_found": len(vulns),
        "patches": memory.target.patches
    }


def get_patch_summary() -> str:
    """获取修补点摘要"""
    memory = get_memory()
    return memory.get_patch_summary()
