"""
LLM 推理机 - 直接模式的核心组件
从 H-Pentest `core/llm.py` 和 `planning/dynamic_planner.py` 迁移并简化
关键特性：
1. 直接模式推理循环，LLM 看到原始数据
2. 工具调用后自动提取 findings
3. 循环检测（防止重复同一动作）
4. RAG 触发逻辑
5. 上下文压缩（Phase 1）
6. 失败模式记录（Phase 1）
7. Strategic Supervisor（Phase 3.1）：初始攻击计划生成
8. Hybrid POC Scanner（Phase 1.3）：快速 POC 扫描集成
"""
import json
import re
import time
from typing import Any, Dict, List, Optional

from .file_state import FileState
from .llm_client import LLMClient
from .prompt_builder import PromptBuilder
from .tool_executor import ToolExecutor
from .rag_knowledge import search_knowledge
from .skill_loader import load_skill
from .context_manager import ContextManager
from .poc_scanner import POCLoader, POCScanner


class DirectReasoner:
    """
    直接模式推理机

    工作流程：
    1. 读取当前状态（target + tool_state + findings）
    2. 构建 prompt
    3. LLM 推理决定下一步
    4. 执行工具
    5. 提取 findings
    6. 检查是否需要 RAG
    7. 更新状态文件
    8. 循环
    """

    def __init__(
        self,
        workspace_dir: str,
        llm_client: LLMClient,
        tool_executor: ToolExecutor,
    ):
        self.state = FileState(workspace_dir)
        self.llm = llm_client
        self.tools = tool_executor
        self.prompt_builder = PromptBuilder()

        # 上下文压缩管理器
        self.context_manager = ContextManager(max_tokens=8000)

        # 循环检测（最近 5 次）
        self.recent_actions: List[str] = []
        self.max_recent_actions = 10
        self.loop_detection_threshold = 5

        # RAG 触发阈值
        self.no_new_findings_count = 0
        self.rag_trigger_threshold = 3

        # 失败模式记录（Phase 1 新增）
        self.failed_attempts: List[Dict[str, str]] = []
        self.max_failed_attempts = 20

        # Strategic Supervisor（Phase 3.1）：攻击计划
        self.attack_plan: Optional[Dict[str, Any]] = None
        self.poc_scan_done = False  # POC 扫描已完成标记

        # Phase 3.1: 立即生成攻击计划（如果 target 已初始化）
        self._generate_strategic_plan()

    def _generate_strategic_plan(self) -> None:
        """
        Phase 3.1: Strategic Supervisor - 生成初始攻击计划

        基于 skill + RAG 生成非强制的攻击路径建议，
        帮助 LLM 在第一步就能有方向，而不是盲目 recon。

        实现逻辑：
        1. 加载 skill 内容（如果存在）
        2. 从 skill 内容中提取关键攻击向量和 POC
        3. 结合 RAG 检索结果补充
        4. 生成建议步骤
        """
        target = self.state.get_target()
        if not target:
            return

        problem_type = target.get("problem_type", "")
        tags = target.get("taxonomy_tags", [])
        url = target.get("url", "")

        # 构建攻击计划
        plan = {
            "problem_type": problem_type,
            "suggested_steps": [],
            "key_observations": [],
            "poc_hints": [],
            "skill_based": False,  # 标记是否基于真实 skill 内容
        }

        # 1. 加载 skill 内容并提取攻击向量
        skill_content = None
        if problem_type:
            skill_content = load_skill(problem_type)

        if skill_content:
            # 从 skill 内容提取攻击向量
            steps, pocs = self._extract_from_skill(skill_content, problem_type)
            if steps:
                plan["suggested_steps"] = steps
                plan["skill_based"] = True
            if pocs:
                plan["poc_hints"] = pocs
            print(f"\n[Strategic Supervisor] 基于 skill 内容生成攻击计划（题型: {problem_type}）")
        else:
            # Fallback: 基于题型硬编码建议（无 skill 内容时）
            plan["suggested_steps"] = self._get_fallback_steps(problem_type, tags)
            plan["poc_hints"] = self._get_fallback_pocs(problem_type)
            print(f"\n[Strategic Supervisor] 基于题型生成攻击计划（题型: {problem_type}）")

        # 2. RAG 检索补充
        if problem_type:
            rag_results = search_knowledge(problem_type, category=problem_type, top_k=2)
            if rag_results:
                plan["rag_insights"] = []
                for r in rag_results[:2]:
                    plan["rag_insights"].append({
                        "title": r.get("title", ""),
                        "method": r.get("method", ""),
                    })

        # 3. 注入到上下文中
        self.attack_plan = plan
        if plan["suggested_steps"]:
            print(f"  建议步骤：")
            for i, s in enumerate(plan["suggested_steps"][:3], 1):
                print(f"    {i}. {s}")

    def _extract_from_skill(self, skill_content: str, problem_type: str) -> tuple:
        """
        从 skill 内容中提取攻击步骤和 POC 提示

        Returns:
            (suggested_steps, poc_hints)
        """
        steps = []
        pocs = []

        # 根据题型提取不同的模式
        if problem_type in ["rce", "command_injection", "code_execution"]:
            # RCE: 提取命令注入相关的 payload 和技术
            lines = skill_content.split("\n")
            for i, line in enumerate(lines):
                line = line.strip()
                # 提取常用 payload
                if any(x in line for x in [";id", "|id", "`id`", "$(id)", ";cat", "|cat"]):
                    # 清理 markdown 代码块格式
                    if line.startswith("`") and line.endswith("`"):
                        line = line[1:-1]
                    if line.startswith("$") or line.startswith("|") or line.startswith(";"):
                        pocs.append(line)
                # 提取攻击步骤描述
                if line.startswith("### ") or line.startswith("## "):
                    step_text = line.replace("### ", "").replace("## ", "")
                    if any(x in step_text for x in ["命令", "注入", "测试", "检测", "绕过"]):
                        steps.append(step_text)

        elif problem_type in ["sqli", "sql_injection"]:
            # SQL注入: 提取 SQL 相关的 payload
            lines = skill_content.split("\n")
            for line in lines:
                line = line.strip()
                if any(x in line for x in ["' OR", "UNION", "admin'--", "'1'='1"]):
                    if line.startswith("`") and line.endswith("`"):
                        line = line[1:-1]
                    pocs.append(line)

        elif problem_type in ["lfi", "file_inclusion"]:
            # LFI: 提取文件包含相关的 payload
            lines = skill_content.split("\n")
            for line in lines:
                line = line.strip()
                if any(x in line for x in ["/etc/passwd", "../", "php://", "data://"]):
                    if line.startswith("`") and line.endswith("`"):
                        line = line[1:-1]
                    pocs.append(line)

        # 去重并限制数量
        pocs = list(set(pocs))[:8]
        steps = list(set(steps))[:4]

        # 如果提取的步骤太少，使用 fallback
        if not steps:
            steps = self._get_fallback_steps(problem_type, [])

        return steps, pocs

    def _get_fallback_steps(self, problem_type: str, tags: list) -> list:
        """无 skill 内容时的 fallback 步骤"""
        if problem_type == "rce" or "rce" in tags:
            return [
                "curl 访问目标，观察页面结构",
                "尝试常见 RCE POC：;cat /flag, |id, $(whoami)",
                "如有源码，分析黑名单函数，找绕过",
                "使用 python_poc 执行复杂 shell 命令",
            ]
        elif problem_type == "sqli" or "sqli" in tags:
            return [
                "curl 访问目标，观察参数",
                "尝试常见 SQLi POC：' OR '1'='1, admin'--",
                "使用 sqlmap 自动化检测",
                "如有注入，尝试 UNION SELECT 读取数据",
            ]
        elif problem_type == "auth" or "auth" in tags:
            return [
                "curl 访问登录页面，观察表单参数",
                "尝试常见弱口令：admin/admin, test/test",
                "检查是否存在验证码绕过后",
                "如有 JS，分析认证逻辑找漏洞",
            ]
        elif problem_type == "lfi" or "lfi" in tags:
            return [
                "观察 URL 参数，找文件包含点",
                "尝试常见 LFI POC：/etc/passwd, ../etc/passwd",
                "尝试 PHP 协议：php://filter/, data://",
                "如有日志文件，尝试 RCE",
            ]
        elif problem_type == "xss" or "xss" in tags:
            return [
                "观察输入点，寻找反射/存储 XSS",
                "尝试常见 XSS POC：<script>alert(1)</script>",
                "尝试绕过过滤：<img src=x onerror=alert(1)>",
            ]
        elif problem_type == "upload" or "upload" in tags:
            return [
                "找到文件上传点",
                "尝试上传 webshell：<?php eval($_POST[x])?>",
                "尝试绕过：双写、00截断、Content-Type 伪造",
                "如上传成功，尝试访问 shell",
            ]
        return [
            "curl 访问目标，观察页面结构",
            "分析页面功能和参数",
            "尝试对应题型的常见攻击手法",
        ]

    def _get_fallback_pocs(self, problem_type: str) -> list:
        """无 skill 内容时的 fallback POC"""
        if problem_type in ["rce", "command_injection", "code_execution"]:
            return [";cat /flag", "|id", "$(cat /flag)", "cat${IFS}/flag"]
        elif problem_type in ["sqli", "sql_injection"]:
            return ["' OR '1'='1", "admin'--", "' UNION SELECT NULL--"]
        elif problem_type in ["lfi", "file_inclusion"]:
            return ["/etc/passwd", "../etc/passwd", "php://filter/convert.base64-encode/resource=/etc/passwd"]
        elif problem_type in ["xss"]:
            return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        elif problem_type in ["upload"]:
            return ["<?php eval($_POST[x])?>", "GIF89a<php eval($_POST[x])?>"]
        return []

    def _try_poc_scan(self) -> None:
        """
        Phase 1.3: Hybrid POC Scanner - 快速 POC 扫描

        当连续无新发现 2+ 次时，触发 POC 快速扫描。
        先用已知 POC 并行测试，如有命中直接写入 findings。
        """
        target = self.state.get_target()
        if not target or self.poc_scan_done:
            return

        problem_type = target.get("problem_type", "")
        url = target.get("url", "")
        if not problem_type or not url:
            return

        # 只对支持的题型执行 POC 扫描
        supported = {"rce", "sqli", "lfi", "command_injection", "sql_injection",
                     "file_inclusion", "file_upload"}
        if problem_type.lower() not in supported:
            return

        # 加载 POC
        loader = POCLoader()
        pocs = loader.load_pocs(problem_type)
        if not pocs:
            return

        print(f"\n[POC Scanner] 开始扫描 {len(pocs)} 个 POC (题型: {problem_type})...")

        # 定义执行函数（使用 curl）
        def executor(poc: str) -> str:
            # RCE: 尝试命令注入
            if problem_type in ("rce", "command_injection"):
                # 简单检测：把 POC 作为命令参数
                test_url = url if "?" not in url else url.split("?")[0]
                return self.tools.execute("curl", {"url": test_url, "method": "GET"})
            # SQLi: 尝试注入
            elif problem_type in ("sqli", "sql_injection"):
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}id=1{poc}"
                return self.tools.execute("curl", {"url": test_url, "method": "GET"})
            # LFI: 尝试文件包含
            elif problem_type in ("lfi", "file_inclusion"):
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}file={poc}"
                return self.tools.execute("curl", {"url": test_url, "method": "GET"})
            return ""

        # 并行扫描（最多 10 个 POC）
        scanner = POCScanner(max_workers=5)
        scan_pocs = pocs[:10]
        results = scanner.scan(scan_pocs, url, executor, timeout=10.0)

        # 分析结果
        successful = [r for r in results if r.success]
        if successful:
            print(f"[POC Scanner] 命中 {len(successful)} 个 POC!")
            for r in successful[:3]:
                print(f"  POC: {r.poc[:50]}")
                self.state.add_finding(
                    kind="poc_hit",
                    value=r.poc,
                    step=0,
                    confirmed=True,
                )
                # 如果响应包含 flag，提取
                flag_match = re.search(r"FLAG\{[^}]+\}", r.response)
                if flag_match:
                    self.state.add_finding(
                        kind="flag",
                        value=flag_match.group(0),
                        step=0,
                        confirmed=True,
                    )
        else:
            print(f"[POC Scanner] 未命中，继续正常推理流程")

        self.poc_scan_done = True

    def run(self, max_steps: int = 30) -> Dict[str, Any]:
        """
        运行推理循环

        Args:
            max_steps: 最大步数

        Returns:
            最终结果
        """
        target = self.state.get_target()
        if not target:
            return {"error": "No target.json found. Run init_target() first."}

        print(f"\n{'='*60}")
        print(f"直接模式启动 - {target.get('url')}")
        print(f"{'='*60}\n")

        # Phase 3.1: Strategic Supervisor - 生成初始攻击计划
        self._generate_strategic_plan()

        step = 0
        while step < max_steps:
            step += 1
            print(f"\n{'='*60}")
            print(f"Step {step}")
            print(f"{'='*60}")

            # 1. 检查 flag
            if self._check_flag():
                print("\n🎯 Flag 已找到！")
                self.state.update_target_status("solved")
                return {"status": "solved", "step": step}

            # 2. 获取当前上下文
            context = self._build_context()

            # 3. 检查是否触发 POC 扫描（早于 RAG）
            if self.no_new_findings_count >= 2 and not self.poc_scan_done:
                self._try_poc_scan()

            # 4. 检查是否触发 RAG
            if self._should_trigger_rag():
                print("\n[RAG] 连续无新发现，触发 RAG 检索...")
                self._trigger_rag()

            # 4. LLM 推理
            decision = self._llm_reason(context)
            print(f"\n[LLM Decision] {decision.get('type', '?')}: {decision}")

            # 5. 执行决策
            if decision.get("type") == "tool_call":
                result = self._execute_tool_call(decision)
                # 6. 提取 findings
                new_findings = self._extract_findings(result, step)
                # 7. 更新状态
                self._update_state(decision, result, new_findings, step)
            elif decision.get("type") == "finished":
                self.state.update_target_status("finished")
                return {"status": "finished", "step": step, "result": decision}
            elif decision.get("type") == "think":
                # LLM 继续推理，不执行工具
                self.state.append_reasoning("assistant", decision.get("content", ""))
                print(f"\n[Thinking] {decision.get('content', '')}")
            elif decision.get("type") == "error":
                # LLM 调用出错
                error_msg = decision.get("content", "Unknown error")
                print(f"\n[Error] LLM 调用失败: {error_msg}")
                self.state.append_reasoning("assistant", f"[Error] {error_msg}")
            else:
                print(f"[Warning] Unknown decision type: {decision}")

        print(f"\n[Max Steps] 达到最大步数 {max_steps}，停止")
        self.state.update_target_status("max_steps_exceeded")
        return {"status": "max_steps_exceeded", "step": step}

    def _build_context(self) -> Dict[str, Any]:
        """构建推理上下文"""
        target = self.state.get_target()
        findings = self.state.get_findings()
        tool_results = self.state.get_last_results(n=5)
        rag = self.state.get_rag_knowledge()
        skill = self.state.get_skill_content()
        history = self.state.get_reasoning_history()

        # 如果 skill_content 为空，尝试加载
        if not skill and target:
            problem_type = target.get("problem_type", "")
            if problem_type:
                skill = load_skill(problem_type)
                if skill:
                    self.state.write_skill_content(skill, problem_type)

        return {
            "target": target,
            "findings": findings,
            "tool_results": tool_results,
            "rag": rag,
            "skill": skill,
            "attack_plan": self.attack_plan,  # Phase 3.1: Strategic Supervisor
            "reasoning_history": history[-10:],  # 最近10条
            "tools": self.tools.get_schemas(),
        }

    # 工具名映射（处理模型使用不同工具名的情况）
    TOOL_NAME_MAP = {
        "cli-mcp-server_run_command": "curl",  # 映射到 curl
        "run_command": "curl",
        "execute_command": "curl",
    }

    def _llm_reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 推理"""
        prompt = self.prompt_builder.build(context)

        # 构建消息
        history = context.get("reasoning_history", [])
        messages = []

        # 系统 prompt
        tool_schemas = self.tools.get_schemas()
        tool_names = [s.get("name") for s in tool_schemas]
        system_prompt = (
            f"你是一个 CTF 靶机解题专家。你可以直接访问题目 URL、执行工具、读取文件来解题。\n"
            f"可用工具: {', '.join(tool_names)}\n"
            f"当你发现解题思路时，立即执行工具验证。不要空想，要动手验证。\n"
            f"发现 flag 后输出 FLAG{{...}} 格式。"
        )

        # 构建基础消息
        base_messages = [{"role": "system", "content": system_prompt}]

        # 历史消息
        history = context.get("reasoning_history", [])
        for msg in history[-10:]:
            base_messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", "")
            })

        # 当前 prompt
        base_messages.append({"role": "user", "content": prompt})

        # 上下文压缩（如果超限）
        if self.context_manager.should_compress(base_messages):
            print("[Context] 历史消息过长，进行压缩...")
            base_messages = self.context_manager.compress(base_messages)

        # LLM 调用（使用流式以获得 tool_calls）
        try:
            response = self.llm.chat(
                messages=base_messages,
                tools=self.tools.get_schemas(),
                stream=True,
            )
        except Exception as e:
            return {"type": "error", "content": str(e)}

        content = response.get("content", "")
        tool_calls = response.get("tool_calls")

        # 记录到历史
        if content:
            self.state.append_reasoning("assistant", content)

        # 解析决策
        if tool_calls:
            # 处理 tool_calls
            tc = tool_calls[0]
            func_name = tc.get("function", {}).get("name", "")
            arguments_str = tc.get("function", {}).get("arguments", "{}")

            # 映射工具名
            func_name = self.TOOL_NAME_MAP.get(func_name, func_name)

            # 检查工具是否在注册表中
            if func_name not in self.tools.tools:
                # 尝试从文本中提取 curl 命令
                if "curl" in content.lower():
                    return self._parse_text_based_curl(content)
                return {
                    "type": "think",
                    "content": f"LLM 选择了未知工具 '{func_name}'。{content[:200]}"
                }

            try:
                arguments = json.loads(arguments_str)
            except:
                arguments = {"raw": arguments_str}

            # 循环检测
            action_key = f"{func_name}:{json.dumps(arguments, sort_keys=True)}"
            if action_key in self.recent_actions[-self.loop_detection_threshold:]:
                print(f"[Loop Detection] 检测到重复动作: {action_key}")
                return {
                    "type": "think",
                    "content": f"这个动作刚执行过，我需要换个方向。LLM 说: {content[:200]}"
                }

            self.recent_actions.append(action_key)
            if len(self.recent_actions) > self.max_recent_actions:
                self.recent_actions = self.recent_actions[-self.max_recent_actions:]

            return {
                "type": "tool_call",
                "tool": func_name,
                "arguments": arguments,
            }

        # 解析文本响应
        content = content.strip()

        # 检查 flag
        flag_match = re.search(r"FLAG\{[^}]+\}", content)
        if flag_match:
            return {"type": "finished", "flag": flag_match.group(0), "content": content}

        # 检查完成标记
        if "FINISHED:" in content:
            return {"type": "finished", "content": content}

        # 尝试从文本中提取 TOOL: xxx | args: {...} 格式
        text_tool = self._parse_text_tool_call(content)
        if text_tool:
            return text_tool

        # 默认：LLM 在思考
        return {"type": "think", "content": content}

    def _parse_text_tool_call(self, text: str) -> Optional[Dict[str, Any]]:
        """从文本中解析工具调用格式: TOOL: tool | args: {...}"""
        # 匹配各种格式的工具调用
        # 支持的格式：
        # - TOOL: execute_python | args: {...} (prompt 指定的格式)
        # - `execute_python | args: {...}` (backtick 包裹)
        # - **TOOL**: execute_python | args: {...} (bold 标记)
        patterns = [
            # TOOL: execute_python | args: {...}
            r"TOOL:\s*(\w+)\s*\|\s*args:\s*(\{.{0,3000}\})",
            # `execute_python | args: {...}` 工具名和args都在反引号内
            r"`(\w+)\s*\|\s*args:\s*(\{.{0,3000}\})`",
            # execute_python | args: {"code": "..."} (无格式标记)
            r"(\w+)\s*\|\s*args:\s*(\{.{0,3000}\})",
            # **TOOL**: execute_python | args: {...}
            r"\*+TOOL\*+:\s*(\w+)\s*\|\s*args:\s*(\{.{0,3000}\})",
            # ```execute_python | args: {...}```
            r"```\s*(\w+)\s*\|\s*args:\s*(\{.{0,3000}\})\s*```",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                tool_name = match.group(1).lower()

                # 映射工具名
                tool_name = self.TOOL_NAME_MAP.get(tool_name, tool_name)

                if tool_name not in self.tools.tools:
                    continue

                # 尝试提取 JSON 参数
                args_str = match.group(2)
                json_start = args_str.find('{')
                json_end = args_str.rfind('}')

                if json_start != -1 and json_end != -1 and json_end > json_start:
                    # 找到完整的 JSON
                    args_json = args_str[json_start:json_end+1]
                    try:
                        arguments = json.loads(args_json)
                        return {
                            "type": "tool_call",
                            "tool": tool_name,
                            "arguments": arguments,
                        }
                    except json.JSONDecodeError:
                        # JSON 不完整，尝试提取单个参数
                        pass

                # 尝试从不完整的 JSON 中提取 code 参数
                # 使用非贪婪匹配，处理转义引号
                code_pattern = r'"code":\s*"(.*?)"'
                code_match = re.search(code_pattern, args_str)
                if code_match:
                    code = code_match.group(1)
                    # 处理转义字符
                    code = code.replace('\\"', '"').replace('\\n', '\n').replace('\\r', '\r').replace('\\\\', '\\')
                    return {
                        "type": "tool_call",
                        "tool": tool_name,
                        "arguments": {"code": code},
                    }

                # 如果是 curl，尝试提取 url 参数
                if tool_name == "curl":
                    url_match = re.search(r'"url"\s*:\s*"([^"]*)"', args_str)
                    if url_match:
                        return {
                            "type": "tool_call",
                            "tool": tool_name,
                            "arguments": {"url": url_match.group(1)},
                        }

        return None

    def _parse_text_based_curl(self, text: str) -> Dict[str, Any]:
        """从文本中提取 curl 命令并执行"""
        # 提取 curl URL
        url_match = re.search(r"curl\s+(https?://[^\s\\]+)", text)
        if url_match:
            url = url_match.group(1).strip("'\"")

            # 检查是否有 POST 方法
            is_post = "post" in text.lower() and "-X POST" in text

            return {
                "type": "tool_call",
                "tool": "curl",
                "arguments": {"url": url, "method": "POST" if is_post else "GET"},
            }

        return {"type": "think", "content": f"无法解析 curl 命令。{text[:200]}"}

    def _execute_tool_call(self, decision: Dict[str, Any]) -> str:
        """执行工具调用"""
        tool = decision.get("tool", "")
        args = decision.get("arguments", {})

        print(f"\n[Executing] {tool}({json.dumps(args, ensure_ascii=False)[:100]})")

        result = self.tools.execute(tool, args)
        print(f"\n[Result]\n{result[:500]}")

        return result

    def _extract_findings(self, result: str, step: int) -> List[Dict]:
        """从工具结果中提取发现"""
        findings = []

        # Flag 检测
        flag_matches = re.findall(r"FLAG\{[^}]+\}", result)
        for flag in flag_matches:
            findings.append({
                "kind": "flag",
                "value": flag,
                "step": step,
                "confirmed": True,
            })

        # Source leak 检测
        if "highlight_file" in result.lower():
            findings.append({
                "kind": "source_leak",
                "value": "highlight_file",
                "step": step,
                "confirmed": True,
            })

        # 参数检测
        param_matches = re.findall(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=", result)
        for param in set(param_matches):
            findings.append({
                "kind": "parameter",
                "value": param,
                "step": step,
                "confirmed": False,
            })

        # 端点检测
        url_matches = re.findall(r"https?://[^\s<>\"']+", result)
        for url in set(url_matches[:5]):
            findings.append({
                "kind": "endpoint",
                "value": url,
                "step": step,
                "confirmed": False,
            })

        # 黑名单函数检测
        blacklist_funcs = ["exec", "system", "shell_exec", "eval", "assert",
                          "file_get_contents", "readfile", "highlight_file",
                          "call_user_func", "forward_static_call", "passthru"]
        for func in blacklist_funcs:
            if func in result and f"blacklist_function:{func}" not in str(findings):
                findings.append({
                    "kind": "blacklist_function",
                    "value": func,
                    "step": step,
                    "confirmed": False,
                })

        return findings

    def _update_state(
        self,
        decision: Dict[str, Any],
        result: str,
        new_findings: List[Dict],
        step: int,
    ) -> None:
        """更新状态文件"""
        # 追加工具结果
        self.state.append_tool_result(
            tool=decision.get("tool", ""),
            args=decision.get("arguments", {}),
            output=result,
            success=True,
        )

        # 追加 findings
        if new_findings:
            self.state.add_findings(new_findings)
            self.no_new_findings_count = 0
            print(f"\n[Findings] 新发现 {len(new_findings)} 条:")
            for f in new_findings:
                print(f"  - {f.get('kind')}: {f.get('value')}")
        else:
            self.no_new_findings_count += 1
            print(f"\n[Findings] 无新发现（连续 {self.no_new_findings_count} 次）")

            # 失败模式记录（Phase 1 新增）
            self._record_failure(decision, result, step)

    def _record_failure(self, decision: Dict[str, Any], result: str, step: int) -> None:
        """记录失败尝试，用于失败模式学习"""
        tool = decision.get("tool", "")
        args = decision.get("arguments", {})
        reason = self._analyze_failure_reason(result)

        failure = {
            "step": step,
            "tool": tool,
            "args": args,
            "reason": reason,
        }

        self.failed_attempts.append(failure)
        if len(self.failed_attempts) > self.max_failed_attempts:
            self.failed_attempts = self.failed_attempts[-self.max_failed_attempts:]

        print(f"\n[Failure Mode] 记录失败: {tool} - {reason}")

    def _analyze_failure_reason(self, result: str) -> str:
        """分析失败原因"""
        result_lower = result.lower()

        if "timeout" in result_lower or "timed out" in result_lower:
            return "timeout"
        if "error" in result_lower or "failed" in result_lower:
            if "connection" in result_lower:
                return "connection_error"
            if "auth" in result_lower or "401" in result_lower or "403" in result_lower:
                return "auth_error"
            if "404" in result_lower:
                return "not_found"
            return "execution_error"
        if "no new findings" in result_lower:
            return "no_findings"
        if "empty" in result_lower or "none" in result_lower:
            return "empty_result"

        return "unknown"

    def get_failed_attempts(self) -> List[Dict[str, str]]:
        """获取失败尝试记录"""
        return self.failed_attempts

    def should_skip_similar_attempt(self, tool: str, args: Dict) -> bool:
        """检查是否应该跳过相似的失败尝试"""
        action_key = f"{tool}:{json.dumps(args, sort_keys=True)}"

        # 检查最近失败中是否有完全相同的尝试
        for failed in self.failed_attempts[-5:]:
            failed_key = f"{failed['tool']}:{json.dumps(failed['args'], sort_keys=True)}"
            if action_key == failed_key:
                return True

        return False

    def _should_trigger_rag(self) -> bool:
        """判断是否需要触发 RAG"""
        if self.no_new_findings_count >= self.rag_trigger_threshold:
            target = self.state.get_target()
            if target and target.get("problem_type"):
                return True
        return False

    def _trigger_rag(self) -> None:
        """触发 RAG 检索"""
        target = self.state.get_target()
        if not target:
            return

        problem_type = target.get("problem_type", "")
        tags = target.get("taxonomy_tags", [])

        # 构建查询
        query = f"{problem_type} {', '.join(tags)}"

        # 搜索相关知识
        rag_results = search_knowledge(query, category=problem_type, top_k=3)

        # 构建 suggested_approach
        if rag_results:
            top = rag_results[0]
            suggested = f"根据 '{query}' 检索到相关知识：{top.get('title', '')}。{top.get('method', '')}"
        else:
            suggested = "连续多次无新发现，建议换一种攻击方向或请求人工指导"

        self.state.write_rag_knowledge(
            query=query,
            retrieved_knowledge=rag_results,
            suggested_approach=suggested,
        )

        self.no_new_findings_count = 0

    def _check_flag(self) -> bool:
        """检查是否已找到 flag"""
        findings = self.state.get_findings()
        for f in findings:
            if f.get("kind") == "flag" and f.get("confirmed"):
                return True
        return False
