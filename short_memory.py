"""
CTF Agent 短期记忆系统
=====================

为单道题目设计的轻量级记忆系统：
- 记录解题步骤
- 防止重复尝试
- 追踪关键发现（端点、参数、flag等）
- 题目结束后可清除

使用示例:
    from short_memory import ShortMemory

    # 开始新题目
    memory = ShortMemory()

    # 添加步骤
    memory.add_step(tool="sqlmap", target="http://target/page?id=1",
                    result="发现SQL注入", success=True)

    # 检查是否尝试过
    if not memory.has_tried(tool="sqlmap", target="http://target/page?id=1"):
        # 执行...
"""

import hashlib
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


FLAG_PATTERNS = [
    r'ctfshow\{[^}\r\n]+\}',
    r'tfshow\{[^}\r\n]+\}',
    r'HCTF\{[^}\r\n]+\}',
    r'FLAG\{[^}\r\n]+\}',
    r'flag\{[^}\r\n]+\}',
    r'ctf\{[^}\r\n]+\}',
]


GENERIC_FINDING_PATTERNS = {
    "repo_exposure": [r'\.git(?:/head|/config)?', r'\.svn/entries', r'\.hg'],
    "backup_file": [r'backup', r'\.zip', r'\.tar(?:\.gz)?', r'\.bak', r'\.old', r'\.swp'],
    "debug_page": [r'phpinfo', r'debug', r'test\.php', r'info\.php'],
    "source_leak": [r'source leak', r'源码泄露', r'highlight_file', r'view-source'],
    "shell_artifact": [r'webshell', r'backdoor\.php', r'@eval\(', r'letmein'],
    "sensitive_file": [r'\.env', r'config\.php', r'flag\.txt', r'/etc/passwd'],
    "info_leak": [r'php version', r'x-powered-by', r'server:', r'content-type:'],
}


def extract_flag_candidates(text: str) -> List[str]:
    """从文本中提取 flag 候选，保持首次出现顺序。"""
    result_text = str(text or "")
    matches = []
    occupied_spans = []
    for pattern in FLAG_PATTERNS:
        for match in re.finditer(pattern, result_text, re.IGNORECASE):
            span = match.span()
            if any(span[0] < end and span[1] > start for start, end in occupied_spans):
                continue
            occupied_spans.append(span)
            matches.append((match.start(), match.group(0)))

    matches.sort(key=lambda item: item[0])
    ordered_flags: List[str] = []
    seen = set()
    for _, flag in matches:
        normalized = flag.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        ordered_flags.append(flag)
    return ordered_flags


def classify_generic_findings(text: str) -> List[Dict[str, str]]:
    """从通用文本中抽取高价值 finding taxonomy。"""
    result_text = str(text or "")
    lower_text = result_text.lower()
    findings: List[Dict[str, str]] = []
    for kind, patterns in GENERIC_FINDING_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower_text, re.IGNORECASE):
                findings.append({"kind": kind, "value": pattern})
                break
    return findings


@dataclass
class Step:
    """单个解题步骤"""
    num: int
    tool: str
    target: str
    params: Dict[str, Any]
    result: str
    success: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    key_findings: List[str] = field(default_factory=list)
    action_id: str = ""
    action_type: str = ""
    expected_tool: str = ""
    canonical_tool: str = ""
    parsed: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    phase: str = "attack"  # 阶段标记: "recon" 信息收集 | "attack" 攻击解题


@dataclass
class TargetInfo:
    """目标信息"""
    url: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    problem_type: Optional[str] = None  # 题目类型
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    # AWD 新增字段
    awd_mode: bool = False              # 是否 AWD 模式
    awd_phase: str = "attack"           # attack | defense
    target_code: str = ""               # 待分析的代码
    patches: List[Dict] = field(default_factory=list)  # 修补点列表


@dataclass
class AgentContext:
    """题目初始化上下文，供主链路共享"""
    problem_type: Optional[str] = None
    url: Optional[str] = None
    description: str = ""
    hint: str = ""
    skill_content: str = ""
    loaded_resources: Dict[str, Any] = field(default_factory=dict)
    wooyun_ref: str = ""
    human_guidance: str = ""
    help_history: List[Dict[str, Any]] = field(default_factory=list)
    resume_count: int = 0
    shared_findings: List[Dict[str, Any]] = field(default_factory=list)
    rag_attempt_anchor_step: int = 0
    rag_attempt_step: int = 0
    rag_query: str = ""
    rag_summary: str = ""
    rag_suggested_approach: str = ""
    rag_attempted_in_current_window: bool = False
    current_round: int = 1
    round_started_step: int = 0
    round_new_findings_count: int = 0
    round_attempted_families: List[str] = field(default_factory=list)
    round_resource_sources_used: List[str] = field(default_factory=list)
    help_readiness_reason: str = ""
    initial_required_families: List[str] = field(default_factory=list)
    legacy_help_mode: bool = False
    initialized_at: str = field(default_factory=lambda: datetime.now().isoformat())


class ShortMemory:
    """
    短期记忆系统 - 单道题目内使用

    功能:
    1. 记录所有尝试的步骤
    2. 检测重复尝试（防止循环）
    3. 追踪目标关键信息
    4. 标识成功/失败尝试
    """

    def __init__(self):
        self.steps: List[Step] = []
        self.target = TargetInfo()
        self.context = AgentContext()
        self._attempted: Set[str] = set()  # 已尝试的签名
        self._failures: Dict[str, int] = {}  # 签名级失败计数
        self._action_failures: Dict[str, int] = {}  # action_id 级失败计数

    def add_step(
        self,
        tool: str,
        target: str,
        params: Dict = None,
        result: str = "",
        success: bool = False,
        key_findings: List[str] = None,
        action_meta: Optional[Dict[str, Any]] = None,
        parsed: Optional[Dict[str, Any]] = None,
        artifacts: Optional[List[Dict[str, Any]]] = None,
        observations: Optional[List[Dict[str, Any]]] = None,
        phase: str = "attack",
    ) -> Step:
        """
        添加解题步骤

        Args:
            tool: 使用的工具
            target: 目标
            params: 参数
            result: 执行结果
            success: 是否成功
            key_findings: 关键发现
            action_meta: 动作元信息
            parsed: 结构化解析结果
            artifacts: 结构化产物列表
            observations: 归一化 observation 列表
        """
        normalized_params = dict(params or {})
        normalized_action = self._normalize_action_meta(tool, normalized_params, action_meta)
        result_text = str(result)

        step = Step(
            num=len(self.steps) + 1,
            tool=tool,
            target=target,
            params=normalized_params,
            result=result_text[:500] if len(result_text) > 500 else result_text,
            success=success,
            key_findings=key_findings or [],
            action_id=normalized_action.get("action_id", ""),
            action_type=normalized_action.get("action_type", ""),
            expected_tool=normalized_action.get("expected_tool", ""),
            canonical_tool=normalized_action.get("canonical_tool", tool),
            parsed=dict(parsed or {}),
            artifacts=list(artifacts or []),
            observations=list(observations or []),
            phase=normalized_action.get("phase", "attack"),
        )
        self.steps.append(step)

        # 记录尝试 - 同时记录完整签名和简单签名，支持模糊匹配
        sig = self._signature(tool, target, normalized_params)
        sig_simple = self._signature(tool, target, None)
        self._attempted.add(sig)
        self._attempted.add(sig_simple)  # 支持不带params的查询
        if not success:
            self._failures[sig] = self._failures.get(sig, 0) + 1
            if step.action_id:
                self._action_failures[step.action_id] = self._action_failures.get(step.action_id, 0) + 1

        # 自动提取关键信息
        before_findings = self._count_structured_findings()
        self._extract_from_step(step)
        after_findings = self._count_structured_findings()
        if after_findings > before_findings:
            self.context.round_new_findings_count += after_findings - before_findings

        return step

    def has_tried(self, tool: str, target: str, params: Dict = None) -> bool:
        """检查是否已经尝试过"""
        sig = self._signature(tool, target, params)
        return sig in self._attempted

    def fail_count(self, tool: str, target: str, params: Dict = None) -> int:
        """获取某方法的失败次数"""
        sig = self._signature(tool, target, params)
        return self._failures.get(sig, 0)

    def should_skip(self, tool: str, target: str, params: Dict = None,
                    max_failures: int = 3) -> bool:
        """判断是否应该跳过（失败太多次）"""
        return self.fail_count(tool, target, params) >= max_failures

    def action_fail_count(self, action_id: str) -> int:
        """获取某个 action_id 的失败次数。"""
        if not action_id:
            return 0
        return self._action_failures.get(action_id, 0)

    def fail_count_for_step(self, step: Step) -> int:
        """优先按 action_id 查询失败次数，缺失时退回旧签名。"""
        if step.action_id:
            return self.action_fail_count(step.action_id)
        return self.fail_count(step.tool, step.target, step.params)

    def should_skip_action(self, action_id: str, max_failures: int = 3) -> bool:
        """判断某个 action_id 是否应该跳过。"""
        return bool(action_id) and self.action_fail_count(action_id) >= max_failures

    def latest_step_for_action(self, action_id: str) -> Optional[Step]:
        """返回某个 action_id 对应的最新一步。"""
        if not action_id:
            return None
        for step in reversed(self.steps):
            if step.action_id == action_id:
                return step
        return None

    def get_summary(self) -> str:
        """获取当前解题摘要"""
        lines = []
        lines.append(f"{'=' * 50}")
        lines.append(f"题目进度: {len(self.steps)} 步")
        lines.append(f"{'=' * 50}")

        # 目标信息
        if self.target.url or self.target.ip:
            lines.append(f"\n目标: {self.target.url or self.target.ip}")
        if self.target.problem_type:
            lines.append(f"题目类型: {self.target.problem_type}")
        if self.target.tech_stack:
            lines.append(f"技术栈: {', '.join(self.target.tech_stack)}")
        if self.target.endpoints:
            lines.append(f"端点: {', '.join(self.target.endpoints[:5])}")
        if self.target.vulnerabilities:
            lines.append(f"漏洞: {[v['type'] for v in self.target.vulnerabilities]}")
        if self.target.flags:
            lines.append(f"[FLAG] {self.target.flags}")

        # 最近步骤
        lines.append("\n最近尝试:")
        for step in self.steps[-5:]:
            status = "[OK]" if step.success else "[FAIL]"
            action_hint = f" action={step.action_id}" if step.action_id else ""
            lines.append(f"  {status} [{step.tool}] {step.target[:50]}...{action_hint}")
            if step.key_findings:
                lines.append(f"    -> {', '.join(step.key_findings[:3])}")

        # 重复尝试警告
        if self._action_failures:
            lines.append("\n动作失败统计:")
            for action_id, count in sorted(self._action_failures.items(), key=lambda x: -x[1])[:3]:
                if count >= 2:
                    lines.append(f"  {action_id}: 失败 {count} 次")
        elif self._failures:
            lines.append("\n失败统计:")
            for sig, count in sorted(self._failures.items(), key=lambda x: -x[1])[:3]:
                if count >= 2:
                    lines.append(f"  {sig[:20]}...: 失败 {count} 次")

        return "\n".join(lines)

    def get_suggested_next(self) -> List[str]:
        """获取建议的下一步（基于失败历史）"""
        suggestions = []

        # 分析重复失败的模式
        if self._action_failures:
            for action_id, count in self._action_failures.items():
                if count >= 2:
                    suggestions.append(f"避免重复动作: {action_id} 已失败 {count} 次")
        elif self._failures:
            for sig, count in self._failures.items():
                if count >= 2:
                    suggestions.append(f"避免重复: {sig[:30]}... 已失败 {count} 次")

        # 基于当前进度建议
        if not self.target.endpoints and not any(s.tool == "dirsearch" for s in self.steps):
            suggestions.append("建议: 尝试目录扫描发现端点")

        if self.target.parameters and not any(s.tool == "sqlmap" for s in self.steps):
            suggestions.append("建议: 发现参数，尝试SQL注入测试")

        return suggestions

    def update_target(self, **kwargs):
        """更新目标信息"""
        for key, value in kwargs.items():
            if hasattr(self.target, key):
                setattr(self.target, key, value)
        # 同步可能的上下文字段
        if "problem_type" in kwargs and kwargs["problem_type"]:
            self.context.problem_type = kwargs["problem_type"]
        if "url" in kwargs and kwargs["url"]:
            self.context.url = kwargs["url"]

    def add_endpoint(self, endpoint: str):
        """添加发现的端点"""
        if endpoint not in self.target.endpoints:
            self.target.endpoints.append(endpoint)

    def add_parameter(self, parameter: str):
        """添加发现的参数"""
        if parameter not in self.target.parameters:
            self.target.parameters.append(parameter)

    def add_vulnerability(self, vuln_type: str, description: str = ""):
        """添加发现的漏洞"""
        vuln = {"type": vuln_type, "desc": description}
        if vuln not in self.target.vulnerabilities:
            self.target.vulnerabilities.append(vuln)

    def add_flag(self, flag: str):
        """添加找到的flag"""
        if flag not in self.target.flags:
            self.target.flags.append(flag)

    def add_patch(
        self,
        location: str,
        vuln_type: str,
        fix_suggestion: str,
        code_snippet: str = "",
    ) -> Dict[str, Any]:
        """添加 AWD 修补点。"""
        patch = {
            "location": location,
            "vuln_type": vuln_type,
            "fix_suggestion": fix_suggestion,
            "code_snippet": code_snippet,
        }
        if patch not in self.target.patches:
            self.target.patches.append(patch)
        return patch

    def get_patch_summary(self) -> str:
        """获取当前修补点摘要。"""
        if not self.target.patches:
            return "暂无修补点"

        lines = [f"修补点: {len(self.target.patches)} 处"]
        for idx, patch in enumerate(self.target.patches, 1):
            lines.append(
                f"{idx}. [{patch.get('vuln_type', 'unknown')}] {patch.get('location', 'unknown')} -> {patch.get('fix_suggestion', '')}"
            )
            code_snippet = (patch.get("code_snippet") or "").strip()
            if code_snippet:
                lines.append(f"   代码: {code_snippet[:120]}")
        return "\n".join(lines)

    def set_context(self, context: Optional[AgentContext] = None, **kwargs) -> AgentContext:
        """设置题目上下文，支持传入 dataclass 或关键字"""
        if context is not None:
            self.context = context
        else:
            for key, value in kwargs.items():
                if hasattr(self.context, key):
                    setattr(self.context, key, value)
        # 同步关键信息到 target
        if self.context.url:
            self.target.url = self.context.url
        if self.context.problem_type:
            self.target.problem_type = self.context.problem_type
        return self.context

    def get_context(self) -> AgentContext:
        """获取当前题目的上下文信息"""
        return self.context

    def note_attempted_family(self, family: str) -> None:
        family_text = str(family or "").strip()
        if not family_text:
            return
        if family_text not in self.context.round_attempted_families:
            self.context.round_attempted_families.append(family_text)

    def note_resource_source_used(self, source: str) -> None:
        source_text = str(source or "").strip()
        if not source_text:
            return
        if source_text not in self.context.round_resource_sources_used:
            self.context.round_resource_sources_used.append(source_text)

    def start_new_round(self, step: int = 0, reason: str = "") -> None:
        self.context.current_round = max(int(getattr(self.context, "current_round", 1) or 1) + 1, 1)
        self.context.round_started_step = int(step or 0)
        self.context.round_new_findings_count = 0
        self.context.round_attempted_families = []
        self.context.round_resource_sources_used = []
        self.context.help_readiness_reason = str(reason or "")

    def set_help_readiness_reason(self, reason: str) -> None:
        self.context.help_readiness_reason = str(reason or "")

    def _count_structured_findings(self) -> int:
        total = len(self.target.endpoints) + len(self.target.parameters) + len(self.target.flags)
        total += len(self.target.vulnerabilities)
        generic_markers = 0
        for step in self.steps:
            for finding in list(step.key_findings or []):
                text = str(finding or "")
                if text.startswith("repo_exposure:") or text.startswith("backup_file:") or text.startswith("debug_page:") or text.startswith("source_leak:") or text.startswith("shell_artifact:") or text.startswith("sensitive_file:") or text.startswith("info_leak:"):
                    generic_markers += 1
        return total + generic_markers

    def snapshot_progress(self) -> Dict[str, Any]:
        return {
            "current_round": int(getattr(self.context, "current_round", 1) or 1),
            "round_started_step": int(getattr(self.context, "round_started_step", 0) or 0),
            "round_new_findings_count": int(getattr(self.context, "round_new_findings_count", 0) or 0),
            "round_attempted_families": list(getattr(self.context, "round_attempted_families", []) or []),
            "round_resource_sources_used": list(getattr(self.context, "round_resource_sources_used", []) or []),
            "structured_findings_total": self._count_structured_findings(),
        }

    def _reset_rag_gate_state(self) -> None:
        """重置当前失败窗口的 RAG-before-help 状态。"""
        self.context.rag_attempt_anchor_step = 0
        self.context.rag_attempt_step = 0
        self.context.rag_query = ""
        self.context.rag_summary = ""
        self.context.rag_suggested_approach = ""
        self.context.rag_attempted_in_current_window = False

    def add_help_entry(
        self,
        request: str,
        guidance: str = "",
        reason: str = "",
        step: int = 0,
    ) -> Dict[str, Any]:
        """记录一次 help / resume 交互。"""
        entry = {
            "step": step,
            "request": request,
            "guidance": guidance,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }
        self.context.help_history.append(entry)
        self.context.help_history = self.context.help_history[-10:]
        if guidance:
            self.context.human_guidance = guidance
        return entry

    def apply_human_guidance(
        self,
        guidance: str,
        step: int = 0,
        reason: str = "",
    ) -> Dict[str, Any]:
        """把人工提示关联到最近一次 help 记录。"""
        if self.context.help_history and not self.context.help_history[-1].get("guidance"):
            entry = self.context.help_history[-1]
            entry["guidance"] = guidance
            if step:
                entry["resume_step"] = step
            if reason and not entry.get("reason"):
                entry["reason"] = reason
            entry["updated_at"] = datetime.now().isoformat()
        else:
            entry = self.add_help_entry(request="", guidance=guidance, reason=reason, step=step)

        self.context.human_guidance = guidance
        self.context.resume_count += 1
        self.start_new_round(step=step, reason=reason or "resume")
        self._reset_rag_gate_state()
        return entry

    # === AWD 方法 ===

    def set_awd_phase(self, phase: str):
        """切换 AWD 阶段"""
        if phase in ["attack", "defense"]:
            self.target.awd_mode = True
            self.target.awd_phase = phase

    def clear(self):
        """清除记忆（题目结束时）"""
        self.steps.clear()
        self._attempted.clear()
        self._failures.clear()
        self._action_failures.clear()
        self.target = TargetInfo()
        self.context = AgentContext()

    def _signature(self, tool: str, target: str, params: Dict = None) -> str:
        """生成尝试签名"""
        params = params or {}
        normalized = f"{tool}:{target}:{str(sorted(params.items()))}"
        return hashlib.md5(normalized.encode()).hexdigest()[:16]

    def _normalize_action_meta(
        self,
        tool: str,
        params: Optional[Dict[str, Any]] = None,
        action_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, str]:
        """从 action_meta 或旧 params 中提取统一动作元信息。"""
        params = params or {}
        action_meta = dict(action_meta or {})

        action_id = str(action_meta.get("action_id") or params.get("action_id") or "")
        action_type = str(action_meta.get("action_type") or params.get("action_type") or "")
        expected_tool = str(action_meta.get("expected_tool") or params.get("expected_tool") or "")
        canonical_tool = str(
            action_meta.get("canonical_tool")
            or params.get("canonical_tool")
            or expected_tool
            or tool
        )
        phase = str(action_meta.get("phase") or params.get("phase") or "attack")

        return {
            "action_id": action_id,
            "action_type": action_type,
            "expected_tool": expected_tool,
            "canonical_tool": canonical_tool,
            "phase": phase,
        }

    def _extract_from_step(self, step: Step):
        """从步骤中自动提取关键信息"""
        result = step.result

        for observation in list(step.observations or []):
            if not isinstance(observation, dict):
                continue
            kind = str(observation.get("kind") or "").strip()
            value = str(observation.get("value") or "").strip()
            if not kind or not value:
                continue
            marker = f"{kind}:{value}"
            if marker not in step.key_findings:
                step.key_findings.append(marker)
            if kind == "endpoint":
                self.add_endpoint(value)
            elif kind in {"parameter", "form_field"}:
                self.add_parameter(value)
            elif kind == "vulnerability":
                self.add_vulnerability(value)

        # 提取URL
        url_match = re.search(r'https?://[^\s<>"\']+', result)
        if url_match and not self.target.url:
            self.target.url = url_match.group(0)
            self.context.url = self.target.url

        # 提取IP
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', result)
        if ip_match and not self.target.ip:
            self.target.ip = ip_match.group(0)

        # 提取端点
        endpoint_pattern = r'(?:Found|Directory|Path):?\s*(/[^\s]+)'
        endpoints = re.findall(endpoint_pattern, result, re.IGNORECASE)
        for ep in endpoints:
            self.add_endpoint(ep)

        sensitive_endpoint_pattern = r'(?:Sensitive path|Exposed file|Interesting path):\s*(/[^\s]+)'
        sensitive_endpoints = re.findall(sensitive_endpoint_pattern, result, re.IGNORECASE)
        for ep in sensitive_endpoints:
            self.add_endpoint(ep)
            if ep not in step.key_findings:
                step.key_findings.append(ep)

        auth_endpoint_pattern = r'Found login form endpoint:\s*(/[^\s]+)'
        auth_endpoints = re.findall(auth_endpoint_pattern, result, re.IGNORECASE)
        for ep in auth_endpoints:
            self.add_endpoint(ep)

        # 提取参数
        param_pattern = r'[?&]([^=]+)='
        params = re.findall(param_pattern, result)
        for p in params:
            if p not in self.target.parameters:
                self.target.parameters.append(p)

        if "phpinfo" in result.lower():
            for finding in ["phpinfo_exposed", "info_leak"]:
                if finding not in step.key_findings:
                    step.key_findings.append(finding)

        high_value_tokens = [".git/head", ".git/config", ".svn/entries", ".env", "backup", ".zip", ".tar.gz", "webshell", "backdoor.php"]
        lower_result = result.lower()
        for token in high_value_tokens:
            if token in lower_result and token not in [item.lower() for item in step.key_findings]:
                step.key_findings.append(token)

        generic_findings = classify_generic_findings(result)
        for finding in generic_findings:
            marker = f"{finding['kind']}:{finding['value']}"
            if marker not in step.key_findings:
                step.key_findings.append(marker)

        auth_params = re.findall(r'Form field:\s*([A-Za-z0-9_\-]+)', result)
        for p in auth_params:
            if p not in self.target.parameters:
                self.target.parameters.append(p)

        # 提取Flag候选
        for flag in extract_flag_candidates(result):
            if flag not in step.key_findings:
                step.key_findings.append(flag)


# 全局实例（单道题目使用）
_short_memory: Optional[ShortMemory] = None


def get_short_memory() -> ShortMemory:
    """获取全局短期记忆实例"""
    global _short_memory
    if _short_memory is None:
        _short_memory = ShortMemory()
    return _short_memory


def reset_short_memory():
    """重置短期记忆（开始新题目时调用）"""
    global _short_memory
    _short_memory = ShortMemory()
    print("[Memory] 已开始新题目的短期记忆")


__all__ = ["ShortMemory", "get_short_memory", "reset_short_memory", "AgentContext", "Step", "extract_flag_candidates", "classify_generic_findings"]
