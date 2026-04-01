"""
phase_gate.py - 阶段切换逻辑

Phase 2 核心组件：
1. 阶段门口条件 - 进入下一阶段前必须满足的条件
2. 自动检测阶段完成 - 满足条件时建议或自动切换阶段
3. 阶段转换验证 - 确保转换的合理性

阶段流程：
    Recon → Identify → Exploit → Flag
"""

from enum import Enum
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass


class Phase(Enum):
    """阶段枚举"""
    RECON = "recon"
    IDENTIFY = "identify"
    EXPLOIT = "exploit"
    FLAG = "flag"

    @classmethod
    def from_string(cls, s: str) -> "Phase":
        """从字符串创建 Phase"""
        s = s.lower().strip()
        for p in cls:
            if p.value == s:
                return p
        return cls.RECON

    def next(self) -> Optional["Phase"]:
        """获取下一阶段"""
        order = [Phase.RECON, Phase.IDENTIFY, Phase.EXPLOIT, Phase.FLAG]
        try:
            idx = order.index(self)
            return order[idx + 1] if idx + 1 < len(order) else None
        except ValueError:
            return None

    def prev(self) -> Optional["Phase"]:
        """获取上一阶段"""
        order = [Phase.RECON, Phase.IDENTIFY, Phase.EXPLOIT, Phase.FLAG]
        try:
            idx = order.index(self)
            return order[idx - 1] if idx > 0 else None
        except ValueError:
            return None


# 阶段配置
PHASE_CONFIG = {
    Phase.RECON: {
        "name": "信息收集",
        "budget": 10,
        "allowed_tools": ["curl", "dirsearch"],
        "min_findings": 2,  # 最少发现数
    },
    Phase.IDENTIFY: {
        "name": "漏洞识别",
        "budget": 8,
        "allowed_tools": ["curl", "sqlmap"],
        "min_findings": 1,  # 必须确定漏洞类型
        "required_hypothesis": True,  # 必须声明假设
    },
    Phase.EXPLOIT: {
        "name": "漏洞利用",
        "budget": 15,
        "allowed_tools": ["curl", "python"],
        "min_findings": 2,  # 需要有攻击方案
        "hypothesis_verified": True,  # 假设必须已验证
    },
    Phase.FLAG: {
        "name": "获取 Flag",
        "budget": 1,
        "allowed_tools": [],
    },
}


@dataclass
class PhaseGateResult:
    """阶段门口检查结果"""
    can_pass: bool
    message: str
    missing_conditions: List[str]
    suggested_actions: List[str]


class PhaseGate:
    """
    阶段门口检查器

    检查是否满足进入下一阶段的条件
    """

    def __init__(self):
        self._state = None
        self._load_state()

    def _load_state(self):
        """加载状态"""
        try:
            from core.state_manager import get_state_manager
            self._state = get_state_manager().get_state()
        except Exception:
            self._state = {}

    def refresh_state(self):
        """刷新状态"""
        self._load_state()

    def check_transition(self, from_phase: Phase, to_phase: Phase) -> PhaseGateResult:
        """
        检查是否可以从 from_phase 转换到 to_phase

        Args:
            from_phase: 当前阶段（字符串或 Phase 枚举）
            to_phase: 目标阶段（字符串或 Phase 枚举）

        Returns:
            PhaseGateResult: 检查结果
        """
        self.refresh_state()

        # 转换字符串到 Phase 枚举
        if isinstance(from_phase, str):
            from_phase = Phase.from_string(from_phase)
        if isinstance(to_phase, str):
            to_phase = Phase.from_string(to_phase)

        # 如果是后退阶段，总是允许
        if from_phase != Phase.FLAG and to_phase == Phase.RECON:
            return PhaseGateResult(
                can_pass=True,
                message="允许返回信息收集阶段重新开始",
                missing_conditions=[],
                suggested_actions=[]
            )

        # 同阶段转换
        if from_phase == to_phase:
            return PhaseGateResult(
                can_pass=True,
                message="已在目标阶段",
                missing_conditions=[],
                suggested_actions=[]
            )

        # 检查是否允许的方向
        if to_phase not in [Phase.RECON, Phase.IDENTIFY, Phase.EXPLOIT, Phase.FLAG]:
            return PhaseGateResult(
                can_pass=False,
                message=f"未知阶段: {to_phase}",
                missing_conditions=[f"未知目标阶段 {to_phase}"],
                suggested_actions=["使用有效的阶段名称: recon, identify, exploit, flag"]
            )

        # 按目标阶段检查条件
        if to_phase == Phase.IDENTIFY:
            return self._check_identify_gate()
        elif to_phase == Phase.EXPLOIT:
            return self._check_exploit_gate()
        elif to_phase == Phase.FLAG:
            return self._check_flag_gate()

        return PhaseGateResult(
            can_pass=True,
            message="阶段转换检查通过",
            missing_conditions=[],
            suggested_actions=[]
        )

    def _check_identify_gate(self) -> PhaseGateResult:
        """检查是否可以进入 Identify 阶段"""
        missing = []
        actions = []

        # Recon 阶段至少需要收集到目标信息
        findings = self._state.get("findings", [])
        if len(findings) < 2:
            missing.append(f"信息收集不足（需要至少 2 个发现，当前 {len(findings)} 个）")
            actions.append("使用 curl 访问目标页面获取更多信息")
            actions.append("使用 dirsearch 扫描目录结构")

        if not self._state.get("target"):
            missing.append("未设置目标 URL")
            actions.append("调用 init_state(target_url, challenge_type) 初始化状态")

        if missing:
            return PhaseGateResult(
                can_pass=False,
                message="不满足 Identify 阶段入口条件",
                missing_conditions=missing,
                suggested_actions=actions
            )

        return PhaseGateResult(
            can_pass=True,
            message="满足 Identify 阶段入口条件",
            missing_conditions=[],
            suggested_actions=["声明当前假设：漏洞类型 + 攻击向量 + 预期结果"]
        )

    def _check_exploit_gate(self) -> PhaseGateResult:
        """检查是否可以进入 Exploit 阶段"""
        missing = []
        actions = []

        # Identify 阶段需要有明确的漏洞类型
        findings = self._state.get("findings", [])
        if len(findings) < 1:
            missing.append("缺少关键发现")
            actions.append("确定漏洞类型和攻击向量")

        # 必须有假设且已验证或待验证
        hypothesis = self._state.get("current_hypothesis", "")
        hypothesis_status = self._state.get("hypothesis_status", "unverified")

        if not hypothesis:
            missing.append("未声明当前假设")
            actions.append("声明假设：目标漏洞类型 + 攻击向量 + 预期结果")
        elif hypothesis_status == "failed":
            missing.append("当前假设已被证伪，需要新假设")
            actions.append("分析失败原因，制定新的攻击假设")

        # 检查是否有已验证的发现支持攻击
        has_vulnerability_indicator = any(
            keyword in str(findings).lower()
            for keyword in ["vulnerability", "injection", "upload", "lfi", "rce", "sqli", "xss", "upload", "auth"]
        )
        if not has_vulnerability_indicator:
            missing.append("未确定漏洞类型")
            actions.append("先确定漏洞类型再进行利用")

        if missing:
            return PhaseGateResult(
                can_pass=False,
                message="不满足 Exploit 阶段入口条件",
                missing_conditions=missing,
                suggested_actions=actions
            )

        return PhaseGateResult(
            can_pass=True,
            message="满足 Exploit 阶段入口条件",
            missing_conditions=[],
            suggested_actions=["基于假设执行攻击尝试获取 flag"]
        )

    def _check_flag_gate(self) -> PhaseGateResult:
        """检查是否可以进入 Flag 阶段"""
        missing = []
        actions = []

        flag = self._state.get("flag", "")
        if not flag:
            missing.append("未找到 flag")
            actions.append("继续 Exploit 阶段尝试获取 flag")

        if missing:
            return PhaseGateResult(
                can_pass=False,
                message="不满足 Flag 阶段入口条件",
                missing_conditions=missing,
                suggested_actions=actions
            )

        return PhaseGateResult(
            can_pass=True,
            message="满足 Flag 阶段入口条件，可以保存经验",
            missing_conditions=[],
            suggested_actions=["调用 set_flag() 保存经验"]
        )

    def should_auto_suggest_transition(self) -> Optional[Tuple[Phase, Phase, str]]:
        """
        检查是否应该自动建议阶段转换

        Returns:
            (from_phase, to_phase, reason) 或 None
        """
        self.refresh_state()

        current_phase = Phase.from_string(self._state.get("phase", Phase.RECON.value))
        findings = self._state.get("findings", [])
        hypothesis = self._state.get("current_hypothesis", "")
        hypothesis_status = self._state.get("hypothesis_status", "unverified")
        flag = self._state.get("flag", "")

        # Recon → Identify: 收集到足够信息
        if current_phase == Phase.RECON:
            if len(findings) >= 2:
                return (
                    current_phase,
                    Phase.IDENTIFY,
                    f"信息收集完成（{len(findings)} 个发现），建议进入漏洞识别阶段"
                )

        # Identify → Exploit: 确定漏洞类型和攻击向量
        elif current_phase == Phase.IDENTIFY:
            if hypothesis and hypothesis_status == "verified":
                return (
                    current_phase,
                    Phase.EXPLOIT,
                    "假设已验证成功，建议进入漏洞利用阶段"
                )
            # 即使假设未验证，如果有明确的攻击方案也可以进入 Exploit
            if hypothesis and len(findings) >= 2:
                return (
                    current_phase,
                    Phase.EXPLOIT,
                    "已有攻击假设和关键发现，建议进入漏洞利用阶段"
                )

        # Exploit → Flag: 找到 flag
        elif current_phase == Phase.EXPLOIT:
            if flag:
                return (
                    current_phase,
                    Phase.FLAG,
                    "已找到 flag，建议进入 Flag 阶段保存经验"
                )

        return None


def check_phase_transition(current: str, target: str) -> PhaseGateResult:
    """
    快捷函数：检查阶段转换是否允许

    Args:
        current: 当前阶段字符串
        target: 目标阶段字符串

    Returns:
        PhaseGateResult
    """
    gate = PhaseGate()
    from_phase = Phase.from_string(current)
    to_phase = Phase.from_string(target)
    return gate.check_transition(from_phase, to_phase)


def get_transition_suggestion() -> Optional[str]:
    """
    获取阶段转换建议

    Returns:
        建议消息或 None
    """
    gate = PhaseGate()
    suggestion = gate.should_auto_suggest_transition()
    if suggestion:
        from_phase, to_phase, reason = suggestion
        return f"💡 建议转换阶段: {from_phase.value} → {to_phase.value}\n原因: {reason}"
    return None


# 全局实例
_gate: Optional[PhaseGate] = None


def get_gate() -> PhaseGate:
    """获取 PhaseGate 单例"""
    global _gate
    if _gate is None:
        _gate = PhaseGate()
    return _gate