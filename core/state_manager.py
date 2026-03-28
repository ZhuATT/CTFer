"""
解题状态持久化 - P3 组件
用于保存和恢复解题进度，支持长对话中断后继续

Phase 1 增强：推理历史、失败模式、建议 bypass
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class StateManager:
    """
    解题状态管理器

    状态结构：
    {
        "target": "http://example.com",
        "type": "rce",
        "step": 5,
        "findings": [...],
        "methods_tried": [...],
        "failed_patterns": [...],
        "suggested_bypass": [...],
        "reasoning_chain": [
            {"step": 1, "action": "curl homepage", "finding": "Admin Login form"},
            {"step": 2, "action": "test sql injection", "finding": "Login success"},
        ],
        "flag": "FLAG{...}",
        "created_at": "...",
        "updated_at": "..."
    }
    """

    DEFAULT_STATE_FILE = "workspace/state.json"

    def __init__(self, state_file: Optional[str] = None):
        if state_file is None:
            project_root = Path(__file__).parent.parent
            state_file = str(project_root / self.DEFAULT_STATE_FILE)
        self.state_file = Path(state_file)
        self._state: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """从文件加载状态"""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._state = {}

    def _save(self) -> None:
        """保存状态到文件"""
        self._state["updated_at"] = datetime.now().isoformat()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self._state, f, ensure_ascii=False, indent=2)

    def init(self, target: str, challenge_type: str = "") -> None:
        """
        初始化新解题状态

        Args:
            target: 目标 URL
            challenge_type: 题型 (rce/sqli/auth/lfi/xss/upload)
        """
        self._state = {
            "target": target,
            "type": challenge_type,
            "step": 0,
            "findings": [],
            "methods_tried": [],
            "failed_patterns": [],
            "suggested_bypass": [],
            "reasoning_chain": [],
            "flag": "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        self._save()

    def update_step(self, step: int) -> None:
        """更新当前步骤"""
        self._state["step"] = step
        self._save()

    def add_finding(self, finding: str) -> None:
        """
        添加发现

        Args:
            finding: 发现描述（如 "copy flag.php works"）
        """
        if "findings" not in self._state:
            self._state["findings"] = []
        if finding not in self._state["findings"]:  # 避免重复
            self._state["findings"].append(finding)
        self._save()

    def add_method(self, method: str) -> None:
        """
        添加已尝试的方法

        Args:
            method: 方法名（如 "copy", "write", "system"）
        """
        if "methods_tried" not in self._state:
            self._state["methods_tried"] = []
        if method not in self._state["methods_tried"]:
            self._state["methods_tried"].append(method)
        self._save()

    def add_reasoning(self, action: str, finding: str) -> None:
        """
        添加推理链记录

        Args:
            action: 执行的动作（如 "curl /check.php with ro1e=admin"）
            finding: 发现的结论（如 "Flag found: CTF{...}"）
        """
        if "reasoning_chain" not in self._state:
            self._state["reasoning_chain"] = []
        step = len(self._state["reasoning_chain"]) + 1
        self._state["reasoning_chain"].append({
            "step": step,
            "action": action,
            "finding": finding,
            "timestamp": datetime.now().isoformat(),
        })
        self._save()

    def add_failed_pattern(self, pattern: str) -> None:
        """
        添加失败特征

        Args:
            pattern: 失败时出现的特征（如 "Admin Login", "Invalid credentials"）
        """
        if "failed_patterns" not in self._state:
            self._state["failed_patterns"] = []
        if pattern not in self._state["failed_patterns"]:
            self._state["failed_patterns"].append(pattern)
        self._save()

    def add_suggested_bypass(self, method: str, reason: str = "") -> None:
        """
        添加建议的 bypass 方法

        Args:
            method: bypass 方法（如 "修改 Cookie ro1e=admin"）
            reason: 为什么建议这个方法（如 "Cookie 伪造已成功"）
        """
        if "suggested_bypass" not in self._state:
            self._state["suggested_bypass"] = []
        entry = {"method": method}
        if reason:
            entry["reason"] = reason
        # 避免重复
        existing = [e["method"] for e in self._state["suggested_bypass"]]
        if method not in existing:
            self._state["suggested_bypass"].append(entry)
        self._save()

    def set_flag(self, flag: str, method_succeeded: str = None) -> None:
        """设置找到的 flag，并自动保存经验"""
        self._state["flag"] = flag
        self._save()

        # 自动保存经验（如果状态已初始化且有成功方法）
        if method_succeeded:
            self._auto_save_experience(method_succeeded)

    def _auto_save_experience(self, method_succeeded: str) -> None:
        """自动保存经验"""
        try:
            from core.experience_manager import save_experience
            save_experience(
                target=self._state.get("target", ""),
                challenge_type=self._state.get("type", ""),
                findings=self._state.get("findings", []),
                methods_tried=self._state.get("methods_tried", []),
                method_succeeded=method_succeeded,
                flag=self._state.get("flag", ""),
            )
        except Exception:
            pass  # 静默失败，不影响主流程

    def get_target(self) -> str:
        """获取当前目标"""
        return self._state.get("target", "")

    def get_type(self) -> str:
        """获取题型"""
        return self._state.get("type", "")

    def get_step(self) -> int:
        """获取当前步骤"""
        return self._state.get("step", 0)

    def get_findings(self) -> List[str]:
        """获取所有发现"""
        return self._state.get("findings", [])

    def get_methods_tried(self) -> List[str]:
        """获取已尝试的方法"""
        return self._state.get("methods_tried", [])

    def get_reasoning_chain(self) -> List[Dict[str, Any]]:
        """获取推理链"""
        return self._state.get("reasoning_chain", [])

    def get_failed_patterns(self) -> List[str]:
        """获取失败特征"""
        return self._state.get("failed_patterns", [])

    def get_suggested_bypass(self) -> List[Dict[str, str]]:
        """获取建议的 bypass"""
        return self._state.get("suggested_bypass", [])

    def get_flag(self) -> str:
        """获取 flag"""
        return self._state.get("flag", "")

    def is_active(self) -> bool:
        """检查是否有活跃状态"""
        return bool(self._state.get("target"))

    def clear(self) -> None:
        """清除状态"""
        self._state = {}
        if self.state_file.exists():
            self.state_file.unlink()

    def get_state(self) -> Dict[str, Any]:
        """获取完整状态"""
        return self._state.copy()

    def has_method(self, method: str) -> bool:
        """检查方法是否已尝试"""
        return method in self._state.get("methods_tried", [])

    def get_methods_count(self) -> int:
        """获取已尝试方法数量"""
        return len(self._state.get("methods_tried", []))

    def summary(self) -> str:
        """获取状态摘要（简略）"""
        if not self.is_active():
            return "No active challenge state."
        return (
            f"Target: {self.get_target()}\n"
            f"Type: {self.get_type()}\n"
            f"Step: {self.get_step()}\n"
            f"Findings: {len(self.get_findings())}\n"
            f"Methods tried: {len(self.get_methods_tried())}\n"
            f"Flag: {self.get_flag() or 'Not found'}"
        )

    def get_context_summary(self) -> str:
        """
        获取状态摘要（供 LLM 上下文使用，包含完整信息）

        Returns:
            格式化的状态摘要，包含推理链和建议
        """
        if not self.is_active():
            return "No active challenge state."

        lines = [
            "=== 解题状态摘要 ===",
            f"目标: {self.get_target()}",
            f"题型: {self.get_type()}",
            f"进度: Step {self.get_step()}",
            "",
        ]

        # 发现
        findings = self.get_findings()
        if findings:
            lines.append("【发现】")
            for f in findings:
                lines.append(f"  - {f}")
            lines.append("")

        # 已尝试方法
        methods = self.get_methods_tried()
        if methods:
            lines.append(f"【已尝试方法】({len(methods)}个)")
            for m in methods:
                lines.append(f"  - {m}")
            lines.append("")

        # 失败特征
        patterns = self.get_failed_patterns()
        if patterns:
            lines.append("【失败特征】")
            for p in patterns:
                lines.append(f"  - {p}")
            lines.append("")

        # 建议 bypass
        bypass = self.get_suggested_bypass()
        if bypass:
            lines.append("【建议尝试】")
            for b in bypass:
                reason = b.get("reason", "")
                if reason:
                    lines.append(f"  - {b['method']} ({reason})")
                else:
                    lines.append(f"  - {b['method']}")
            lines.append("")

        # 推理链
        reasoning = self.get_reasoning_chain()
        if reasoning:
            lines.append("【推理链】")
            for r in reasoning[-5:]:  # 只显示最近5条
                lines.append(f"  Step{r['step']}: {r['action']}")
                lines.append(f"    → {r['finding']}")
            lines.append("")

        # Flag
        flag = self.get_flag()
        if flag:
            lines.append(f"【FLAG】: {flag}")
        else:
            lines.append("【FLAG】: 未找到")

        return "\n".join(lines)


# 全局实例
_state_manager: Optional[StateManager] = None


def get_state_manager() -> StateManager:
    """获取 StateManager 单例"""
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager()
    return _state_manager


# 快捷函数
def init_state(target: str, challenge_type: str = "") -> None:
    """初始化状态"""
    get_state_manager().init(target, challenge_type)


def update_step(step: int) -> None:
    """更新步骤"""
    get_state_manager().update_step(step)


def add_finding(finding: str) -> None:
    """添加发现"""
    get_state_manager().add_finding(finding)


def add_method(method: str) -> None:
    """添加已尝试方法"""
    get_state_manager().add_method(method)


def add_reasoning(action: str, finding: str) -> None:
    """添加推理链记录"""
    get_state_manager().add_reasoning(action, finding)


def add_failed_pattern(pattern: str) -> None:
    """添加失败特征"""
    get_state_manager().add_failed_pattern(pattern)


def add_suggested_bypass(method: str, reason: str = "") -> None:
    """添加建议 bypass"""
    get_state_manager().add_suggested_bypass(method, reason)


def set_flag(flag: str, method_succeeded: str = None) -> None:
    """设置 flag（自动保存经验）"""
    get_state_manager().set_flag(flag, method_succeeded)


def save_experience_auto(method_succeeded: str) -> str:
    """
    自动保存当前解题经验（基于已有状态）

    Args:
        method_succeeded: 成功的方法名称

    Returns:
        保存的文件路径
    """
    from core.experience_manager import save_experience
    state = get_state_manager().get_state()

    return save_experience(
        target=state.get("target", ""),
        challenge_type=state.get("type", ""),
        findings=state.get("findings", []),
        methods_tried=state.get("methods_tried", []),
        method_succeeded=method_succeeded,
        flag=state.get("flag", ""),
    )


def get_state() -> Dict[str, Any]:
    """获取状态"""
    return get_state_manager().get_state()


def is_active() -> bool:
    """检查是否有活跃状态"""
    return get_state_manager().is_active()


def clear_state() -> None:
    """清除状态"""
    get_state_manager().clear()


def state_summary() -> str:
    """获取状态摘要"""
    return get_state_manager().summary()


def get_context_summary() -> str:
    """获取供 LLM 使用的完整状态摘要"""
    return get_state_manager().get_context_summary()
