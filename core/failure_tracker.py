"""
失败模式记录 - 直接模式组件
在 workspace/ 中记录已失败的尝试，避免重复劳动

Phase 2 增强：LLM 失败分析
- 失败原因归类（防御类型/过滤类型/路径类型）
- bypass 建议
- 替代方法推荐
"""
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

# 编码修复
from skills.encoding_fix import safe_print


class FailureTracker:
    """失败记录追踪器"""

    def __init__(self, workspace_dir: Optional[str] = None):
        if workspace_dir is None:
            project_root = Path(__file__).parent.parent
            workspace_dir = str(project_root / "workspace")
        self.workspace = Path(workspace_dir)
        self.failure_file = self.workspace / "failures.json"
        self._ensure_file()

    def _ensure_file(self):
        """确保失败记录文件存在"""
        if not self.failure_file.exists():
            self.failure_file.write_text("[]", encoding="utf-8")

    def _load(self) -> List[Dict[str, Any]]:
        """加载失败记录"""
        try:
            return json.loads(self.failure_file.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save(self, records: List[Dict[str, Any]]):
        """保存失败记录"""
        self.failure_file.write_text(
            json.dumps(records, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def record(
        self,
        target: str,
        method: str,
        reason: str,
        payload: str = "",
        category: str = "",
    ):
        """
        记录一次失败尝试

        Args:
            target: 目标 URL
            method: 尝试的方法（如 "file_get_contents", "copy"）
            reason: 失败原因（如 "no output", "file not found"）
            payload: 使用的 payload
            category: 题型（rce/sqli/lfi 等）
        """
        records = self._load()

        # 检查是否已记录相同的 target + method
        for record in records:
            if record["target"] == target and record["method"] == method:
                # 更新记录
                record["reason"] = reason
                record["payload"] = payload
                record["updated_at"] = datetime.now().isoformat()
                self._save(records)
                return

        # 新增记录
        records.append({
            "target": target,
            "method": method,
            "reason": reason,
            "payload": payload,
            "category": category,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        })
        self._save(records)

        # LLM 失败分析（异步，不阻塞主流程）
        self._async_analyze_failure(target, method, reason, payload, category)

    def _async_analyze_failure(
        self,
        target: str,
        method: str,
        reason: str,
        payload: str,
        category: str,
    ) -> None:
        """
        异步调用 LLM 分析失败原因（不阻塞主流程）

        将分析结果更新到记录中
        """
        try:
            analysis = analyze_failure_with_llm(method, reason, payload, category, target)
            if not analysis:
                return

            # 更新记录，添加分析结果
            records = self._load()
            for record in records:
                if record["target"] == target and record["method"] == method:
                    record["analysis"] = analysis
                    record["updated_at"] = datetime.now().isoformat()
                    self._save(records)
                    break
        except Exception as e:
            # 分析失败不影响主流程
            safe_print(f"[失败分析 LLM 调用失败] {e}")

    def is_failed(self, target: str, method: str) -> bool:
        """检查某个方法是否已失败过"""
        records = self._load()
        for record in records:
            if record["target"] == target and record["method"] == method:
                return True
        return False

    def get_failures(self, target: str) -> List[Dict[str, Any]]:
        """获取目标的所有失败记录"""
        records = self._load()
        return [r for r in records if r["target"] == target]

    def clear(self, target: Optional[str] = None):
        """
        清除失败记录

        Args:
            target: 可选，只清除指定目标的记录
        """
        if target is None:
            # 清除所有
            self._save([])
        else:
            # 只清除指定目标
            records = self._load()
            records = [r for r in records if r["target"] != target]
            self._save(records)


# 全局实例
_tracker: Optional[FailureTracker] = None


def get_tracker() -> FailureTracker:
    """获取失败追踪器实例（单例）"""
    global _tracker
    if _tracker is None:
        _tracker = FailureTracker()
    return _tracker


def record_failure(
    target: str,
    method: str,
    reason: str,
    payload: str = "",
    category: str = "",
):
    """快捷函数：记录一次失败"""
    get_tracker().record(target, method, reason, payload, category)


def is_method_failed(target: str, method: str) -> bool:
    """快捷函数：检查方法是否已失败"""
    return get_tracker().is_failed(target, method)


def get_failed_methods(target: str) -> List[str]:
    """快捷函数：获取目标已失败的方法列表"""
    return [r["method"] for r in get_tracker().get_failures(target)]


def get_failures_list(target: str, max_rows: int = 10) -> str:
    """
    格式化失败记录为易读字符串，供 Hook 注入上下文

    Returns:
        多行字符串，每行: "- method: reason"
    """
    failures = get_tracker().get_failures(target)
    if not failures:
        return "  （暂无失败记录）"

    lines = []
    for f in failures[-max_rows:]:
        method = f.get("method", "未知")
        reason = f.get("reason", "")
        payload = f.get("payload", "")
        snippet = f"  - {method}: {reason}"
        if payload:
            snippet += f" (payload: {payload[:50]})"

        # 添加 LLM 分析结果
        analysis = f.get("analysis")
        if analysis:
            bypass = analysis.get("bypass_suggestion", "")
            if bypass:
                snippet += f"\n    → 建议: {bypass}"
            alts = analysis.get("alternative_methods", [])
            if alts:
                snippet += f"\n    → 替代: {', '.join(alts[:3])}"

        lines.append(snippet)
    return "\n".join(lines)


# 失败阈值常量
FAILURE_THRESHOLD = 3


def _get_target_category(target: str) -> str:
    """从 failures.json 推断目标题型"""
    failures = get_tracker().get_failures(target)
    if not failures:
        return "unknown"
    return failures[-1].get("category", "unknown")


def _build_forced_rerag_message(target: str, count: int) -> str:
    """构建强制重查知识的指令消息"""
    failures_list = get_failures_list(target)
    category = _get_target_category(target)

    return f"""
╔══════════════════════════════════════════════════════════════════════╗
║  ⚠️  强制重查知识 — 失败次数已达到 {count} 次                              ║
║                                                                      ║
║  你必须立即执行以下操作：                                               ║
║                                                                      ║
║  1. 停止当前攻击方向（不要再尝试类似的方法）                              ║
║  2. 调用以下命令重新获取知识：                                          ║
║     get_all_type_knowledge('{category}')                                ║
║  3. 基于新知识制定全新的攻击计划                                        ║
║  4. 查看 memories/experiences/ 中的历史成功经验                        ║
║                                                                      ║
║  失败记录（来自 failures.json）：                                        ║
{failures_list}                                                            ║
║                                                                      ║
║  ⚠️  禁止重复已失败的方法！继续相同方向将浪费时间！                     ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def should_trigger_rag(target: str) -> Tuple[bool, str, int]:
    """
    判断是否应该触发 RAG 检索，并返回格式化消息

    Returns:
        (should_trigger, message, failure_count)
    """
    failures = get_failed_methods(target)
    count = len(failures)

    if count >= FAILURE_THRESHOLD:
        msg = _build_forced_rerag_message(target, count)
        return True, msg, count

    return False, "", count


def get_failure_count(target: str) -> int:
    """获取失败方法数量"""
    return len(get_failed_methods(target))


# ============ LLM 失败分析 ============


def _format_failures_for_llm(failures: List[Dict[str, Any]], limit: int = 10) -> str:
    """格式化失败记录供 LLM 分析"""
    if not failures:
        return "  （暂无失败记录）"

    lines = []
    for i, f in enumerate(failures[-limit:], 1):
        method = f.get("method", "未知")
        reason = f.get("reason", "")
        payload = f.get("payload", "")
        lines.append(f"{i}. 方法: {method}")
        if reason:
            lines.append(f"   原因: {reason}")
        if payload:
            # 截断过长的 payload
            display_payload = payload[:100] + "..." if len(payload) > 100 else payload
            lines.append(f"   Payload: {display_payload}")

    return "\n".join(lines)


def analyze_failure_with_llm(
    method: str,
    reason: str,
    payload: str = "",
    category: str = "",
    target: str = "",
) -> Optional[Dict[str, Any]]:
    """
    使用 LLM 分析失败原因，给出 bypass 建议和换方向建议

    Phase 3 改造：调用 advisor.analyze_failure() 替代原有 LLM 调用

    Args:
        method: 失败的方法名（如 "system", "copy"）
        reason: 失败原因（如 "disabled by disable_functions"）
        payload: 使用的 payload
        category: 题型（rce/sqli/lfi 等）
        target: 目标 URL（用于获取同目标全部失败记录）

    Returns:
        分析结果字典，包含：
        - reason_type: 失败类型（defense/filter/path/waf/auth）
        - reason_type_detail: 详细分类
        - bypass_suggestion: 建议的 bypass 方法
        - alternative_methods: 替代方法列表
        - should_pivot: 是否应该换方向
        - pivot_reason: 换方向或不换方向的原因
        - next_method: 建议尝试的下一个方法
        - alternative_vector: 完全不同的攻击向量（如果不建议继续）
        如果 LLM 未配置或调用失败，返回 None
    """
    from core.advisor import analyze_failure

    try:
        result = analyze_failure(method, reason, payload, category, target)
        if result and result.get("reason_type") != "unknown":
            return result
        return None
    except RuntimeError as e:
        safe_print(f"[LLM 未配置] {e}")
        return None
    except Exception as e:
        safe_print(f"[失败分析调用失败] {type(e).__name__}: {e}")
        return None
