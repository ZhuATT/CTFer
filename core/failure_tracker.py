"""
失败模式记录 - 直接模式组件
在 workspace/ 中记录已失败的尝试，避免重复劳动
"""
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime


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


# 失败阈值常量
FAILURE_THRESHOLD = 3


def should_trigger_rag(target: str) -> bool:
    """
    判断是否应该触发 RAG 检索

    当失败方法数量达到阈值时返回 True

    Args:
        target: 目标 URL

    Returns:
        True 如果应该触发 RAG
    """
    failures = get_failed_methods(target)
    return len(failures) >= FAILURE_THRESHOLD


def get_failure_count(target: str) -> int:
    """获取失败方法数量"""
    return len(get_failed_methods(target))
