"""
Task/TaskPlan dataclass - 参考 H-Pentest 的规划数据结构
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Task:
    """单一任务单元"""
    task_id: str
    description: str
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[str] = None
    error: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def mark_completed(self, result: str):
        self.status = "completed"
        self.result = result

    def mark_failed(self, error: str):
        self.status = "failed"
        self.error = error


@dataclass
class TaskPlan:
    """任务计划，包含多个 Task"""
    plan_id: str
    tasks: List[Task] = field(default_factory=list)
    current_task_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: Task):
        self.tasks.append(task)

    def get_task(self, task_id: str) -> Optional[Task]:
        for task in self.tasks:
            if task.task_id == task_id:
                return task
        return None

    def get_next_task(self) -> Optional[Task]:
        for task in self.tasks:
            if task.status == "pending" and all(
                self.get_task(dep).status == "completed"
                for dep in task.depends_on
            ):
                return task
        return None

    def is_complete(self) -> bool:
        return all(task.status in ("completed", "failed") for task in self.tasks)
