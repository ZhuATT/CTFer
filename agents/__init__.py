"""Agent 基础框架
============
多智能体系统的核心基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime


@dataclass
class AgentResult:
    """Agent执行结果"""
    agent_id: str
    agent_type: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp
        }


class BaseAgent(ABC):
    """Agent基类 - 所有Agent继承此类"""

    def __init__(self, agent_id: str = None):
        self.agent_id = agent_id or self._generate_id()
        self.agent_type = self.__class__.__name__
        self.start_time = None
        self.end_time = None

    def _generate_id(self) -> str:
        import uuid
        return f"{self.__class__.__name__.lower()}_{uuid.uuid4().hex[:8]}"

    @abstractmethod
    async def execute(self, target: str, **kwargs) -> AgentResult:
        """Agent主要执行逻辑"""
        pass

    def _calculate_duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    async def run(self, target: str, **kwargs) -> AgentResult:
        """运行Agent（包装执行）"""
        self.start_time = datetime.now()
        try:
            result = await self.execute(target, **kwargs)
            self.end_time = datetime.now()
            result.duration = self._calculate_duration()
            return result
        except Exception as e:
            self.end_time = datetime.now()
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                error=str(e),
                duration=self._calculate_duration()
            )


class ReconAgent(BaseAgent):
    """侦察Agent基类"""
    def __init__(self, agent_id: str = None):
        super().__init__(agent_id)
        self.category = "recon"


def format_recon_results(results: List[AgentResult]) -> str:
    """格式化侦察结果为可读摘要"""
    if not results:
        return "No recon results"

    lines = ["=== Parallel Recon Complete ===\n"]

    for result in results:
        status = "OK" if result.success else "FAIL"
        lines.append(f"[{status}] {result.agent_type} ({result.duration:.1f}s)")

        if result.success and result.data:
            findings = result.data.get('findings', [])
            for finding in findings[:5]:
                lines.append(f"  -> {finding}")

        if result.error:
            lines.append(f"  Error: {result.error}")

    return "\n".join(lines)


def merge_recon_data(results: List[AgentResult]) -> Dict[str, Any]:
    """合并多个侦察Agent的结果"""
    merged = {
        "agents_executed": [],
        "success_count": 0,
        "fail_count": 0,
        "total_duration": 0.0,
        "findings": {},
        "all_data": {}
    }

    for result in results:
        merged["agents_executed"].append(result.agent_type)
        merged["total_duration"] += result.duration

        if result.success:
            merged["success_count"] += 1
            merged["all_data"][result.agent_type] = result.data
            if result.data.get('findings'):
                merged["findings"][result.agent_type] = result.data['findings']
        else:
            merged["fail_count"] += 1

    return merged
