"""侦察协调器
===========
管理多个侦察Agent的并行执行
"""

import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path
import sys

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents import (
    AgentResult, ReconAgent,
    format_recon_results, merge_recon_data
)

# 导入侦察Agent
from agents.recon.web_fingerprint import WebFingerprintAgent
from agents.recon.dir_brute import DirBruteAgent


class ReconCoordinator:
    """侦察协调器

    管理多个侦察Agent的并行执行，整合结果
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.agents: Dict[str, ReconAgent] = {}
        self._register_default_agents()

    def _register_default_agents(self):
        """注册默认侦察Agent"""
        self.agents['fingerprint'] = WebFingerprintAgent()
        self.agents['dir_brute'] = DirBruteAgent()

    def register_agent(self, name: str, agent: ReconAgent):
        """注册自定义Agent"""
        self.agents[name] = agent

    async def run_all(self, target: str, agent_names: List[str] = None) -> Dict[str, Any]:
        """并行运行所有侦察Agent

        Args:
            target: 目标URL
            agent_names: 指定要运行的Agent，None表示全部

        Returns:
            包含所有Agent结果的字典
        """
        if agent_names is None:
            agent_names = list(self.agents.keys())

        tasks = []
        agent_list = []

        for name in agent_names:
            if name in self.agents:
                agent = self.agents[name]
                # 创建任务，带超时
                task = asyncio.create_task(
                    asyncio.wait_for(
                        agent.run(target),
                        timeout=self.timeout
                    )
                )
                tasks.append(task)
                agent_list.append(name)

        if not tasks:
            return {
                "success": False,
                "error": "No valid agents to run",
                "results": [],
                "summary": "No agents executed"
            }

        print(f"[Recon] Starting {len(tasks)} agents: {agent_list}")

        # 并行执行，捕获结果和异常
        results = []
        completed_tasks = await asyncio.gather(*tasks, return_exceptions=True)

        ag_idx = 0
        for result in completed_tasks:
            agent_name = agent_list[ag_idx] if ag_idx < len(agent_list) else f"agent_{ag_idx}"
            ag_idx += 1

            if isinstance(result, asyncio.TimeoutError):
                print(f"[Recon] {agent_name} timed out after {self.timeout}s")
                results.append(AgentResult(
                    agent_id=f"{agent_name}_timeout",
                    agent_type=agent_name,
                    success=False,
                    error=f"Timeout after {self.timeout}s"
                ))
            elif isinstance(result, Exception):
                print(f"[Recon] {agent_name} error: {result}")
                results.append(AgentResult(
                    agent_id=f"{agent_name}_error",
                    agent_type=agent_name,
                    success=False,
                    error=str(result)
                ))
            else:
                results.append(result)
                status = "OK" if result.success else "FAIL"
                print(f"[Recon] [{status}] {agent_name} completed in {result.duration:.1f}s")

        # 合并结果
        merged = merge_recon_data(results)
        summary = format_recon_results(results)

        return {
            "success": merged["fail_count"] == 0 or merged["success_count"] > 0,
            "results": results,
            "merged_data": merged,
            "summary": summary,
            "findings": merged.get("findings", {})
        }

    async def run_parallel(self, target: str) -> str:
        """简化接口：运行所有Agent并返回摘要字符串"""
        result = await self.run_all(target)
        return result["summary"]


def run_recon_sync(target: str, timeout: int = 60) -> Dict[str, Any]:
    """同步接口：运行侦察并返回结果

    方便从非async上下文调用
    """
    coordinator = ReconCoordinator(timeout=timeout)

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    result = loop.run_until_complete(coordinator.run_all(target))
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "http://httpbin.org"

    print(f"Testing recon coordinator on: {target}\n")

    result = run_recon_sync(target, timeout=30)
    print("\n" + "=" * 50)
    print("SUMMARY:")
    print(result["summary"])
