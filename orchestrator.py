# -*- coding: utf-8 -*-
"""
项目级 orchestrator 主入口。

职责：
- 统一接入 AutoAgent.initialize_challenge()
- 复用 AutoAgent.run_main_loop() 作为唯一主循环
- 暴露结构化 state，供 CLI / 后续 HITL / graph manager 扩展
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_core import AutoAgent, AgentNeedsHelpException
from tools import get_agent_context, get_memory_summary


@dataclass
class RouteEvent:
    """单次编排事件。"""

    stage: str
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestratorState:
    """项目级运行状态。"""

    target_url: str = ""
    description: str = ""
    hint: str = ""
    source_code_path: str = ""
    init_result: Dict[str, Any] = field(default_factory=dict)
    agent_context: Dict[str, Any] = field(default_factory=dict)
    status: str = "created"
    current_step_num: int = 0
    last_action: Dict[str, Any] = field(default_factory=dict)
    last_result: str = ""
    memory_summary: str = ""
    final_result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)
    pending_task: Dict[str, Any] = field(default_factory=dict)
    pending_flag: str = ""
    consecutive_failures: int = 0
    route_trace: List[Dict[str, Any]] = field(default_factory=list)
    advisor_context: Dict[str, Any] = field(default_factory=dict)
    planner_output: Dict[str, Any] = field(default_factory=dict)
    executor_output: Dict[str, Any] = field(default_factory=dict)
    tool_node_state: Dict[str, Any] = field(default_factory=dict)
    help_request: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CTFOrchestrator:
    """薄封装 orchestrator，统一初始化与主循环入口。"""

    def __init__(self, agent: Optional[AutoAgent] = None, **agent_kwargs: Any):
        self.agent = agent or AutoAgent(**agent_kwargs)
        self.state = OrchestratorState()

    def _append_message(self, stage: str, payload: Dict[str, Any]) -> None:
        message = {
            "stage": stage,
            "step": payload.get("step", self.agent.current_step_num),
        }

        if stage == "advisor":
            message["content"] = f"Advisor loaded context for {payload.get('context', {}).get('target_type', 'unknown')}"
        elif stage == "planner":
            action = payload.get("action", {})
            message["content"] = f"Planner selected action {action.get('type', 'unknown')}"
        elif stage == "executor":
            action = payload.get("action", {})
            message["content"] = f"Executor prepared {action.get('type', 'unknown')}"
        elif stage == "tool_node":
            action = payload.get("action", {})
            outcome = "success" if payload.get("success") else "failure"
            message["content"] = f"ToolNode executed {action.get('type', 'unknown')} with {outcome}"
        elif stage == "help":
            message["content"] = payload.get("message", "")
        else:
            message["content"] = json.dumps(payload, ensure_ascii=False)

        self.state.messages.append(message)
        self.state.messages = self.state.messages[-20:]

    def _record_route_event(self, stage: str, payload: Dict[str, Any]) -> None:
        event = RouteEvent(stage=stage, payload=payload)
        self.state.route_trace.append(asdict(event))
        self.state.route_trace = self.state.route_trace[-50:]
        self._append_message(stage, payload)

        if stage == "advisor":
            self.state.advisor_context = dict(payload.get("context", {}))
        elif stage == "planner":
            self.state.planner_output = dict(payload.get("action", {}))
            self.state.pending_task = dict(payload.get("action", {}))
        elif stage == "executor":
            self.state.executor_output = dict(payload.get("action", {}))
        elif stage == "tool_node":
            self.state.tool_node_state = {
                "action": dict(payload.get("action", {})),
                "result": payload.get("result", ""),
                "success": payload.get("success", False),
            }
        elif stage == "help":
            self.state.help_request = {
                "step": payload.get("step", self.agent.current_step_num),
                "message": payload.get("message", ""),
            }

    def _handle_agent_event(self, stage: str, payload: Dict[str, Any]) -> None:
        self._record_route_event(stage, payload)
        self._sync_state()

    def _sync_state(self) -> None:
        self.state.init_result = dict(self.agent.init_result or {})
        self.state.agent_context = asdict(get_agent_context())
        self.state.current_step_num = self.agent.current_step_num
        self.state.last_action = dict(self.agent.last_action or {})
        self.state.last_result = self.agent.last_result
        self.state.memory_summary = get_memory_summary()
        self.state.consecutive_failures = self.agent._get_consecutive_failures()

        if self.state.last_action:
            self.state.pending_task = dict(self.state.last_action)

        if self.state.final_result.get("success"):
            self.state.pending_flag = self.state.final_result.get("flag", "")

    def initialize_challenge(
        self,
        url: str = "",
        hint: str = "",
        description: str = "",
        source_code: str = "",
        source_code_path: str = "",
    ) -> Dict[str, Any]:
        """统一初始化入口，接收 init_problem 返回值并同步 state。"""
        self.state.status = "initializing"
        self.state.target_url = url
        self.state.description = description
        self.state.hint = hint
        self.state.source_code_path = source_code_path

        init_result = self.agent.initialize_challenge(
            url=url,
            hint=hint,
            description=description,
            source_code=source_code,
        )

        self.state.target_url = init_result.get("target_url", url)
        self.state.status = "initialized"
        self._record_route_event(
            "advisor",
            {
                "step": 0,
                "context": self.agent.build_advisor_context(),
            },
        )
        self._sync_state()
        return self.state.to_dict()

    def run(self) -> Dict[str, Any]:
        """运行唯一主循环，并将结果回写到结构化 state。"""
        if not self.agent.init_result:
            raise ValueError("Challenge not initialized. Call initialize_challenge() first.")

        self.state.status = "running"
        self._sync_state()

        try:
            result = self.agent.run_main_loop(event_callback=self._handle_agent_event)
            self.state.status = "succeeded"
            self.state.error = ""
            self.state.final_result = result
        except AgentNeedsHelpException as exc:
            self.state.status = "needs_help"
            self.state.error = exc.message
            self.state.final_result = {
                "success": False,
                "needs_help": True,
                "message": exc.message,
                "steps": self.agent.current_step_num,
            }
        except Exception as exc:
            self.state.status = "failed"
            self.state.error = str(exc)
            self.state.final_result = {
                "success": False,
                "needs_help": False,
                "message": str(exc),
                "steps": self.agent.current_step_num,
            }

        self._sync_state()
        return self.state.final_result

    def solve(
        self,
        url: str = "",
        hint: str = "",
        description: str = "",
        source_code: str = "",
        source_code_path: str = "",
    ) -> Dict[str, Any]:
        """项目级统一求解入口。"""
        self.initialize_challenge(
            url=url,
            hint=hint,
            description=description,
            source_code=source_code,
            source_code_path=source_code_path,
        )
        result = self.run()
        return {
            **result,
            "orchestrator_state": self.state.to_dict(),
        }

    def get_state(self) -> Dict[str, Any]:
        """获取当前结构化状态。"""
        self._sync_state()
        return self.state.to_dict()


def orchestrate_challenge(
    url: str = "",
    hint: str = "",
    description: str = "",
    source_code: str = "",
    **agent_kwargs: Any,
) -> Dict[str, Any]:
    """便捷函数：项目级统一入口。"""
    orchestrator = CTFOrchestrator(**agent_kwargs)
    return orchestrator.solve(
        url=url,
        hint=hint,
        description=description,
        source_code=source_code,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CTF Agent 项目级 orchestrator 入口")
    parser.add_argument("--url", default="", help="目标 URL")
    parser.add_argument("--hint", default="", help="题目提示")
    parser.add_argument("--description", default="", help="题目描述")
    parser.add_argument("--source-code-file", default="", help="源码文件路径")
    parser.add_argument("--max-steps", type=int, default=20, help="最大步数")
    parser.add_argument("--max-failures", type=int, default=3, help="同类方法最大失败次数")
    parser.add_argument("--min-steps-before-help", type=int, default=None, help="最少尝试步数后才允许求助")
    parser.add_argument("--quiet", action="store_true", help="减少日志输出")
    parser.add_argument("--json", action="store_true", help="输出 JSON 结果")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    source_code = ""
    if args.source_code_file:
        source_path = Path(args.source_code_file)
        source_code = source_path.read_text(encoding="utf-8")

    if not any([args.url, args.hint, args.description, source_code]):
        parser.error("至少提供 --url、--hint、--description、--source-code-file 之一")

    result = orchestrate_challenge(
        url=args.url,
        hint=args.hint,
        description=args.description,
        source_code=source_code,
        max_steps=args.max_steps,
        max_failures=args.max_failures,
        min_steps_before_help=args.min_steps_before_help,
        verbose=not args.quiet,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if result.get("success"):
            print(f"[SUCCESS] Flag: {result.get('flag', '')}")
            print(f"[SUCCESS] Steps: {result.get('steps', 0)}")
        else:
            print(f"[RESULT] {result.get('message', 'Unknown result')}")
            state = result.get("orchestrator_state", {})
            summary = state.get("memory_summary")
            if summary:
                print(summary)

    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
