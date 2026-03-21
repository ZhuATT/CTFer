import unittest
from contextlib import ExitStack
from unittest.mock import patch

from agent_core import AutoAgent, AgentNeedsHelpException
from orchestrator import CTFOrchestrator
from short_memory import ShortMemory


class ResumeFlowAgent(AutoAgent):
    def __init__(self):
        super().__init__(max_failures=1, max_steps=1, verbose=False, min_steps_before_help=1)
        self.memory = ShortMemory()
        self.agent_context = self.memory.get_context()
        self.init_result = {}
        self.target_url = ""
        self.target_type = "unknown"
        self.initialize_calls = 0
        self.planned_contexts = []

    def _sync_agent_context(self) -> None:
        self.agent_context = self.memory.get_context()

    def initialize_challenge(self, url: str = "", hint: str = "", description: str = "", source_code: str = ""):
        self.initialize_calls += 1
        self.target_url = url or "http://target.local"
        self.target_type = "sqli"
        self.init_result = {
            "target_url": self.target_url,
            "problem_type": self.target_type,
            "skill_content": "SQLi skill",
            "loaded_resources": {"skills": ["sqli"]},
        }
        self.memory.update_target(url=self.target_url, problem_type=self.target_type)
        self.memory.set_context(
            url=self.target_url,
            description=description,
            hint=hint,
            problem_type=self.target_type,
            skill_content="SQLi skill",
            loaded_resources={"skills": ["sqli"]},
        )
        self._sync_agent_context()
        return self.init_result

    def plan_next_action(self):
        self.planned_contexts.append(self.build_advisor_context())
        return {
            "id": f"action-{self.current_step_num}",
            "type": "attack_step",
            "target": self.target_url,
            "description": "resume test action",
            "intent": "resume test action",
            "expected_tool": "attack_step",
            "params": {},
        }

    def _execute_action(self, action):
        self.last_action = dict(action)
        if self.current_step_num == 1:
            self.memory.add_step(
                tool="attack_step",
                target=self.target_url,
                params={"action_id": action["id"]},
                result="blocked",
                success=False,
            )
            return "blocked"

        self.memory.add_step(
            tool="attack_step",
            target=self.target_url,
            params={"action_id": action["id"]},
            result="flag{resumed}",
            success=True,
        )
        return "flag{resumed}"

    def maybe_request_help(self, step_num: int):
        if step_num == 1 and getattr(self.agent_context, "resume_count", 0) == 0:
            self.last_help_reason = "unit_test_blocker"
            request = "need human guidance"
            self.memory.add_help_entry(
                request=request,
                reason=self.last_help_reason,
                step=step_num,
            )
            self._sync_agent_context()
            return request
        return None


class ResumeFlowTests(unittest.TestCase):
    def _patch_runtime(self, agent: ResumeFlowAgent) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(
            patch("agent_core.get_memory_summary", side_effect=agent.memory.get_summary)
        )
        stack.enter_context(
            patch(
                "agent_core.extract_flags",
                side_effect=lambda text: ["flag{resumed}"] if "flag{resumed}" in text else [],
            )
        )
        stack.enter_context(
            patch.object(ResumeFlowAgent, "_auto_save_experience", autospec=True, return_value=None)
        )
        stack.enter_context(
            patch("orchestrator.get_agent_context", side_effect=agent.memory.get_context)
        )
        stack.enter_context(
            patch("orchestrator.get_memory_summary", side_effect=agent.memory.get_summary)
        )
        return stack

    def test_short_memory_patch_summary(self):
        memory = ShortMemory()
        self.assertEqual(memory.get_patch_summary(), "暂无修补点")

        memory.add_patch(
            location="line 10",
            vuln_type="sqli",
            fix_suggestion="改用参数化查询",
            code_snippet="query = 'select * from users where id=' + user_id",
        )

        summary = memory.get_patch_summary()
        self.assertIn("修补点: 1 处", summary)
        self.assertIn("[sqli] line 10", summary)
        self.assertIn("改用参数化查询", summary)

    def test_autoagent_resume_uses_guidance_and_continues_steps(self):
        agent = ResumeFlowAgent()
        agent.initialize_challenge(url="http://target.local", hint="hint", description="desc")

        with self._patch_runtime(agent):
            with self.assertRaises(AgentNeedsHelpException):
                agent.run_main_loop()

            result = agent.resume_with_guidance("check cookies")

        self.assertTrue(result["success"])
        self.assertEqual(result["flag"], "flag{resumed}")
        self.assertEqual(result["steps"], 2)
        self.assertEqual(agent.current_step_num, 2)
        self.assertEqual(len(agent.memory.steps), 2)
        self.assertEqual(agent.memory.steps[0].num, 1)
        self.assertEqual(agent.memory.steps[1].num, 2)
        self.assertEqual(agent.memory.get_context().human_guidance, "check cookies")
        self.assertEqual(agent.memory.get_context().resume_count, 1)
        self.assertEqual(agent.planned_contexts[-1]["human_guidance"], "check cookies")
        self.assertEqual(agent.planned_contexts[-1]["resume_count"], 1)
        self.assertEqual(agent.planned_contexts[-1]["help_history"][-1]["guidance"], "check cookies")

    def test_orchestrator_resume_reuses_same_agent(self):
        agent = ResumeFlowAgent()
        orchestrator = CTFOrchestrator(agent=agent)

        with self._patch_runtime(agent):
            orchestrator.initialize_challenge(url="http://target.local", hint="hint", description="desc")
            first_result = orchestrator.run()
            resumed_result = orchestrator.resume("try cookies")

        self.assertFalse(first_result["success"])
        self.assertTrue(first_result["needs_help"])
        self.assertEqual(agent.initialize_calls, 1)
        self.assertEqual(orchestrator.state.status, "succeeded")
        self.assertTrue(resumed_result["success"])
        self.assertEqual(resumed_result["flag"], "flag{resumed}")
        self.assertEqual(resumed_result["steps"], 2)
        self.assertEqual(orchestrator.state.help_request["reason"], "unit_test_blocker")
        self.assertEqual(orchestrator.state.help_request["guidance"], "try cookies")
        self.assertEqual(orchestrator.state.resume_count, 1)
        self.assertEqual(orchestrator.state.paused_action, {})
        self.assertEqual(orchestrator.state.pending_flag, "flag{resumed}")
        self.assertEqual(orchestrator.state.help_history[-1]["guidance"], "try cookies")
        stages = [event["stage"] for event in orchestrator.state.route_trace]
        self.assertIn("help", stages)
        self.assertIn("resume", stages)


if __name__ == "__main__":
    unittest.main()
