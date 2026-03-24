import unittest

import agent_core
from agent_core import AutoAgent
from tools import reset_memory


class RagBeforeHelpRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()
        self.rag_calls = []
        self.original_retrieve_rag_knowledge = agent_core.retrieve_rag_knowledge

        def fake_retrieve_rag_knowledge(**kwargs):
            self.rag_calls.append(dict(kwargs))
            return {
                "retrieved_knowledge": [
                    {
                        "type": "technique",
                        "content": "Try alternate payload families for the current target.",
                    }
                ],
                "suggested_approach": "Switch payload family and verify known parameters first.",
            }

        agent_core.retrieve_rag_knowledge = fake_retrieve_rag_knowledge

    def tearDown(self):
        agent_core.retrieve_rag_knowledge = self.original_retrieve_rag_knowledge
        reset_memory()

    def _make_agent(self) -> AutoAgent:
        agent = AutoAgent(max_failures=4, max_steps=20, verbose=False, min_steps_before_help=1)
        agent.target_url = "http://target.test"
        agent.target_type = "sqli"
        agent.init_result = {"problem_type": "sqli", "loaded_resources": {}}
        agent.memory.set_context(hint="use GET parameter", description="demo")
        agent._sync_agent_context()
        return agent

    def _add_same_error_failures(self, agent: AutoAgent, count: int) -> None:
        for idx in range(count):
            action_id = f"action-{idx + 1}"
            action_type = f"attack-{idx + 1}"
            tool = f"tool{idx + 1}"
            agent.last_action = {
                "id": action_id,
                "type": action_type,
                "description": f"Attempt {idx + 1}",
                "expected_tool": tool,
                "params": {"attempt": idx + 1},
            }
            agent.memory.add_step(
                tool=tool,
                target="http://target.test/item.php?id=1",
                params={"attempt": idx + 1},
                result="blocked by filter",
                success=False,
                action_meta={
                    "action_id": action_id,
                    "action_type": action_type,
                    "expected_tool": tool,
                    "canonical_tool": tool,
                },
            )

    def test_first_help_threshold_runs_rag_then_second_hit_requests_help(self):
        agent = self._make_agent()

        self._add_same_error_failures(agent, 2)
        self.assertIsNone(agent.maybe_request_help(step_num=3))
        self.assertEqual(len(self.rag_calls), 0)
        self.assertFalse(agent.memory.get_context().rag_attempted_in_current_window)
        self.assertEqual(len(agent.memory.get_context().help_history), 0)

        self._add_same_error_failures(agent, 1)
        self.assertIsNone(agent.maybe_request_help(step_num=4))

        context_after_rag = agent.memory.get_context()
        advisor_context = agent.build_advisor_context()
        self.assertEqual(len(self.rag_calls), 1)
        self.assertTrue(context_after_rag.rag_attempted_in_current_window)
        self.assertEqual(context_after_rag.rag_attempt_step, 4)
        self.assertIn("最近受阻动作", context_after_rag.rag_query)
        self.assertIn("technique", context_after_rag.rag_summary)
        self.assertEqual(
            context_after_rag.rag_suggested_approach,
            "Switch payload family and verify known parameters first.",
        )
        self.assertEqual(advisor_context["latest_rag_query"], context_after_rag.rag_query)
        self.assertEqual(advisor_context["latest_rag_summary"], context_after_rag.rag_summary)
        self.assertTrue(advisor_context["rag_attempted_in_current_window"])
        self.assertEqual(len(context_after_rag.help_history), 0)

        help_request = agent.maybe_request_help(step_num=5)
        context_after_help = agent.memory.get_context()
        self.assertIsInstance(help_request, str)
        self.assertIn("需要人工介入", help_request)
        self.assertEqual(len(self.rag_calls), 1)
        self.assertEqual(len(context_after_help.help_history), 1)
        self.assertIn("当前摘要", context_after_help.help_history[-1]["request"])

    def test_resume_resets_rag_gate_state(self):
        agent = self._make_agent()
        self._add_same_error_failures(agent, 3)

        self.assertIsNone(agent.maybe_request_help(step_num=4))
        self.assertTrue(agent.memory.get_context().rag_attempted_in_current_window)

        agent.current_step_num = 5
        agent.run_main_loop = lambda event_callback=None, resume=False: {
            "resume": resume,
            "resume_count": agent.agent_context.resume_count,
            "rag_attempted": agent.agent_context.rag_attempted_in_current_window,
            "rag_query": agent.agent_context.rag_query,
            "help_cooldown": agent.help_cooldown_remaining,
        }

        result = agent.resume_with_guidance("Check WAF bypass")
        context_after_resume = agent.memory.get_context()

        self.assertTrue(result["resume"])
        self.assertEqual(result["resume_count"], 1)
        self.assertFalse(result["rag_attempted"])
        self.assertEqual(result["rag_query"], "")
        self.assertEqual(result["help_cooldown"], 2)
        self.assertEqual(context_after_resume.resume_count, 1)
        self.assertFalse(context_after_resume.rag_attempted_in_current_window)
        self.assertEqual(context_after_resume.rag_query, "")
        self.assertEqual(context_after_resume.help_history[-1]["guidance"], "Check WAF bypass")


if __name__ == "__main__":
    unittest.main()
