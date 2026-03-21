import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_core import AutoAgent, AgentNeedsHelpException
from short_memory import ShortMemory


def build_action_meta(
    action_id: str,
    action_type: str = "recon",
    expected_tool: str = "python_poc",
    canonical_tool: str = "python_poc",
):
    return {
        "action_id": action_id,
        "action_type": action_type,
        "expected_tool": expected_tool,
        "canonical_tool": canonical_tool,
    }


class ShortMemoryActionFailureTests(unittest.TestCase):
    def test_short_memory_aggregates_failures_by_action_id(self):
        memory = ShortMemory()

        first = memory.add_step(
            tool="python_poc",
            target="http://target.local",
            params={"variant": "a"},
            result="blocked-a",
            success=False,
            action_meta=build_action_meta("action-1"),
        )
        second = memory.add_step(
            tool="python_poc",
            target="http://target.local",
            params={"variant": "b"},
            result="blocked-b",
            success=False,
            action_meta=build_action_meta("action-1"),
        )

        self.assertEqual(memory.fail_count("python_poc", "http://target.local", {"variant": "a"}), 1)
        self.assertEqual(memory.fail_count("python_poc", "http://target.local", {"variant": "b"}), 1)
        self.assertEqual(memory.action_fail_count("action-1"), 2)
        self.assertEqual(memory.fail_count_for_step(first), 2)
        self.assertEqual(memory.fail_count_for_step(second), 2)
        self.assertTrue(memory.should_skip_action("action-1", max_failures=2))

    def test_legacy_signature_failure_tracking_still_works_without_action_meta(self):
        memory = ShortMemory()

        memory.add_step(
            tool="sqlmap",
            target="http://target.local?id=1",
            params={"batch": True},
            result="run-1",
            success=False,
        )
        memory.add_step(
            tool="sqlmap",
            target="http://target.local?id=1",
            params={"batch": True},
            result="run-2",
            success=False,
        )

        self.assertTrue(memory.has_tried("sqlmap", "http://target.local?id=1", {"batch": True}))
        self.assertEqual(memory.fail_count("sqlmap", "http://target.local?id=1", {"batch": True}), 2)
        self.assertTrue(memory.should_skip("sqlmap", "http://target.local?id=1", {"batch": True}, max_failures=2))
        self.assertEqual(memory.action_fail_count("missing-action"), 0)


class AutoAgentActionFailureTests(unittest.TestCase):
    def make_agent(self, max_failures: int = 3, max_steps: int = 20) -> AutoAgent:
        agent = AutoAgent(
            max_failures=max_failures,
            max_steps=max_steps,
            verbose=False,
            min_steps_before_help=1,
        )
        agent.memory = ShortMemory()
        agent.agent_context = agent.memory.get_context()
        agent.target_url = "http://target.local?id=1"
        agent.target_type = "unknown"
        return agent

    def test_execute_sqlmap_action_logs_action_metadata_without_leaking_kwargs(self):
        agent = self.make_agent()
        action = agent._build_action(
            "sqlmap_scan",
            target=agent.target_url,
            description="detect injection",
            intent="validate sql injection",
            expected_tool="sqlmap",
            params={"batch": True, "level": 2},
        )
        captured = {}

        def fake_sqlmap_scan(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = dict(kwargs)
            return SimpleNamespace(success=False, stdout="no injection found", stderr="request blocked")

        with patch("tools.get_memory", return_value=agent.memory), patch("tools.TOOLKIT_AVAILABLE", True), patch(
            "tools.sqlmap_scan", side_effect=fake_sqlmap_scan
        ):
            result = agent._execute_sqlmap_action(action)

        self.assertIn("[SQLMap]", result)
        self.assertEqual(captured["url"], agent.target_url)
        self.assertEqual(captured["kwargs"], {"batch": True, "level": 2})
        self.assertNotIn("action_id", captured["kwargs"])
        self.assertEqual(len(agent.memory.steps), 1)

        step = agent.memory.steps[0]
        self.assertEqual(step.action_id, action["id"])
        self.assertEqual(step.action_type, "sqlmap_scan")
        self.assertEqual(step.expected_tool, "sqlmap")
        self.assertEqual(step.canonical_tool, "sqlmap")

    def test_decide_next_action_switches_after_repeated_action_failures(self):
        agent = self.make_agent()
        meta = build_action_meta("repeat-action", action_type="recon")

        agent.memory.add_step(
            tool="python_poc",
            target=agent.target_url,
            params={"variant": "one"},
            result="blocked-1",
            success=False,
            action_meta=meta,
        )
        agent.memory.add_step(
            tool="python_poc",
            target=agent.target_url,
            params={"variant": "two"},
            result="blocked-2",
            success=False,
            action_meta=meta,
        )

        next_action = agent._decide_next_action()

        self.assertEqual(next_action["type"], "dir_scan")
        self.assertEqual(next_action["expected_tool"], "dirsearch")
        self.assertTrue(next_action.get("alternative"))

    def test_tool_node_success_uses_memory_step_success(self):
        agent = self.make_agent(max_failures=5, max_steps=1)
        action = agent._build_action(
            "sqlmap_scan",
            target=agent.target_url,
            description="detect injection",
            intent="validate sql injection",
            expected_tool="sqlmap",
            params={"batch": True},
        )
        events = []

        def fake_plan_next_action():
            return dict(action)

        def fake_execute_action(current_action):
            agent.memory.add_step(
                tool="sqlmap",
                target=agent.target_url,
                params={"batch": True},
                result="blocked by waf",
                success=False,
                action_meta=agent._build_memory_action_meta(current_action),
            )
            return "[SQLMap] blocked by waf"

        callback = lambda stage, payload: events.append({"stage": stage, "payload": payload})

        with patch.object(agent, "plan_next_action", side_effect=fake_plan_next_action), patch.object(
            agent, "_execute_action", side_effect=fake_execute_action
        ), patch("agent_core.extract_flags", return_value=[]), patch.object(
            agent, "maybe_request_help", return_value=None
        ), patch("agent_core.get_memory_summary", return_value="summary"):
            with self.assertRaises(AgentNeedsHelpException):
                agent.run_main_loop(event_callback=callback)

        tool_events = [event for event in events if event["stage"] == "tool_node"]
        self.assertEqual(len(tool_events), 1)
        self.assertFalse(tool_events[0]["payload"]["success"])
        self.assertFalse(agent.memory.steps[-1].success)

    def test_should_ask_for_help_uses_action_failure_counts(self):
        agent = self.make_agent(max_failures=3, max_steps=10)
        repeat_meta = build_action_meta("repeat-action", action_type="recon")

        agent.memory.add_step(
            tool="python_poc",
            target=agent.target_url,
            params={"variant": "one"},
            result="blocked-one",
            success=False,
            action_meta=repeat_meta,
        )
        agent.memory.add_step(
            tool="dirsearch",
            target=agent.target_url,
            params={"extensions": ["php"]},
            result="found /index.php",
            success=True,
            action_meta=build_action_meta("other-action", action_type="dir_scan", expected_tool="dirsearch", canonical_tool="dirsearch"),
        )
        agent.memory.add_step(
            tool="python_poc",
            target=agent.target_url,
            params={"variant": "two"},
            result="blocked-two",
            success=False,
            action_meta=repeat_meta,
        )
        agent.memory.add_step(
            tool="python_poc",
            target=agent.target_url,
            params={"variant": "three"},
            result="blocked-three",
            success=False,
            action_meta=repeat_meta,
        )

        should_help = agent._should_ask_for_help()

        self.assertTrue(should_help)
        self.assertEqual(agent.last_help_reason, "action_failures:repeat-action")


if __name__ == "__main__":
    unittest.main()
