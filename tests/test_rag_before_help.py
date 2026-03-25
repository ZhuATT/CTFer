import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import agent_core
import tools
from agent_core import AgentNeedsHelpException, AutoAgent
from long_memory import LongMemory
from orchestrator import CTFOrchestrator
from short_memory import extract_flag_candidates
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


class RunMainLoopFlagRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def _make_agent(self) -> AutoAgent:
        agent = AutoAgent(max_failures=3, max_steps=1, verbose=False, min_steps_before_help=10)
        agent.target_url = "http://target.test"
        agent.target_type = "unknown"
        agent.init_result = {"problem_type": "unknown", "loaded_resources": {}}
        agent.memory.set_context(url=agent.target_url, description="demo")
        agent._sync_agent_context()
        agent.graph_manager.apply_graph_op = lambda *args, **kwargs: None
        agent._refresh_graph_state = lambda: []
        agent.maybe_request_help = lambda step_num: None
        return agent

    def _prepare_single_action(self, agent: AutoAgent) -> None:
        action = agent._build_action(
            "recon",
            target=agent.target_url,
            description="Collect response preview",
            intent="Look for a flag in the response",
            expected_tool="recon",
        )
        agent.plan_next_action = lambda: dict(action)

    def test_run_main_loop_keeps_unconfirmed_flag_as_candidate(self):
        agent = self._make_agent()
        self._prepare_single_action(agent)
        agent._auto_save_experience = lambda flag: None
        events = []

        def fake_execute_action(action):
            output = "Status: 200\nFLAG_FOUND: ctfshow{demo_candidate}"
            agent.memory.add_step(
                tool="python_poc",
                target=agent.target_url,
                params={},
                result=output,
                success=False,
                action_meta=agent._build_memory_action_meta(action),
            )
            return output

        agent._execute_action = fake_execute_action

        with self.assertRaises(AgentNeedsHelpException):
            agent.run_main_loop(event_callback=lambda stage, payload: events.append((stage, payload)))

        self.assertEqual(agent.memory.target.flags, [])
        self.assertIn("ctfshow{demo_candidate}", agent.memory.steps[-1].key_findings)
        tool_node_payload = [payload for stage, payload in events if stage == "tool_node"][-1]
        self.assertFalse(tool_node_payload["success"])
        self.assertFalse(agent.memory.steps[-1].success)

    def test_run_main_loop_confirms_flag_when_action_succeeds(self):
        agent = self._make_agent()
        self._prepare_single_action(agent)
        autosaved_flags = []
        agent._auto_save_experience = lambda flag: autosaved_flags.append(flag)
        events = []

        def fake_execute_action(action):
            output = "Status: 200\nFLAG_FOUND: ctfshow{demo_success}"
            agent.memory.add_step(
                tool="python_poc",
                target=agent.target_url,
                params={},
                result=output,
                success=True,
                action_meta=agent._build_memory_action_meta(action),
            )
            return output

        agent._execute_action = fake_execute_action

        result = agent.run_main_loop(event_callback=lambda stage, payload: events.append((stage, payload)))

        self.assertTrue(result["success"])
        self.assertEqual(result["flag"], "ctfshow{demo_success}")
        self.assertEqual(autosaved_flags, ["ctfshow{demo_success}"])
        self.assertIn("ctfshow{demo_success}", agent.memory.target.flags)
        tool_node_payload = [payload for stage, payload in events if stage == "tool_node"][-1]
        self.assertTrue(tool_node_payload["success"])
        self.assertEqual(tool_node_payload["success"], agent.memory.steps[-1].success)


class OrchestratorFlagSemanticsRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def _make_agent(self) -> AutoAgent:
        agent = AutoAgent(max_failures=3, max_steps=1, verbose=False, min_steps_before_help=10)
        agent.target_url = "http://target.test"
        agent.target_type = "unknown"
        agent.init_result = {"problem_type": "unknown", "loaded_resources": {}}
        agent.memory.set_context(url=agent.target_url, description="demo")
        agent._sync_agent_context()
        agent.graph_manager.apply_graph_op = lambda *args, **kwargs: None
        agent.graph_manager.snapshot = lambda: {}
        agent._refresh_graph_state = lambda: []
        return agent

    def _prepare_single_action(self, agent: AutoAgent) -> None:
        action = agent._build_action(
            "recon",
            target=agent.target_url,
            description="Collect response preview",
            intent="Look for a flag in the response",
            expected_tool="recon",
        )
        agent.plan_next_action = lambda: dict(action)

    def test_orchestrator_keeps_unconfirmed_flag_candidate_out_of_final_state(self):
        agent = self._make_agent()
        self._prepare_single_action(agent)
        agent._auto_save_experience = lambda flag: None

        def fake_execute_action(action):
            output = "Status: 200\nFLAG_FOUND: ctfshow{demo_candidate}"
            agent.memory.add_step(
                tool="python_poc",
                target=agent.target_url,
                params={},
                result=output,
                success=False,
                action_meta=agent._build_memory_action_meta(action),
            )
            return output

        agent._execute_action = fake_execute_action

        orchestrator = CTFOrchestrator(agent=agent)
        result = orchestrator.run()
        state = orchestrator.state

        self.assertFalse(result["success"])
        self.assertTrue(result["needs_help"])
        self.assertEqual(state.status, "needs_help")
        self.assertEqual(state.pending_flag, "")
        self.assertEqual(state.tool_node_state["success"], agent.memory.steps[-1].success)
        self.assertFalse(state.tool_node_state["success"])
        self.assertEqual(agent.memory.target.flags, [])
        self.assertIn("ctfshow{demo_candidate}", agent.memory.steps[-1].key_findings)

    def test_orchestrator_persists_confirmed_flag_into_final_state(self):
        agent = self._make_agent()
        self._prepare_single_action(agent)
        agent._auto_save_experience = lambda flag: None

        def fake_execute_action(action):
            output = "Status: 200\nFLAG_FOUND: ctfshow{demo_success}"
            agent.memory.add_step(
                tool="python_poc",
                target=agent.target_url,
                params={},
                result=output,
                success=True,
                action_meta=agent._build_memory_action_meta(action),
            )
            return output

        agent._execute_action = fake_execute_action

        orchestrator = CTFOrchestrator(agent=agent)
        result = orchestrator.run()
        state = orchestrator.state

        self.assertTrue(result["success"])
        self.assertEqual(result["flag"], "ctfshow{demo_success}")
        self.assertEqual(state.status, "succeeded")
        self.assertEqual(state.pending_flag, "ctfshow{demo_success}")
        self.assertEqual(state.final_result["flag"], "ctfshow{demo_success}")
        self.assertEqual(state.tool_node_state["success"], agent.memory.steps[-1].success)
        self.assertTrue(state.tool_node_state["success"])
        self.assertIn("ctfshow{demo_success}", agent.memory.target.flags)


class FlagExtractorRegressionTest(unittest.TestCase):
    def test_shared_extractors_keep_first_match_order(self):
        text = (
            "prefix ctfshow{alpha} middle FLAG{beta} repeat ctfshow{alpha} "
            "suffix tfshow{gamma}"
        )
        expected = ["ctfshow{alpha}", "FLAG{beta}", "tfshow{gamma}"]

        self.assertEqual(extract_flag_candidates(text), expected)
        self.assertEqual(tools.extract_flags(text), expected)


class FenjingFlagBookkeepingRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def test_fenjing_crack_form_records_confirmed_flag_via_memory_api(self):
        response = Mock(status_code=200, text="rendered output ctfshow{fenjing_demo}")

        with patch.object(tools, "_init_fenjing", return_value=True), patch.object(
            tools,
            "fenjing_generate_payload",
            return_value={"success": True, "payload": "{{demo}}", "will_print": True, "error": ""},
        ), patch("requests.get", return_value=response):
            result = tools.fenjing_crack_form("http://target.test", inputs="name")

        memory = tools.get_memory()
        self.assertTrue(result["success"])
        self.assertEqual(result["flag"], "ctfshow{fenjing_demo}")
        self.assertIn("ctfshow{fenjing_demo}", memory.target.flags)


class LongMemoryRegressionTest(unittest.TestCase):
    def test_save_experience_returns_saved_file_path(self):
        memory = LongMemory()

        with tempfile.TemporaryDirectory() as tmpdir:
            memory.BASE_PATH = Path(tmpdir)
            saved_path = memory.save_experience(
                problem_type="unit_test",
                target="http://target.test/demo",
                steps=[
                    {
                        "tool": "python_poc",
                        "target": "http://target.test/demo",
                        "result": "FLAG_FOUND: ctfshow{saved_demo}",
                        "success": True,
                    }
                ],
                flag="ctfshow{saved_demo}",
                key_techniques=["python_poc"],
            )
            exp_file = Path(saved_path)
            self.assertTrue(exp_file.exists())
            self.assertIn("ctfshow{saved_demo}", exp_file.read_text(encoding="utf-8"))

        self.assertTrue(saved_path)


class InitProblemTlsRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def test_init_problem_https_probe_uses_verify_false_for_type_detection(self):
        response = Mock(status_code=200, text="welcome", headers={"Server": "TornadoServer"})

        def fake_get(*args, **kwargs):
            if kwargs.get("verify") is not False:
                raise tools.requests.exceptions.SSLError("certificate verify failed")
            return response

        with patch("tools.requests.get", side_effect=fake_get) as get_mock, patch.object(
            tools, "LONG_MEMORY_AVAILABLE", False
        ), patch.object(tools, "_retrieve_wooyun_knowledge", return_value=""):
            result = tools.init_problem("https://target.test")

        self.assertEqual(result["problem_type"], "tornado")
        self.assertEqual(get_mock.call_count, 1)
        self.assertEqual(get_mock.call_args.args[0], "https://target.test")
        self.assertEqual(get_mock.call_args.kwargs["timeout"], 10)
        self.assertIs(get_mock.call_args.kwargs["verify"], False)
