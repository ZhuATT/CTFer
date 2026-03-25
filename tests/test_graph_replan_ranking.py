import unittest

from agent_core import AutoAgent
from tools import reset_memory


class GraphReplanRankingRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def _make_agent(self) -> AutoAgent:
        agent = AutoAgent(max_failures=3, max_steps=20, verbose=False, min_steps_before_help=1)
        agent.target_url = "http://target.test"
        agent.target_type = "unknown"
        agent.init_result = {"problem_type": "unknown", "loaded_resources": {}}
        agent.memory.set_context(url=agent.target_url, description="demo")
        agent._sync_agent_context()
        agent._refresh_graph_state = lambda: []
        return agent

    def _set_planner_signals(self, agent: AutoAgent, **overrides) -> None:
        signals = {
            "latest_guidance": "",
            "guidance_history": [],
            "latest_endpoint": "",
            "latest_parameter": "",
            "known_endpoints": [],
            "known_parameters": [],
            "known_vulnerabilities": [],
            "known_flags": [],
            "failed_action_ids": [],
            "failed_action_types": [],
            "failed_tools": [],
            "failed_action_counts": {},
            "failed_tool_counts": {},
            "recent_failed_cluster": [],
            "succeeded_action_ids": [],
            "active_node_id": "",
            "active_chain": [],
            "latest_replan": {},
            "recent_replans": [],
            "avoid_action_ids": [],
            "avoid_tools": [],
            "alternative_candidates": [],
        }
        signals.update(overrides)
        agent.graph_manager.planner_signals = lambda: dict(signals)

    def _add_failed_steps(self, agent: AutoAgent, action: dict, count: int) -> None:
        tool_name = agent._canonical_tool_name(action)
        action_meta = agent._build_memory_action_meta(action)
        agent.last_action = dict(action)
        for idx in range(count):
            agent.memory.add_step(
                tool=tool_name,
                target=action.get("target") or agent.target_url,
                params=dict(action.get("params") or {}),
                result=f"failure-{idx + 1}",
                success=False,
                action_meta=action_meta,
            )

    def test_build_replan_payload_prefers_new_endpoint_over_earlier_guidance_candidate(self):
        agent = self._make_agent()
        failed_action = agent._build_action(
            "sqlmap_scan",
            target=agent.target_url,
            description="Try sqlmap",
            intent="Probe injection",
            expected_tool="sqlmap",
            params={"batch": True},
        )
        self._add_failed_steps(agent, failed_action, 5)
        self._set_planner_signals(
            agent,
            latest_guidance="Check cookie behavior",
            latest_endpoint="/admin",
            known_endpoints=["/admin"],
        )

        payload = agent._build_replan_payload()
        candidates = list(payload.get("alternative_candidates") or [])

        self.assertGreaterEqual(len(candidates), 2)
        self.assertEqual(payload.get("reason_code"), "limited_diversity")
        self.assertEqual(candidates[0]["source_finding_kind"], "endpoint")
        self.assertEqual(candidates[0]["target"], "http://target.test/admin")
        self.assertEqual(payload.get("selected_alternative"), candidates[0])

        graph_action = agent._build_graph_informed_action(replan=payload)
        self.assertIsNotNone(graph_action)
        self.assertEqual(graph_action["target"], candidates[0]["target"])
        self.assertEqual(graph_action["type"], candidates[0]["action_type"])

        agent.pending_replan = dict(payload)
        planned_action = agent.plan_next_action()
        self.assertEqual(planned_action["target"], candidates[0]["target"])
        self.assertEqual(planned_action["type"], candidates[0]["action_type"])
        self.assertEqual(planned_action["replan"]["selected_alternative"], candidates[0])

    def test_rank_graph_candidates_demotes_blocked_tool(self):
        agent = self._make_agent()
        ranked = agent._rank_graph_informed_candidates(
            [
                {
                    "action_id": "b-action",
                    "action_type": "dir_scan",
                    "target": agent.target_url,
                    "description": "Scan directories",
                    "intent": "Find paths",
                    "expected_tool": "dirsearch",
                    "params": {"extensions": ["php"]},
                },
                {
                    "action_id": "a-action",
                    "action_type": "recon",
                    "target": agent.target_url,
                    "description": "Retry recon",
                    "intent": "Collect headers",
                    "expected_tool": "recon",
                    "params": {"focus": "headers"},
                },
            ],
            replan={"blocked_tools": ["dirsearch"]},
        )

        self.assertEqual(ranked[0]["action_type"], "recon")
        self.assertEqual(ranked[-1]["action_type"], "dir_scan")

    def test_rank_graph_candidates_uses_stable_tiebreaker(self):
        agent = self._make_agent()
        candidate_a = {
            "action_id": "a-action",
            "action_type": "recon",
            "target": agent.target_url,
            "description": "Candidate A",
            "intent": "Collect headers",
            "expected_tool": "recon",
            "params": {"focus": "headers"},
        }
        candidate_b = {
            "action_id": "b-action",
            "action_type": "recon",
            "target": agent.target_url,
            "description": "Candidate B",
            "intent": "Collect headers",
            "expected_tool": "recon",
            "params": {"focus": "headers"},
        }

        ranked_forward = agent._rank_graph_informed_candidates([candidate_b, candidate_a])
        ranked_reverse = agent._rank_graph_informed_candidates([candidate_a, candidate_b])

        self.assertEqual([item["action_id"] for item in ranked_forward], ["a-action", "b-action"])
        self.assertEqual([item["action_id"] for item in ranked_reverse], ["a-action", "b-action"])


if __name__ == "__main__":
    unittest.main()
