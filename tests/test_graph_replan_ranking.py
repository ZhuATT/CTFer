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

    def test_rank_graph_candidates_demotes_blocked_lineage(self):
        agent = self._make_agent()
        ranked = agent._rank_graph_informed_candidates(
            [
                {
                    "action_id": "blocked-lineage",
                    "action_type": "recon",
                    "target": agent.target_url,
                    "description": "Retry blocked lineage",
                    "intent": "Retry repo exposure validation",
                    "expected_tool": "recon",
                    "source_finding_kind": "repo_exposure",
                    "source_finding_value": "/.git/HEAD",
                    "verification_family": "repo_exposure",
                },
                {
                    "action_id": "fresh-lineage",
                    "action_type": "source_analysis",
                    "target": agent.target_url,
                    "description": "Try new source leak lineage",
                    "intent": "Analyze alternate source leak",
                    "expected_tool": "source_analysis",
                    "source_finding_kind": "source_leak",
                    "source_finding_value": "view-source",
                    "verification_family": "source_leak",
                },
            ],
            signals={
                "blocked_findings": [
                    {
                        "kind": "repo_exposure",
                        "value": "/.git/HEAD",
                        "verification_family": "repo_exposure",
                        "lineage_key": "repo_exposure::/.git/HEAD::repo_exposure",
                    }
                ],
                "finding_failure_counts": {"repo_exposure::/.git/HEAD::repo_exposure": 3},
                "finding_attempt_counts": {"repo_exposure::/.git/HEAD::repo_exposure": 3},
            },
            replan={"avoid_lineages": ["repo_exposure::/.git/HEAD::repo_exposure"]},
        )

        self.assertEqual(ranked[0]["action_id"], "fresh-lineage")
        self.assertEqual(ranked[-1]["action_id"], "blocked-lineage")

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

    def test_priority_findings_surface_in_planner_signals(self):
        agent = self._make_agent()
        agent._refresh_graph_state = AutoAgent._refresh_graph_state.__get__(agent, AutoAgent)
        agent.memory.add_endpoint("/.git/HEAD")
        agent.memory.add_step(
            tool="dirsearch",
            target=agent.target_url,
            params={},
            result="Sensitive path: /.git/HEAD",
            success=True,
            key_findings=["repo_exposure:\\.git(?:/head|/config)?"],
            action_meta={
                "action_id": "dir-1",
                "action_type": "dir_scan",
                "expected_tool": "dirsearch",
                "canonical_tool": "dirsearch",
            },
        )
        agent._refresh_graph_state()
        self.assertTrue(any(item.get("kind") == "repo_exposure" for item in agent.graph_manager.get_shared_findings()))

        signals = agent.graph_manager.planner_signals()

        self.assertTrue(any(item.get("kind") == "repo_exposure" for item in signals["priority_findings"]))
        self.assertTrue(any(item.get("kind") == "repo_exposure" for item in signals["verification_hints"]))

    def test_repo_exposure_finding_prefers_repo_specific_follow_up(self):
        agent = self._make_agent()
        self._set_planner_signals(
            agent,
            priority_findings=[
                {
                    "kind": "repo_exposure",
                    "value": "/.git/HEAD",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "dir-1",
                    "source_node_id": "action:dir-1",
                }
            ],
            verification_hints=[
                {
                    "kind": "repo_exposure",
                    "value": "/.git/HEAD",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "dir-1",
                    "source_node_id": "action:dir-1",
                }
            ],
        )

        candidates = agent._collect_graph_informed_actions()

        self.assertTrue(any(item.get("tactic_family") == "repo_exposure" for item in candidates))
        self.assertTrue(any((item.get("params") or {}).get("focus") == "repo-exposure" for item in candidates))
        self.assertFalse(all(item.get("type") == "dir_scan" for item in candidates[:1]))

        agent = self._make_agent()
        self._set_planner_signals(
            agent,
            priority_findings=[
                {
                    "kind": "repo_exposure",
                    "value": "/.git/HEAD",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "dir-1",
                    "source_node_id": "action:dir-1",
                }
            ],
            verification_hints=[
                {
                    "kind": "repo_exposure",
                    "value": "/.git/HEAD",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "dir-1",
                    "source_node_id": "action:dir-1",
                }
            ],
        )

        candidates = agent._collect_graph_informed_actions()

        self.assertTrue(any(item.get("source_finding_kind") == "repo_exposure" for item in candidates))
        self.assertTrue(any(item.get("verification_family") == "repo_exposure" for item in candidates))

    def test_form_findings_build_auth_follow_up_candidates(self):
        agent = self._make_agent()
        agent.target_type = "auth"
        self._set_planner_signals(
            agent,
            priority_findings=[
                {
                    "kind": "form_field",
                    "value": "username",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "recon-1",
                    "source_node_id": "action:recon-1",
                },
                {
                    "kind": "form_method",
                    "value": "POST",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "recon-1",
                    "source_node_id": "action:recon-1",
                },
            ],
            verification_hints=[
                {
                    "kind": "auth_hint",
                    "value": "login_endpoint",
                    "confidence": 1.0,
                    "metadata": {},
                    "source_action_id": "recon-1",
                    "source_node_id": "action:recon-1",
                }
            ],
            known_endpoints=["/login.php"],
            known_parameters=["username", "password"],
        )
        candidates = agent._collect_graph_informed_actions()
        self.assertTrue(any(item.get("verification_family") == "endpoint-enum" for item in candidates))
        self.assertTrue(any(item.get("type") == "poc" for item in candidates))

        agent = self._make_agent()
        self._set_planner_signals(
            agent,
            latest_endpoint="/.git/HEAD",
            known_endpoints=["/.git/HEAD"],
        )

        candidates = agent._collect_graph_informed_actions()

        self.assertTrue(any(item.get("target") == "http://target.test/.git/HEAD" for item in candidates))
        self.assertTrue(any(item.get("source_finding_kind") in {"repo_exposure", "sensitive_endpoint"} for item in candidates))

    def test_decide_next_action_breaks_repeated_dir_scan_without_findings(self):
        agent = self._make_agent()
        failed_action = agent._build_action(
            "dir_scan",
            target=agent.target_url,
            description="Scan directories",
            intent="Find paths",
            expected_tool="dirsearch",
            params={"extensions": ["php"]},
        )
        action_meta = agent._build_memory_action_meta(failed_action)
        for idx in range(3):
            agent.memory.add_step(
                tool="dirsearch",
                target=agent.target_url,
                params={"extensions": ["php"]},
                result=f"dir-failure-{idx}",
                success=False,
                key_findings=[],
                action_meta=action_meta,
            )

        agent._build_graph_informed_action = lambda: None
        action = agent._decide_next_action()

        self.assertEqual(action["type"], "recon")
        self.assertEqual(action["params"]["focus"], "break-dir-scan-loop")

    def test_build_replan_payload_detects_low_yield_probe_loop(self):
        agent = self._make_agent()
        failed_action = agent._build_action(
            "recon",
            target=agent.target_url,
            description="Retry recon",
            intent="Collect headers",
            expected_tool="recon",
            params={"focus": "headers"},
        )
        action_meta = agent._build_memory_action_meta(failed_action)
        for idx in range(3):
            agent.memory.add_step(
                tool="recon",
                target=agent.target_url,
                params={"focus": "headers"},
                result=f"header-only-{idx}",
                success=False,
                key_findings=[],
                action_meta=action_meta,
            )

        agent._build_graph_informed_action = lambda: None
        action = agent._decide_next_action()

        self.assertEqual(action["type"], "dir_scan")

        agent = self._make_agent()

        actions = agent._build_guidance_actions(
            "Check cookie and source leak behavior",
            target=agent.target_url,
            source_action_id="replan-1",
            source_action_type="recon",
        )

        self.assertTrue(any(item["source_finding_kind"] == "guidance" for item in actions))
        self.assertTrue(all(item["verification_family"] == "guidance" for item in actions))
        self.assertTrue(any(item["type"] == "recon" for item in actions))
        self.assertTrue(any(item["type"] == "source_analysis" for item in actions))

        agent = self._make_agent()
        failed_action = agent._build_action(
            "dir_scan",
            target=agent.target_url,
            description="Scan directories",
            intent="Find paths",
            expected_tool="dirsearch",
            params={"extensions": ["php"]},
        )
        action_meta = agent._build_memory_action_meta(failed_action)
        for idx in range(2):
            agent.memory.add_step(
                tool="dirsearch",
                target=agent.target_url,
                params={"extensions": ["php"]},
                result=f"dir-failure-{idx}",
                success=False,
                key_findings=[],
                action_meta=action_meta,
            )

        agent._build_graph_informed_action = lambda: agent._build_action(
            "recon",
            target=agent.target_url,
            description="Fallback recon",
            intent="Collect better findings",
            expected_tool="recon",
        )

        action = agent._decide_next_action()

        self.assertEqual(action["type"], "recon")


if __name__ == "__main__":
    unittest.main()
