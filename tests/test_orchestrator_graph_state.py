import unittest

from agent_core import AutoAgent
from orchestrator import CTFOrchestrator
from tools import reset_memory


class OrchestratorGraphStateRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def test_sync_state_exposes_latest_replan_rationale(self):
        agent = AutoAgent(max_failures=3, max_steps=5, verbose=False, min_steps_before_help=10)
        agent.target_url = "http://target.test"
        agent.target_type = "unknown"
        agent.init_result = {"problem_type": "unknown", "loaded_resources": {}}
        agent.memory.set_context(url=agent.target_url, description="demo")
        agent._sync_agent_context()

        action = agent._build_action(
            "recon",
            target="http://target.test/.git/HEAD",
            description="Verify repo exposure",
            intent="Inspect leaked repo marker",
            expected_tool="recon",
            metadata={
                "source_finding_kind": "repo_exposure",
                "source_finding_value": "/.git/HEAD",
                "verification_family": "repo_exposure",
            },
        )
        agent.graph_manager.record_planned_action(action, step=1)
        agent.graph_manager.record_action_result(action, step=2, success=False, result="blocked")
        agent.graph_manager.record_replan(
            step=3,
            action=action,
            reason="limited_diversity",
            graph_op={
                "checkpoint_label": "replan",
                "metadata": {
                    "reason_code": "limited_diversity",
                    "reason_detail": "Repo exposure lineage stalled",
                    "source_finding_kind": "repo_exposure",
                    "source_finding_value": "/.git/HEAD",
                    "verification_family": "repo_exposure",
                    "blocked_findings": [
                        {
                            "kind": "repo_exposure",
                            "value": "/.git/HEAD",
                            "verification_family": "repo_exposure",
                        }
                    ],
                    "selected_alternative": {
                        "action_type": "source_analysis",
                        "target": "http://target.test",
                        "source_finding_kind": "source_leak",
                        "source_finding_value": "view-source",
                    },
                },
            },
        )

        orchestrator = CTFOrchestrator(agent=agent)
        orchestrator._sync_state()

        self.assertEqual(orchestrator.state.replan_reason, "Repo exposure lineage stalled")
        self.assertTrue(any(item.get("kind") == "repo_exposure" for item in orchestrator.state.blocked_findings))
        self.assertEqual(orchestrator.state.selected_alternative.get("action_type"), "source_analysis")


if __name__ == "__main__":
    unittest.main()
