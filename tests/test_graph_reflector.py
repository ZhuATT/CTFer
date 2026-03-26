import unittest

from agent_core import AutoAgent
from graph_manager import GraphManager
from tools import reset_memory


class GraphReflectorRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def test_record_replan_exposes_blocked_finding_lineage_signals(self):
        manager = GraphManager()
        action = {
            "id": "recon-1",
            "type": "recon",
            "target": "http://target.test/.git/HEAD",
            "description": "Verify repo exposure",
            "intent": "Inspect leaked repo marker",
            "expected_tool": "recon",
            "params": {},
            "source_finding_kind": "repo_exposure",
            "source_finding_value": "/.git/HEAD",
            "verification_family": "repo_exposure",
        }
        manager.record_planned_action(action, step=1)
        manager.record_action_result(action, step=2, success=False, result="blocked")
        manager.record_replan(
            step=3,
            action=action,
            reason="limited_diversity",
            graph_op={
                "checkpoint_label": "replan",
                "metadata": {
                    "reason_code": "limited_diversity",
                    "reason_detail": "Repo exposure lineage stalled",
                    "source_action_id": "recon-1",
                    "source_action_type": "recon",
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
                    "avoid_lineages": ["repo_exposure::/.git/HEAD::repo_exposure"],
                },
            },
        )

        signals = manager.planner_signals()
        latest_replan = signals["latest_replan"]

        self.assertEqual(latest_replan["source_finding_kind"], "repo_exposure")
        self.assertEqual(latest_replan["verification_family"], "repo_exposure")
        self.assertIn("repo_exposure::/.git/HEAD::repo_exposure", latest_replan["avoid_lineages"])
        self.assertTrue(any(item.get("lineage_key") == "repo_exposure::/.git/HEAD::repo_exposure" for item in signals["blocked_findings"]))
        self.assertEqual(signals["finding_failure_counts"]["repo_exposure::/.git/HEAD::repo_exposure"], 1)

    def test_planner_signals_surface_form_findings_as_priority(self):
        manager = GraphManager()
        memory = type("MemoryView", (), {})()
        memory.target = type("TargetView", (), {"endpoints": ["/login.php"], "parameters": ["username", "password"], "vulnerabilities": [], "flags": []})()
        memory.context = type("ContextView", (), {"shared_findings": [], "human_guidance": "", "help_history": []})()
        memory.steps = [
            type("StepView", (), {
                "action_id": "recon-1",
                "result": "Found login form endpoint: /login.php\nForm field: username\nForm field: password\nForm method: POST",
                "key_findings": ["auth_hint:login_endpoint", "form_field:username", "form_field:password", "form_method:POST"],
            })()
        ]
        manager.refresh_shared_findings(memory)
        signals = manager.planner_signals()
        kinds = {item.get("kind") for item in signals["priority_findings"]}
        self.assertIn("form_field", kinds)
        self.assertIn("form_method", kinds)
        self.assertIn("auth_hint", kinds)


if __name__ == "__main__":
    unittest.main()
