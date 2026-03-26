"""
Regression tests for auth execution drift fixes.
Validates that:
1. tactic_family and resource_source are preserved through replan cycle
2. auth-sqli is blocked until endpoint-enum is confirmed
3. auth targets don't degenerate to dir_scan in low_yield scenarios
"""

import unittest
from agent_core import AutoAgent
from tools import reset_memory


class AuthReplanDegradationRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def _make_agent(self) -> AutoAgent:
        agent = AutoAgent(max_failures=3, max_steps=20, verbose=False, min_steps_before_help=1)
        agent.target_url = "http://target.test"
        agent.target_type = "auth"
        agent.init_result = {
            "problem_type": "auth",
            "skill_content": "auth bypass skill",
            "loaded_resources": {"resource_bundle": {"skills": ["auth-bypass"]}},
        }
        agent.memory.set_context(
            problem_type="auth",
            url=agent.target_url,
            hint="login page",
            skill_content=agent.init_result["skill_content"],
            loaded_resources=agent.init_result["loaded_resources"],
        )
        agent._sync_agent_context()
        return agent

    def test_action_candidate_summary_preserves_tactic_family(self):
        """Verify _action_candidate_summary preserves tactic_family and resource_source."""
        agent = self._make_agent()
        action = agent._build_action(
            "poc",
            target=agent.target_url,
            description="Test POC",
            intent="Test intent",
            expected_tool="python_poc",
            metadata={
                "tactic_family": "weak-creds",
                "resource_source": "long_memory",
            },
        )
        summary = agent._action_candidate_summary(action)

        self.assertEqual(summary.get("tactic_family"), "weak-creds")
        self.assertEqual(summary.get("resource_source"), "long_memory")

    def test_build_action_from_candidate_restores_tactic_family(self):
        """Verify _build_action_from_candidate restores tactic_family and resource_source."""
        agent = self._make_agent()
        candidate = {
            "action_type": "poc",
            "target": agent.target_url,
            "description": "Test POC",
            "intent": "Test intent",
            "expected_tool": "python_poc",
            "tactic_family": "weak-creds",
            "resource_source": "skill",
        }
        action = agent._build_action_from_candidate(candidate)

        self.assertIsNotNone(action)
        # Verify tactic_family and resource_source are at the top level (since _build_action merges metadata)
        self.assertEqual(action.get("tactic_family"), "weak-creds")
        self.assertEqual(action.get("resource_source"), "skill")

    def test_auth_sqli_blocked_before_endpoint_enum_confirmed(self):
        """Verify auth-sqli is not allowed until endpoint-enum is confirmed."""
        agent = self._make_agent()
        agent.memory.add_endpoint("/login.php")
        agent.memory.add_parameter("username")
        agent.memory.add_parameter("password")

        # No endpoint confirmation yet - should not allow auth-sqli
        auth_state = agent._auth_progress_state()
        self.assertFalse(auth_state.get("endpoint_enum_confirmed", False))
        self.assertFalse(auth_state.get("structured_auth_signal", False))

        # Required families should NOT include auth-sqli yet
        required = agent._required_tactic_families()
        self.assertIn("endpoint-enum", required)
        self.assertIn("weak-creds", required)
        self.assertNotIn("auth-sqli", required)

    def test_auth_sqli_allowed_after_endpoint_confirmation(self):
        """Verify auth-sqli is allowed after endpoint-enum is confirmed."""
        agent = self._make_agent()
        agent.memory.add_endpoint("/login.php")
        agent.memory.add_parameter("username")
        agent.memory.add_parameter("password")

        # Add a step that confirms endpoint enum
        agent.memory.add_step(
            tool="recon",
            target=agent.target_url,
            params={"focus": "auth"},
            result="Found login form endpoint: /login.php with form method: POST, form fields: username, password",
            success=True,
            key_findings=["login form endpoint: /login.php", "form method: POST", "form field: username", "form field: password"],
            action_meta={
                "action_id": "recon-1",
                "action_type": "recon",
                "expected_tool": "recon",
                "canonical_tool": "recon",
            },
        )

        # Now endpoint should be confirmed
        auth_state = agent._auth_progress_state()
        self.assertTrue(auth_state.get("endpoint_enum_confirmed", False))

        # Required families should now include auth-sqli
        required = agent._required_tactic_families()
        self.assertIn("auth-sqli", required)

    def test_auth_target_does_not_fallback_to_dir_scan_in_low_yield_probe_loop(self):
        """Verify auth targets don't fall back to dir_scan in low_yield_probe_loop."""
        agent = self._make_agent()
        agent.memory.add_endpoint("/login.php")

        # Simulate low_yield_probe_loop conditions
        for i in range(3):
            agent.memory.add_step(
                tool="recon",
                target=agent.target_url,
                params={"focus": "headers"},
                result=f"header-only-{i}",
                success=False,
                key_findings=[],
                action_meta={
                    "action_id": f"recon-{i}",
                    "action_type": "recon",
                    "expected_tool": "recon",
                    "canonical_tool": "recon",
                },
            )

        # Mock _build_graph_informed_action to return None
        agent._build_graph_informed_action = lambda: None

        action = agent._decide_next_action()

        # For auth targets, should NOT return dir_scan
        self.assertNotEqual(action.get("type"), "dir_scan")
        # Auth target with no successful POC will return POC (correct auth flow)
        # but should not go to dir_scan in low_yield loop
        if action.get("type") == "poc":
            # This is expected - auth target returns POC first
            pass
        elif action.get("type") == "recon":
            # Should have auth-recover focus
            self.assertEqual(action.get("params", {}).get("focus"), "auth-recover")

    def test_auth_target_avoids_dir_scan_in_generic_failure_branch(self):
        """Verify auth targets avoid dir_scan in generic failure handling."""
        agent = self._make_agent()
        agent.memory.add_endpoint("/login.php")

        # Simulate repeated failures but not in low_yield loop yet
        for i in range(2):
            agent.memory.add_step(
                tool="python_poc",
                target=agent.target_url,
                params={"code": "print('test')"},
                result=f"poc-failure-{i}",
                success=False,
                key_findings=[],
                action_meta={
                    "action_id": f"poc-{i}",
                    "action_type": "poc",
                    "expected_tool": "python_poc",
                    "canonical_tool": "python_poc",
                },
            )

        # Mock _build_graph_informed_action to return None
        agent._build_graph_informed_action = lambda: None

        action = agent._decide_next_action()

        # For auth targets, should NOT return dir_scan in the generic failure branch
        self.assertNotEqual(action.get("type"), "dir_scan")


if __name__ == "__main__":
    unittest.main()
