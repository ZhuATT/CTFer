import unittest

import tools
from agent_core import AutoAgent
from taxonomy import build_taxonomy_profile, canonical_skill_names, canonicalize_problem_type, problem_type_aliases
from tools import reset_memory


class TaxonomyBridgeRegressionTest(unittest.TestCase):
    def setUp(self):
        reset_memory()

    def tearDown(self):
        reset_memory()

    def test_canonicalize_problem_type_handles_aliases(self):
        self.assertEqual(canonicalize_problem_type("file-inclusion"), "lfi")
        self.assertEqual(canonicalize_problem_type("auth-bypass"), "auth")
        self.assertEqual(canonicalize_problem_type("web-recon"), "recon")
        self.assertEqual(canonicalize_problem_type("unknown-thing"), "unknown")

    def test_problem_type_aliases_include_legacy_names(self):
        self.assertIn("file-inclusion", canonical_skill_names("lfi"))
        self.assertIn("auth-bypass", canonical_skill_names("auth"))
        self.assertIn("web-recon", canonical_skill_names("recon"))
        self.assertIn("lfi", problem_type_aliases("lfi"))

    def test_build_taxonomy_profile_exposes_canonical_and_tags(self):
        profile = build_taxonomy_profile(
            "file-inclusion",
            "http://target.test",
            "",
            "尝试 path traversal 和 php://filter",
        )
        self.assertEqual(profile["canonical_problem_type"], "lfi")
        self.assertIn("lfi", profile["taxonomy_tags"])
        self.assertIn("file-inclusion", profile["skill_names"])

    def test_init_problem_returns_taxonomy_profile_and_canonical_type(self):
        result = tools.init_problem("http://target.test", hint="尝试 file inclusion")
        self.assertEqual(result["problem_type"], "lfi")
        self.assertIn("taxonomy_profile", result)
        self.assertEqual(result["taxonomy_profile"]["canonical_problem_type"], "lfi")
        self.assertIn("taxonomy_profile", result["loaded_resources"])

    def test_get_available_resources_returns_normalized_bundle(self):
        result = tools.init_problem("http://target.test", hint="auth bypass")
        resources = tools.get_available_resources()

        self.assertEqual(resources["canonical_problem_type"], "auth")
        self.assertIn("taxonomy_profile", resources)
        self.assertIn("resource_bundle", resources)
        self.assertIn("skills", resources["resource_bundle"])

    def test_rag_query_context_uses_taxonomy_profile_and_shared_findings(self):
        tools.reset_memory()
        memory = tools.get_memory()
        memory.set_context(url="http://target.test", description="demo", hint="file inclusion")
        memory.context.loaded_resources = {
            "taxonomy_profile": build_taxonomy_profile("file-inclusion", "http://target.test", "demo", "file inclusion")
        }
        memory.context.shared_findings = [{"kind": "endpoint", "value": "/download.php", "metadata": {}}]

        context = tools._build_rag_query_context(
            query="Need more LFI ideas",
            vuln_type="file-inclusion",
            target_url="http://target.test",
            attempted_methods=["php://filter"],
        )

        self.assertEqual(context["current_vuln_type"], "lfi")
        self.assertIn("file-inclusion", context["taxonomy_aliases"])
        self.assertTrue(any(item.get("kind") == "endpoint" for item in context["shared_findings"]))

        agent = AutoAgent(max_failures=3, max_steps=5, verbose=False, min_steps_before_help=10)
        agent.target_url = "http://target.test"
        agent.target_type = "lfi"
        agent.init_result = {
            "problem_type": "lfi",
            "loaded_resources": {
                "taxonomy_profile": build_taxonomy_profile("lfi", "http://target.test", "", "php://filter"),
                "resource_bundle": {"skills": ["file-inclusion"]},
            },
            "skill_content": "demo",
        }
        agent.memory.set_context(url=agent.target_url, description="demo")
        agent._sync_agent_context()
        agent._refresh_graph_state = lambda: []

        context = agent.build_advisor_context()

        self.assertEqual(context["canonical_problem_type"], "lfi")
        self.assertIn("lfi", context["taxonomy_tags"])
        self.assertIn("file-inclusion", context["resource_summary"]["skill_names"])


if __name__ == "__main__":
    unittest.main()
