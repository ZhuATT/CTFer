import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import tools
from short_memory import ShortMemory
from toolkit import fenjing
from utils import python_runner


class SharedRuntimeTests(unittest.TestCase):
    def test_execute_command_uses_shared_runner_without_workon_wrapper(self):
        memory = ShortMemory()
        completed = subprocess.CompletedProcess(
            args="python -V",
            returncode=0,
            stdout="Python 3.11.0\n",
            stderr="",
        )

        with patch("tools.get_memory", return_value=memory), patch("tools.run_subprocess", return_value=completed) as mock_run:
            result = tools.execute_command("python -V", timeout=33)

        mock_run.assert_called_once_with("python -V", shell=True, timeout=33)
        self.assertNotIn("workon", mock_run.call_args.args[0])
        self.assertIn("Exit Code: 0", result)
        self.assertIn("Python 3.11.0", result)
        self.assertEqual(len(memory.steps), 1)
        self.assertTrue(memory.steps[-1].success)

    def test_execute_python_poc_uses_configured_python_and_workspace_cwd(self):
        memory = ShortMemory()
        completed = subprocess.CompletedProcess(
            args=["C:/venv/python.exe", "temp.py"],
            returncode=0,
            stdout="flag{demo}\n",
            stderr="",
        )
        workspace = Path(tools.__file__).parent / "workspace"

        with patch("tools.get_memory", return_value=memory), patch(
            "tools.get_venv_python", return_value="C:/venv/python.exe"
        ), patch("tools.run_subprocess", return_value=completed) as mock_run:
            result = tools.execute_python_poc("print('demo')", timeout=9)

        command = mock_run.call_args.args[0]
        self.assertEqual(command[0], "C:/venv/python.exe")
        self.assertTrue(command[1].endswith(".py"))
        self.assertEqual(Path(command[1]).parent, workspace)
        self.assertEqual(mock_run.call_args.kwargs["timeout"], 9)
        self.assertEqual(mock_run.call_args.kwargs["cwd"], workspace)
        self.assertFalse(Path(command[1]).exists())
        self.assertIn("flag{demo}", result)
        self.assertTrue(memory.steps[-1].success)

    def test_python_runner_reuses_shared_runtime(self):
        completed = subprocess.CompletedProcess(
            args=["C:/venv/python.exe", "script.py", "--flag"],
            returncode=0,
            stdout="runner-ok",
            stderr="",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = Path(tmpdir) / "sample.py"
            script_path.write_text("print('ok')\n", encoding="utf-8")

            with patch("utils.python_runner.get_venv_python", return_value="C:/venv/python.exe"), patch(
                "utils.python_runner.run_subprocess", return_value=completed
            ) as mock_run:
                exit_code, stdout, stderr = python_runner.run_python_script(str(script_path), args=["--flag"], timeout=21)

        mock_run.assert_called_once_with(
            ["C:/venv/python.exe", str(script_path.resolve()), "--flag"],
            timeout=21,
            cwd=script_path.resolve().parent,
        )
        self.assertEqual((exit_code, stdout, stderr), (0, "runner-ok", ""))

    def test_fenjing_cli_uses_shared_runtime(self):
        completed = subprocess.CompletedProcess(
            args=["C:/venv/python.exe", "-m", "fenjing", "scan"],
            returncode=0,
            stdout="done",
            stderr="",
        )

        with patch("toolkit.fenjing.get_venv_python", return_value="C:/venv/python.exe"), patch(
            "toolkit.fenjing.run_subprocess", return_value=completed
        ) as mock_run:
            result = fenjing._run_fenjing_cli(["scan", "--url", "http://target.local"], timeout=55)

        self.assertIs(result, completed)
        mock_run.assert_called_once_with(
            ["C:/venv/python.exe", "-m", "fenjing", "scan", "--url", "http://target.local"],
            timeout=55,
            cwd=fenjing.FENJING_PATH,
        )


class ToolWrapperContractTests(unittest.TestCase):
    def test_sqlmap_wrapper_keeps_string_return_and_memory_failure_semantics(self):
        memory = ShortMemory()
        result_obj = SimpleNamespace(success=False, stdout="no injection", stderr="blocked by waf")
        memory_meta = {
            "action_id": "sqlmap-action",
            "action_type": "sqlmap_scan",
            "expected_tool": "sqlmap",
            "canonical_tool": "sqlmap",
        }

        with patch("tools.get_memory", return_value=memory), patch("tools.TOOLKIT_AVAILABLE", True), patch(
            "tools.sqlmap_scan", return_value=result_obj
        ):
            result = tools.sqlmap_scan_url("http://target.local?id=1", memory_meta=memory_meta, batch=True)

        self.assertIsInstance(result, str)
        self.assertEqual(result, "[SQLMap] http://target.local?id=1\nblocked by waf")
        self.assertEqual(len(memory.steps), 1)
        step = memory.steps[-1]
        self.assertFalse(step.success)
        self.assertEqual(step.action_id, "sqlmap-action")
        self.assertEqual(step.expected_tool, "sqlmap")

    def test_dirsearch_wrapper_keeps_string_return_and_memory_success_semantics(self):
        memory = ShortMemory()
        result_obj = SimpleNamespace(success=True, stdout="200 GET /admin", stderr="")
        memory_meta = {
            "action_id": "dirsearch-action",
            "action_type": "dir_scan",
            "expected_tool": "dirsearch",
            "canonical_tool": "dirsearch",
        }

        with patch("tools.get_memory", return_value=memory), patch("tools.TOOLKIT_AVAILABLE", True), patch(
            "tools.dirsearch_scan", return_value=result_obj
        ):
            result = tools.dirsearch_scan_url("http://target.local/", memory_meta=memory_meta, extensions=["php"])

        self.assertIsInstance(result, str)
        self.assertEqual(result, "[Dirsearch] http://target.local/\n200 GET /admin")
        self.assertEqual(len(memory.steps), 1)
        step = memory.steps[-1]
        self.assertTrue(step.success)
        self.assertEqual(step.action_id, "dirsearch-action")
        self.assertEqual(step.expected_tool, "dirsearch")
        self.assertIn("发现目录", step.key_findings)


if __name__ == "__main__":
    unittest.main()
