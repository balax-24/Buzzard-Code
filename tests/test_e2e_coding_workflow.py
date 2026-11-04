"""
End-to-end demonstration and regression test for Buzzard Code autonomous coding workflow.

Verifies:
1. Repository discovery and active workspace scoping.
2. Manifest and test runner detection (pytest).
3. Pre-fix test execution and failure capture.
4. File inspection with line numbers (file_view).
5. Surgical search-and-replace editing with diff verification (file_edit).
6. Post-fix test execution and pass verification (ControlledHostSandbox).
7. Working tree git diff inspection (git_diff).
8. CodingVerifier authoritative completion gate.
"""

import sys
import subprocess
import tempfile
import pytest
from pathlib import Path

from security_agent.tools.filesystem import set_active_workspace, get_active_workspace, file_view, file_edit, file_read
from security_agent.tools.git_tools import git_status, git_diff, git_log
from security_agent.sandbox.container import ControlledHostSandbox
from security_agent.verification.coding_verifier import CodingVerifier, detect_project_test_runner


def test_e2e_autonomous_coding_workflow():
    old_ws = get_active_workspace()
    temp_dir = tempfile.TemporaryDirectory()
    repo_path = Path(temp_dir.name).resolve()

    try:
        # Step 1: Initialize git repository
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Buzzard Test"], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "buzzard@test.local"], cwd=str(repo_path), check=True, capture_output=True)

        # Step 2: Create a buggy module and test suite
        calc_code = (
            "def add(a, b):\n"
            "    # Buggy implementation\n"
            "    return a - b\n"
        )
        test_code = (
            "from calculator import add\n\n"
            "def test_add():\n"
            "    assert add(2, 3) == 5\n"
        )
        pyproject = (
            "[project]\n"
            "name = 'calculator'\n"
            "version = '0.1.0'\n"
        )

        (repo_path / "calculator.py").write_text(calc_code, encoding="utf-8")
        (repo_path / "test_calculator.py").write_text(test_code, encoding="utf-8")
        (repo_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")

        subprocess.run(["git", "add", "."], cwd=str(repo_path), check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit with buggy calculator"], cwd=str(repo_path), check=True, capture_output=True)

        # Scope active workspace to this repo
        set_active_workspace(repo_path)
        assert get_active_workspace() == str(repo_path)

        # Step 3: Test runner detection
        runner_info = detect_project_test_runner(str(repo_path))
        assert runner_info["detected"] is True
        assert runner_info["runner"] == "pytest"

        # Step 4: Run initial tests (expect failure)
        sandbox = ControlledHostSandbox(workspace=str(repo_path))
        test_cmd = f'"{sys.executable}" -m pytest -q test_calculator.py'
        res_fail = sandbox.execute(test_cmd)
        fail_code = res_fail["exit_code"] if isinstance(res_fail, dict) else res_fail.exit_code
        fail_out = (res_fail.get("stdout", "") + res_fail.get("stderr", "")) if isinstance(res_fail, dict) else (res_fail.stdout + res_fail.stderr)
        assert fail_code != 0
        assert "assert -1 == 5" in fail_out

        # Step 5: Completion gate MUST reject before fix
        verifier = CodingVerifier(workspace=str(repo_path))
        gate_before = verifier.verify_task("Fix the bug in calculator.py", auto_run_tests=False)
        assert gate_before.passed is False
        assert "No modifications were made" in gate_before.message

        # Step 6: Inspect file content with line ranges
        view_result = file_view("calculator.py", start_line=1, end_line=3)
        assert "1 | def add(a, b):" in view_result
        assert "return a - b" in view_result

        # Step 7: Apply surgical edit using file_edit
        edit_result = file_edit(
            path="calculator.py",
            old_str="    return a - b",
            new_str="    return a + b"
        )
        assert "Successfully edited 'calculator.py'" in edit_result
        assert "-    return a - b" in edit_result
        assert "+    return a + b" in edit_result

        # Step 8: Re-run test suite (expect green pass)
        res_pass = sandbox.execute(test_cmd)
        pass_code = res_pass["exit_code"] if isinstance(res_pass, dict) else res_pass.exit_code
        pass_out = (res_pass.get("stdout", "") + res_pass.get("stderr", "")) if isinstance(res_pass, dict) else (res_pass.stdout + res_pass.stderr)
        assert pass_code == 0
        assert "1 passed" in pass_out

        # Step 9: Inspect Git Diff
        diff_output = git_diff()
        assert "-    return a - b" in diff_output
        assert "+    return a + b" in diff_output

        # Step 10: Completion gate MUST now pass with verified green test suite
        import unittest.mock
        mock_sandbox_res = {"exit_code": 0, "stdout": "1 passed in 0.01s", "stderr": ""}
        with unittest.mock.patch.object(verifier.sandbox, "execute", return_value=mock_sandbox_res):
            gate_after = verifier.verify_task("Fix the bug in calculator.py", auto_run_tests=True)
            assert gate_after.passed is True
            assert gate_after.requires_action is False
            assert "All verification gates passed" in gate_after.message

    finally:
        set_active_workspace(old_ws)
        temp_dir.cleanup()
