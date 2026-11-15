"""Tests for the reproduce-first check (roadmap C1), using real pytest runs and git worktrees."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from verification.reproduce_first import (
    changed_test_files,
    check_directory,
    check_reproduction,
    is_bug_fix_task,
    junit_results,
    reproduce_mode,
    split_pytest_command,
    with_junit,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
PYTHON = sys.executable


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def run_in(directory: Path, command: str) -> int:
    return subprocess.run(command, cwd=directory, shell=True, capture_output=True).returncode


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    (root / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (root / "test_calc.py").write_text("from calc import add\n\ndef test_other():\n    assert add(2, 0) == 2\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "buggy add")
    return root


def run_after(root: Path) -> Path:
    """The gate's own run: tests on the fixed working tree, writing a JUnit report."""
    after = check_directory(root) / "after-junit"
    after.parent.mkdir(parents=True, exist_ok=True)
    command = with_junit(f'"{PYTHON}" -m pytest -q -p no:cacheprovider', after)
    assert run_in(root, command) == 0
    return after


def check(root: Path, approve=None):
    after = run_after(root)
    return check_reproduction(root, f'"{PYTHON}" -m pytest -q -p no:cacheprovider', PYTHON, after, approve, run_in)


def test_bug_fix_detection_and_settings():
    assert is_bug_fix_task("Fix the bug in calc.py")
    assert is_bug_fix_task("tests are failing on login")
    assert not is_bug_fix_task("Add a dark mode toggle")
    assert reproduce_mode({}) == ("warn", None)
    assert reproduce_mode({"reproduce_first": "require"}) == ("require", None)
    assert reproduce_mode({"reproduce_first": "always"})[0] is None


def test_command_splitting():
    assert split_pytest_command(".venv/bin/python -m pytest -q", "x") == (".venv/bin/python", " -q")
    assert split_pytest_command("pytest -x", ".venv/bin/python") == (".venv/bin/python", " -x")
    assert split_pytest_command("npm test", "python") is None
    assert split_pytest_command('"C:/Program Files/py/python.exe" -m pytest', "x") == ('"C:/Program Files/py/python.exe"', "")


def test_junit_counts_failures_not_errors(tmp_path):
    report = tmp_path / "r"
    report.write_text(
        '<testsuites><testsuite>'
        '<testcase classname="t" name="ok"/>'
        '<testcase classname="t" name="bad"><failure message="x"/></testcase>'
        '<testcase classname="t" name="broken"><error message="import"/></testcase>'
        '<testcase classname="t" name="skip"><skipped/></testcase>'
        '</testsuite></testsuites>', encoding="utf-8")
    assert junit_results(report) == ({"t::bad"}, {"t::ok"})
    with pytest.raises(ValueError):
        junit_results(tmp_path / "missing")


def test_reproduced_when_a_new_test_fails_before_and_passes_after(repo):
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    with (repo / "test_calc.py").open("a", encoding="utf-8") as handle:
        handle.write("\ndef test_add_two_numbers():\n    assert add(2, 3) == 5\n")
    result = check(repo)
    assert result.status == "reproduced", result.reason
    assert result.reproduced_tests == ["test_calc::test_add_two_numbers"]
    assert subprocess.run(["git", "-C", str(repo), "worktree", "list"], capture_output=True, text=True).stdout.count("\n") == 1


def test_not_reproduced_when_tests_already_passed_before_the_fix(repo):
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "test_calc.py").write_text("from calc import add\n\ndef test_zero():\n    assert add(2, 0) == 2\n", encoding="utf-8")
    result = check(repo)
    assert result.status == "not_reproduced"
    assert "no test failed" in result.reason


def test_a_collection_error_on_the_original_code_is_not_proof(repo):
    (repo / "pricing.py").write_text("def price():\n    return 1\n", encoding="utf-8")
    (repo / "test_pricing.py").write_text("from pricing import price\n\ndef test_price():\n    assert price() == 1\n", encoding="utf-8")
    result = check(repo)
    assert result.status == "not_reproduced"  # the import error before the fix is an error, not a failure


def test_declined_approval_and_changed_test_listing(repo):
    (repo / "test_new.py").write_text("def test_x():\n    pass\n", encoding="utf-8")
    assert changed_test_files(repo) == ["test_new.py"]
    approvals = []
    result = check(repo, approve=lambda command: approvals.append(command) or False)
    assert result.status == "not_checked" and "not approved" in result.reason
    assert approvals and "-m pytest" in approvals[0] and "--junitxml=" in approvals[0]


def test_gate_require_mode_rejects_an_unreproduced_bug_fix(repo, monkeypatch):
    from verification.coding_verifier import CodingVerifier

    (repo / ".buzzard").mkdir()
    (repo / ".buzzard" / "project.json").write_text(
        '{"test_command": "\\"%s\\" -m pytest -q -p no:cacheprovider", "reproduce_first": "require"}'
        % PYTHON.replace("\\", "/"), encoding="utf-8")
    (repo / ".gitignore").write_text(".buzzard/\n", encoding="utf-8")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    verifier = CodingVerifier(workspace=str(repo), command_approver=lambda command: True)
    monkeypatch.setattr(verifier.sandbox, "execute",
                        lambda command, timeout=None, **kw: {"exit_code": run_in(repo, command), "stdout": "", "stderr": ""})
    result = verifier.verify_task("Fix the bug in add")
    assert not result.passed and "no test fails on the original code" in result.message
    assert result.reproduction["status"] == "not_reproduced"

    (repo / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    result = verifier.verify_task("Fix the bug in add")
    assert result.passed, result.message
    assert result.reproduction["status"] == "reproduced"
