"""Tests for `buzzard gate` and the Buzzard Verify GitHub Action (roadmap F4)."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from cli.main import main
from verification.pr_gate import DEFAULT_GOAL, GateError, comment_body, gate_goal, run_pr_gate

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "shop"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@t")
    git(root, "config", "user.name", "T")
    (root / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (root / ".buzzard").mkdir()
    (root / ".buzzard" / "project.json").write_text(json.dumps({
        "test_command": f'"{sys.executable}" -m pytest -q -p no:cacheprovider', "coverage": "off"}), encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "start")
    git(root, "checkout", "-qb", "feature")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    return root


def commit(root, message, files):
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


TEST = "from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n"


def test_a_good_pull_request_passes_and_head_is_restored(repo):
    head = commit(repo, "fix add", {"calc.py": "def add(a, b):\n    return a + b\n", "test_calc.py": TEST})
    result = run_pr_gate(repo, "main", title="Fix add so the tests pass")
    assert result.passed, result.message
    assert git(repo, "rev-parse", "HEAD") == head and git(repo, "status", "--porcelain") == ""
    assert "exit 0" in result.report
    assert result.verification["reproduction"]["status"] == "reproduced"  # the fix title ran reproduce-first
    assert comment_body(result).startswith("## ✅ Buzzard Verify passed")


def test_a_broken_pull_request_fails_with_the_test_output(repo):
    head = commit(repo, "add a test that fails", {"test_calc.py": TEST})
    result = run_pr_gate(repo, "main")
    assert not result.passed and "Test suite failed" in result.message
    assert git(repo, "rev-parse", "HEAD") == head and git(repo, "status", "--porcelain") == ""
    body = comment_body(result)
    assert body.startswith("## ❌ Buzzard Verify failed") and "<details>" in body


def test_head_is_restored_even_when_the_gate_crashes(repo):
    head = commit(repo, "fix add", {"calc.py": "def add(a, b):\n    return a + b\n"})

    class Broken:
        def verify_task(self, goal):
            raise RuntimeError("gate crashed")

    with pytest.raises(RuntimeError, match="gate crashed"):
        run_pr_gate(repo, "main", verifier_factory=lambda path: Broken())
    assert git(repo, "rev-parse", "HEAD") == head and git(repo, "status", "--porcelain") == ""


def test_refuses_a_dirty_tree_and_an_unknown_base_and_handles_no_changes(repo):
    assert run_pr_gate(repo, "main").message.startswith("No changes")
    (repo / "calc.py").write_text("changed\n", encoding="utf-8")
    with pytest.raises(GateError, match="uncommitted changes"):
        run_pr_gate(repo, "main")
    git(repo, "checkout", "--", "calc.py")
    with pytest.raises(GateError, match="merge base"):
        run_pr_gate(repo, "no-such-branch")


def test_goal_uses_the_title_only_when_it_describes_a_change():
    assert gate_goal("Fix the cart total") == "Fix the cart total"
    assert gate_goal("Weekly sync notes") == DEFAULT_GOAL
    assert gate_goal(None) == DEFAULT_GOAL


def test_cli_exit_codes_json_and_report_file(repo, tmp_path):
    commit(repo, "fix add", {"calc.py": "def add(a, b):\n    return a + b\n", "test_calc.py": TEST})
    report = tmp_path / "comment.md"
    ok = CliRunner().invoke(main, ["gate", "--base", "main", "--workspace", str(repo), "--json", "--report-file", str(report)])
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.output)["passed"] is True and "Buzzard Verify passed" in report.read_text(encoding="utf-8")
    missing = CliRunner().invoke(main, ["gate", "--base", "nope", "--workspace", str(repo)])
    assert missing.exit_code == 2


def test_action_definition_runs_the_gate_and_comments():
    action = yaml.safe_load((ROOT / "packaging" / "public_action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) == {"base", "python-version", "comment", "github-token"}
    scripts = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
    assert 'buzzard gate --base "$BASE"' in scripts and "gh pr comment" in scripts
    assert action["outputs"]["passed"]["value"] == "${{ steps.gate.outputs.passed }}"
    # untrusted pull request text reaches the script only through environment variables
    for step in action["runs"]["steps"]:
        assert "github.event.pull_request.title" not in step.get("run", "")


def test_public_repo_contains_the_action(tmp_path):
    output = tmp_path / "public"
    built = subprocess.run([sys.executable, str(ROOT / "packaging" / "build_public_repo.py"), str(output)],
                           capture_output=True, text=True, check=False)
    assert built.returncode == 0, built.stderr
    assert (output / "action.yml").read_text(encoding="utf-8") == \
        (ROOT / "packaging" / "public_action.yml").read_text(encoding="utf-8")
