"""Integrity and repository-state tests for Evidence Bundles."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner

from agent.run_session import RunSession
from cli.main import main
from tools.filesystem import set_active_workspace
from verification.evidence_bundle import create_evidence_bundle, verify_evidence_bundle


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True)


def _repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Evidence Test")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "baseline")
    source.write_text("value = 2\n", encoding="utf-8")
    return tmp_path


def test_bundle_verifies_unchanged_tree_and_rejects_changed_tree(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    verification = SimpleNamespace(
        passed=True,
        requires_action=False,
        test_command="pytest -q",
        test_exit_code=0,
        test_environment="host",
        lint_command=None,
        lint_status="not configured",
    )
    bundle_path = create_evidence_bundle(
        workspace=root,
        session_id="task-safe-id",
        task="Fix app.py with token=example-secret-value",
        verification=verification,
        approvals_granted=2,
        approvals_denied=0,
        model="test-model",
        evidence_report="Tests passed",
    )

    assert bundle_path.relative_to(root).as_posix() == ".buzzard/evidence/task-safe-id.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert "example-secret-value" not in bundle_path.read_text(encoding="utf-8")
    assert bundle["verification"]["changed_line_coverage"] is None
    assert verify_evidence_bundle(bundle_path, root)["valid"] is True
    cli_result = CliRunner().invoke(main, ["verify", str(bundle_path), "--workspace", str(root)])
    assert cli_result.exit_code == 0
    assert "Bundle matches the current repository state" in cli_result.output

    (root / "app.py").write_text("value = 3\n", encoding="utf-8")
    result = verify_evidence_bundle(bundle_path, root)
    assert result["valid"] is False
    assert result["repository_matches"] is False


def test_bundle_rejects_tampering_and_cli_reports_state_mismatch(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    bundle_path = create_evidence_bundle(
        workspace=root,
        session_id="task-verify",
        task="Fix app.py",
        verification=SimpleNamespace(passed=True),
        approvals_granted=0,
        approvals_denied=0,
        model="test-model",
        evidence_report=None,
    )
    tampered = json.loads(bundle_path.read_text(encoding="utf-8"))
    tampered["task"] = "modified after writing"
    bundle_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert "integrity hash" in verify_evidence_bundle(bundle_path, root)["reason"]

    result = CliRunner().invoke(main, ["verify", str(bundle_path), "--workspace", str(root)])
    assert result.exit_code == 1
    assert "integrity hash" in result.output


def test_run_session_attaches_generated_bundle_to_evidence_report(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    set_active_workspace(str(root))
    session = RunSession(None, None, None, {}, ask_approval=lambda _request: "deny")
    verification = SimpleNamespace(
        passed=True,
        requires_action=False,
        test_command="pytest -q",
        test_exit_code=0,
        test_environment="host",
        lint_status="not configured",
    )
    try:
        report = session._evidence_report(
            SimpleNamespace(last_verification=verification), "Fix app.py", "task-run-session",
        )
        assert report is not None and "Evidence Bundle:" in report
        assert session.last_evidence_bundle is not None
        assert Path(session.last_evidence_bundle).is_file()
    finally:
        set_active_workspace(None)
