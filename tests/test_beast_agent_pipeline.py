"""
Unit & integration tests for Buzzard Code Autonomous Engineering Beast Agent Pipeline:
- TestImpactSelector
- AtomicCodeEditor
- AutonomousSelfHealingLoop
- CodingModelRouter
- AutonomousEngineer
"""

from pathlib import Path
import pytest

from verification.test_selector import TestImpactSelector
from coding.atomic_editor import AtomicCodeEditor, EditOperation
from coding.self_healing import AutonomousSelfHealingLoop
from model.coding_router import CodingModelRouter
from agent.autonomous_engineer import AutonomousEngineer


@pytest.fixture
def test_workspace(tmp_path: Path):
    ws = tmp_path / "test_repo"
    ws.mkdir()

    # Create dummy project files
    src_dir = ws / "pkg"
    src_dir.mkdir()
    (src_dir / "__init__.py").write_text("", encoding="utf-8")

    (src_dir / "auth.py").write_text(
        "class TokenManager:\n"
        "    def generate_token(self, user_id: str) -> str:\n"
        "        return f'token-{user_id}'\n",
        encoding="utf-8"
    )

    (src_dir / "api.py").write_text(
        "from pkg.auth import TokenManager\n\n"
        "def login_endpoint(user_id: str):\n"
        "    mgr = TokenManager()\n"
        "    return mgr.generate_token(user_id)\n",
        encoding="utf-8"
    )

    test_dir = ws / "tests"
    test_dir.mkdir()
    (test_dir / "test_auth.py").write_text(
        "from pkg.auth import TokenManager\n\n"
        "def test_token_gen():\n"
        "    m = TokenManager()\n"
        "    assert m.generate_token('alice') == 'token-alice'\n",
        encoding="utf-8"
    )

    (test_dir / "test_api.py").write_text(
        "from pkg.api import login_endpoint\n\n"
        "def test_login():\n"
        "    assert login_endpoint('bob') == 'token-bob'\n",
        encoding="utf-8"
    )

    (ws / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")

    return ws


def test_test_impact_selector(test_workspace: Path):
    selector = TestImpactSelector(test_workspace)
    assert selector.detect_runner() == "pytest"

    # Selecting tests for auth.py should find test_auth.py and downstream test_api.py
    selected = selector.select_tests_for_files(["pkg/auth.py"])
    assert "tests/test_auth.py" in selected.targeted_test_files
    assert selected.targeted_command is not None
    assert "pytest" in selected.targeted_command
    assert "tests/test_auth.py" in selected.targeted_command


def test_atomic_code_editor_syntax_guard(test_workspace: Path):
    editor = AtomicCodeEditor(test_workspace)

    # 1. Attempt to inject invalid Python syntax (missing closing paren)
    bad_op = EditOperation(
        file_path="pkg/auth.py",
        new_full_content="def broken_syntax(:\n    return 42\n"
    )

    res = editor.apply_transaction([bad_op])
    assert not res.success
    assert len(res.syntax_errors) > 0
    assert "SyntaxError" in res.syntax_errors[0]

    # Disk must NOT be corrupted
    original = (test_workspace / "pkg/auth.py").read_text(encoding="utf-8")
    assert "class TokenManager" in original
    assert "broken_syntax" not in original


def test_atomic_code_editor_successful_transaction(test_workspace: Path):
    editor = AtomicCodeEditor(test_workspace)

    # Valid replacement
    valid_op = EditOperation(
        file_path="pkg/auth.py",
        target_pattern="return f'token-{user_id}'",
        replacement_text="return f'bearer-{user_id}'"
    )

    res = editor.apply_transaction([valid_op])
    assert res.success
    assert "pkg/auth.py" in res.modified_files

    # Check updated content
    updated = (test_workspace / "pkg/auth.py").read_text(encoding="utf-8")
    assert "return f'bearer-{user_id}'" in updated


def test_self_healing_pytest_diagnostics(test_workspace: Path):
    healer = AutonomousSelfHealingLoop(test_workspace)

    sample_pytest_output = (
        "=================================== FAILURES ===================================\n"
        "________________________________ test_token_gen ________________________________\n"
        "tests/test_auth.py:5: in test_token_gen\n"
        "    assert m.generate_token('alice') == 'bearer-alice'\n"
        "E   AssertionError: assert 'token-alice' == 'bearer-alice'\n"
        "E     - bearer-alice\n"
        "E     + token-alice\n"
        "=========================== short test summary info ============================\n"
        "FAILED tests/test_auth.py::test_token_gen - AssertionError: assert 'token-alice' == 'bearer-alice'\n"
    )

    plan = healer.create_repair_plan(sample_pytest_output)
    assert plan.failure_count >= 1
    diag = plan.diagnostics[0]
    assert diag.test_function == "test_token_gen"
    assert "test_auth.py" in diag.test_file
    assert "token-alice" in diag.error_message


def test_coding_model_router():
    router = CodingModelRouter()

    # Simple search -> fast
    assert router.classify_task_tier("where is the login function?") == "fast"

    # Standard feature -> standard
    assert router.classify_task_tier("Add email validation to user registration") == "standard"

    # High risk / architectural -> frontier
    assert router.classify_task_tier("Audit authentication security boundary against auth bypass cve") == "frontier"
    assert router.classify_task_tier("Refactor auth", risk_level="critical") == "frontier"
    assert router.classify_task_tier("Refactor core", affected_files_count=6) == "frontier"


def test_autonomous_engineer_integration(test_workspace: Path):
    engineer = AutonomousEngineer(test_workspace)

    # 1. Plan workflow for auth modification
    plan = engineer.plan("Update TokenManager to support refresh tokens")
    assert plan.impact is not None
    assert len(plan.steps) == 6
    assert plan.model_recommended is not None

    # 2. Atomic edit
    op = EditOperation(
        file_path="pkg/auth.py",
        target_pattern="return f'token-{user_id}'",
        replacement_text="return f'jwt-{user_id}'"
    )
    res = engineer.apply_edits_atomically([op])
    assert res.success

    # Memory graph updated
    assert (test_workspace / "pkg/auth.py").exists()
