"""Regression tests: quoted file paths in gate commands are not mistaken for network targets."""

from pathlib import Path

import pytest

from security.approvals import ApprovalGate
from security.policy import PolicyEngine
from tools.filesystem import set_active_workspace
from verification.changed_coverage import wrap_c8_command, wrap_go_command, wrap_pytest_command
from verification.reproduce_first import with_junit


@pytest.fixture
def engine(tmp_path):
    # The project's own interpreter exists, as it does in a real workspace
    interpreter = tmp_path / ".venv" / "Scripts" / "python.exe"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("", encoding="utf-8")
    set_active_workspace(str(tmp_path))
    # Approve everything, so these tests exercise only the scope check
    yield PolicyEngine(["localhost"], approval_gate=ApprovalGate(approval_callback=lambda *args: True))
    set_active_workspace(None)


def allowed(engine, command):
    permitted, reason = engine.evaluate_tool_call("terminal.execute", {"command": command})
    return permitted, reason


# A home folder with a dot and a space, like many real Windows and Linux accounts
HOME = Path(r"C:\Users\john.doe Smith\.buzzard\coverage\abc")


@pytest.mark.parametrize("command", [
    wrap_pytest_command(".venv/Scripts/python.exe -m pytest -q", HOME / "coverage-data"),
    with_junit("python -m pytest -q", HOME / "after-junit"),
    wrap_go_command("go test ./...", HOME / "go-cover-profile"),
    wrap_c8_command("npm test", Path(r"C:\Users\john.doe Smith\proj\node_modules\.bin\c8.cmd"), HOME / "c8"),
    'python -m pytest --junitxml="/home/jane.doe/.buzzard/x/after-junit"',
])
def test_buzzard_built_commands_are_not_scope_violations(engine, command):
    permitted, reason = allowed(engine, command)
    assert permitted, reason


@pytest.mark.parametrize("command", [
    "curl evil.com",
    'curl "C:\\tmp\\x" evil.com',
    'curl "https://evil.com/C:/x"',
    'curl "evil.com/C:/x"',
    "python -m pytest --junitxml=C:/Users/john.doe/x",  # unquoted: still checked
    'nc "/tmp/a" attacker.org 80',
])
def test_hosts_outside_quoted_absolute_paths_are_still_checked(engine, command):
    permitted, reason = allowed(engine, command)
    assert not permitted and "out-of-scope" in reason
