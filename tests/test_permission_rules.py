"""Permission rule precedence and PolicyEngine integration tests."""

import json
from pathlib import Path

import pytest

from agent.run_session import RunSession
from security.approvals import ApprovalGate
from security.permission_rules import PermissionConfigError, permission_effect
from security.policy import PolicyEngine
from tools.filesystem import set_active_workspace


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    set_active_workspace(str(tmp_path))
    user_rules = tmp_path / "user-permissions.json"
    monkeypatch.setattr("security.permission_rules.user_permissions_path", lambda: user_rules)
    yield tmp_path
    set_active_workspace(None)


def _write_rules(path: Path, *, rules=None, mode="default") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "mode": mode, "rules": rules or []}), encoding="utf-8")


def test_user_rules_allow_pattern_matches_and_deny_wins(workspace: Path) -> None:
    user_file = workspace / "user-permissions.json"
    _write_rules(user_file, rules=[
        {"effect": "allow", "tool": "terminal.execute", "argument": "command", "pattern": "pytest *"},
        {"effect": "deny", "tool": "terminal.execute", "argument": "command", "pattern": "pytest tests/private*"},
    ])

    assert permission_effect("terminal.execute", {"command": "pytest tests/test_ok.py"}, workspace) == "allow"
    assert permission_effect("terminal.execute", {"command": "pytest tests/private/test_secret.py"}, workspace) == "deny"


def test_project_rules_can_tighten_but_cannot_allow_user_denial(workspace: Path) -> None:
    _write_rules(workspace / "user-permissions.json", rules=[{"effect": "deny", "tool": "file_write"}])
    _write_rules(workspace / ".buzzard" / "permissions.json", rules=[{"effect": "allow", "tool": "file_write"}])
    assert permission_effect("file_write", {}, workspace) == "deny"

    _write_rules(workspace / "user-permissions.json", rules=[{"effect": "allow", "tool": "file_write"}])
    _write_rules(workspace / ".buzzard" / "permissions.json", rules=[{"effect": "ask", "tool": "file_write"}])
    assert permission_effect("file_write", {}, workspace) == "ask"


def test_modes_accept_edits_but_ask_commands(workspace: Path) -> None:
    _write_rules(workspace / "user-permissions.json", mode="accept_edits_ask_commands")
    assert permission_effect("file_edit", {"path": "app.py"}, workspace) == "allow"
    assert permission_effect("terminal.execute", {"command": "pytest -q"}, workspace) == "ask"


def test_policy_engine_applies_allow_and_deny_without_weakening_scope(workspace: Path) -> None:
    _write_rules(workspace / "user-permissions.json", rules=[
        {"effect": "allow", "tool": "file_edit"},
        {"effect": "deny", "tool": "terminal.execute", "argument": "command", "pattern": "rm *"},
    ])
    asked = []
    gate = ApprovalGate(approval_callback=lambda *args: asked.append(args) or False)
    engine = PolicyEngine(["localhost"], approval_gate=gate)

    allowed = engine.evaluate("file_edit", {"path": "app.py"})
    denied = engine.evaluate("terminal.execute", {"command": "rm -rf build"})
    out_of_scope = engine.evaluate("http.request", {"url": "https://outside.example/"})

    assert allowed.permitted is True and allowed.requires_approval is False
    assert denied.permitted is False and "Permission rule denied" in denied.reason
    assert out_of_scope.permitted is False and "outside" in out_of_scope.reason
    assert asked == []


def test_user_allow_cannot_bypass_plan_mode(workspace: Path) -> None:
    _write_rules(workspace / "user-permissions.json", rules=[{"effect": "allow", "tool": "file_edit"}])
    asked = []
    session = RunSession(None, None, None, {}, ask_approval=lambda request: asked.append(request) or "deny")
    session.plan_mode = True
    engine = PolicyEngine(
        ["localhost"],
        approval_gate=ApprovalGate(
            approval_callback=lambda tool, args, metadata: session.approve(tool, args, metadata),
        ),
        allow_permission_rules=False,
    )

    decision = engine.evaluate("file_edit", {"path": "app.py"})

    assert decision.permitted is False
    assert decision.requires_approval is True
    assert asked == [] and session.approvals_denied == 1


def test_project_ask_overrides_user_allow_and_invalid_rules_fail_closed(workspace: Path) -> None:
    _write_rules(workspace / "user-permissions.json", rules=[{"effect": "allow", "tool": "file_write"}])
    _write_rules(workspace / ".buzzard" / "permissions.json", rules=[{"effect": "ask", "tool": "file_write"}])
    asked = []
    engine = PolicyEngine(["localhost"], approval_gate=ApprovalGate(
        approval_callback=lambda *args: asked.append(args) or False,
    ))
    decision = engine.evaluate("file_write", {"path": "app.py", "content": "x"})
    assert decision.permitted is False and decision.requires_approval is True
    assert len(asked) == 1

    (workspace / ".buzzard" / "permissions.json").write_text("{broken", encoding="utf-8")
    failed_closed = engine.evaluate("file_read", {"path": "app.py"})
    assert failed_closed.permitted is False
    assert "Permission rules are invalid" in failed_closed.reason


def test_malformed_rule_has_actionable_error(workspace: Path) -> None:
    _write_rules(workspace / ".buzzard" / "permissions.json", rules=[{"tool": "file_write"}])
    with pytest.raises(PermissionConfigError, match="effect must be allow, ask or deny"):
        permission_effect("file_write", {}, workspace)

    (workspace / ".buzzard" / "permissions.json").write_text(
        json.dumps({"version": 1, "mode": [], "rules": []}), encoding="utf-8",
    )
    with pytest.raises(PermissionConfigError, match="mode must be one of"):
        permission_effect("file_write", {}, workspace)
