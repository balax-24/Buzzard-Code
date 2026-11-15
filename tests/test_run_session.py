"""Unit tests for RunSession's approval rules, which every front end shares."""

import pytest

from agent import run_session
from agent.run_session import ALLOW, ALLOW_SESSION, DENY, RunSession
from tools import mcp_client


def session(answer):
    asked = []

    def ask(request):
        asked.append(request)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return RunSession(None, None, None, {}, ask_approval=ask), asked


def test_allow_and_deny_are_counted():
    allowed, _ = session(ALLOW)
    assert allowed.approve("file_edit", {"path": "a.py"}, None) is True
    denied, _ = session(DENY)
    assert denied.approve("file_edit", {"path": "a.py"}, None) is False
    assert (allowed.approvals_granted, denied.approvals_denied) == (1, 1)


def test_allow_session_remembers_only_rule_based_actions():
    s, asked = session(ALLOW_SESSION)
    assert s.approve("file_edit", {"path": "a.py"}, None)
    assert s.approve("file_edit", {"path": "b.py"}, None)
    assert len(asked) == 1 and asked[0].session_rule == "file edits"
    assert s.approve("terminal.execute", {"command": "rm -rf build && ls"}, None)
    assert s.approve("terminal.execute", {"command": "rm -rf build && ls"}, None)
    assert len(asked) == 3  # a command with shell operators is never remembered


def test_plan_mode_and_cancel_deny_without_asking():
    s, asked = session(ALLOW)
    s.plan_mode = True
    assert s.approve("file_edit", {"path": "a.py"}, None) is False
    s.plan_mode = False
    s.cancel()
    assert s.approve("file_edit", {"path": "a.py"}, None) is False
    assert asked == [] and s.approvals_denied == 2


@pytest.mark.parametrize("answer", [RuntimeError("UI crashed"), "maybe", None])
def test_broken_or_unknown_answers_fail_closed(answer):
    s, _ = session(answer)
    assert s.approve("file_edit", {"path": "a.py"}, None) is False


def test_mcp_auto_approve_still_respects_plan_mode(monkeypatch):
    manager = mcp_client.McpManager()
    manager.auto_approved.add("mcp.docs.search")
    monkeypatch.setattr(mcp_client, "_manager", manager)
    s, asked = session(DENY)
    assert s.approve("mcp.docs.search", {}, None) is True and asked == []
    s.plan_mode = True
    assert s.approve("mcp.docs.search", {}, None) is False


def test_only_one_run_at_a_time(monkeypatch):
    s, _ = session(ALLOW)
    s._run_lock.acquire()
    try:
        outcome = s.run("fix it", target="localhost", scope=["localhost"])
        assert outcome.status == "rejected" and "already running" in outcome.error
    finally:
        s._run_lock.release()


def test_loop_crash_becomes_a_failed_outcome(monkeypatch):
    s, _ = session(ALLOW)

    class Boom:
        def __init__(self, **kwargs):
            raise RuntimeError("provider exploded")

    monkeypatch.setattr("agent.loop.AgentLoop", Boom)
    outcome = s.run("fix it", target="localhost", scope=["localhost"])
    assert outcome.status == "failed" and "provider exploded" in outcome.error
    assert not s.is_running
