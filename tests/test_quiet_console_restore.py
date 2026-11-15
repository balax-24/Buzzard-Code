"""Regression: a quiet AgentLoop run must hand the shared console back afterwards."""

import io

import pytest

from agent.loop import AgentLoop
from cli.renderer import console


def test_quiet_run_restores_the_shared_console(monkeypatch):
    before = (console._file, console._force_terminal)
    agent = AgentLoop.__new__(AgentLoop)
    agent.quiet = True
    agent.subagent_role = "explore"  # skips parent registration; only the wrapper is under test

    def fake_run(self, *args, **kwargs):
        console.file = io.StringIO()
        console.force_terminal = False
        return {"status": "completed"}

    monkeypatch.setattr(AgentLoop, "_run", fake_run)
    assert agent.run("goal", "localhost") == {"status": "completed"}
    assert (console._file, console._force_terminal) == before


def test_quiet_run_restores_the_console_when_it_fails(monkeypatch):
    before = (console._file, console._force_terminal)
    agent = AgentLoop.__new__(AgentLoop)
    agent.quiet = True
    agent.subagent_role = "explore"

    def broken(self, *args, **kwargs):
        console.file = io.StringIO()
        raise RuntimeError("model failed")

    monkeypatch.setattr(AgentLoop, "_run", broken)
    with pytest.raises(RuntimeError):
        agent.run("goal", "localhost")
    assert (console._file, console._force_terminal) == before
