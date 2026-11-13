"""
Tests for project initialization and dynamic custom commands.
"""

import pytest
import json
from pathlib import Path
from core.project import (
    init_project,
    load_custom_commands,
    parse_markdown_command,
    render_custom_command_prompt,
)

def test_init_project(tmp_path):
    success, msg, created = init_project(target_dir=tmp_path)
    assert success is True
    assert (tmp_path / "buzzard.json").is_file()
    assert (tmp_path / ".buzzard" / "commands" / "scan.md").is_file()
    assert (tmp_path / ".buzzard" / "commands" / "audit.md").is_file()
    assert (tmp_path / ".buzzard" / "commands" / "recon.md").is_file()
    assert (tmp_path / ".buzzard" / "commands" / "explain.md").is_file()
    assert (tmp_path / ".gitignore").is_file()

def test_init_project_overwrite_protection(tmp_path):
    init_project(target_dir=tmp_path)
    # Attempting to re-init without force should fail
    success, msg, _ = init_project(target_dir=tmp_path, force=False)
    assert success is False
    assert "already initialized" in msg

    # Re-init with force should succeed
    success2, msg2, _ = init_project(target_dir=tmp_path, force=True)
    assert success2 is True

def test_parse_markdown_command():
    md = """---
description: Custom Exploit Scanner
args: [host, port]
---
Scan target {{host}} on port {{port}}.
"""
    parsed = parse_markdown_command(md)
    assert parsed["description"] == "Custom Exploit Scanner"
    assert parsed["args"] == ["host", "port"]
    rendered = render_custom_command_prompt(parsed, ["192.168.1.50", "8080"])
    assert "Scan target 192.168.1.50 on port 8080." in rendered

def test_load_custom_commands(tmp_path):
    init_project(target_dir=tmp_path)
    cmds = load_custom_commands(project_dir=tmp_path)
    assert "scan" in cmds
    assert "audit" in cmds
    assert "recon" in cmds
    assert "explain" in cmds
    assert "target" in cmds["scan"]["args"]


# -- user-level commands, $ARGUMENTS and expansion for every front end (roadmap F3) -------------

from core.project import expand_custom_command  # noqa: E402
from tools.filesystem import set_active_workspace  # noqa: E402


def _write_command(folder, name, text):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.md").write_text(text, encoding="utf-8")


def test_user_commands_win_and_active_workspace_is_used(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    _write_command(project / ".buzzard" / "commands", "review", "---\ndescription: project review\n---\nProject review of $ARGUMENTS")
    _write_command(project / ".buzzard" / "commands", "release", "Prepare release notes")
    _write_command(tmp_path / "home" / "commands", "review", "---\ndescription: my review\n---\nMy review of $ARGUMENTS")
    monkeypatch.chdir(tmp_path)  # the working directory is not the project
    set_active_workspace(str(project))
    try:
        commands = load_custom_commands()
        assert commands["review"]["source"] == "user" and commands["review"]["description"] == "my review"
        assert commands["release"]["source"] == "project"
        assert expand_custom_command("/review pull request 42") == "My review of pull request 42"
        assert expand_custom_command("/release v2") == "Prepare release notes\nAdditional context: v2"
        assert expand_custom_command("/missing x") is None
        assert expand_custom_command("plain task") is None
        assert expand_custom_command("/review x", reserved=["/review"]) is None
    finally:
        set_active_workspace(None)


def test_bad_names_and_oversized_files_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    folder = tmp_path / ".buzzard" / "commands"
    _write_command(folder, "Bad Name", "x")
    _write_command(folder, "huge", "x" * 30_000)
    _write_command(folder, "ok", "fine")
    assert set(load_custom_commands(tmp_path)) == {"ok"}


def test_run_session_expands_custom_commands_for_every_front_end(tmp_path, monkeypatch):
    from agent.run_session import RunSession

    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    _write_command(tmp_path / "home" / "commands", "explain", "Explain $ARGUMENTS without changing files")
    seen = []
    session = RunSession(None, None, None, {}, ask_approval=lambda request: "deny")
    monkeypatch.setattr(session, "_run", lambda goal, *args: seen.append(goal) or SimpleOutcome())
    set_active_workspace(str(tmp_path))
    try:
        session.run("/explain calc.py", target="localhost", scope=["localhost"])
    finally:
        set_active_workspace(None)
    assert seen == ["Explain calc.py without changing files"]


class SimpleOutcome:
    status = "completed"
