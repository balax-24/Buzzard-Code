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
