import os
import subprocess
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from security_agent.tools.filesystem import set_active_workspace, get_active_workspace
from security_agent.verification.coding_verifier import (
    detect_project_test_runner,
    check_code_syntax,
    CodingVerifier,
    CodingVerificationResult,
)


def test_detect_project_test_runner(tmp_path):
    # Python
    py_dir = tmp_path / "py_proj"
    py_dir.mkdir()
    (py_dir / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    info = detect_project_test_runner(str(py_dir))
    assert info["detected"] is True
    assert info["runner"] == "pytest"

    # Node.js
    node_dir = tmp_path / "node_proj"
    node_dir.mkdir()
    (node_dir / "package.json").write_text("{\"name\": \"test\"}", encoding="utf-8")
    info_node = detect_project_test_runner(str(node_dir))
    assert info_node["detected"] is True
    assert info_node["runner"] == "npm"

    # Cargo
    cargo_dir = tmp_path / "cargo_proj"
    cargo_dir.mkdir()
    (cargo_dir / "Cargo.toml").write_text("[package]\nname='test'\n", encoding="utf-8")
    info_cargo = detect_project_test_runner(str(cargo_dir))
    assert info_cargo["detected"] is True
    assert info_cargo["runner"] == "cargo"

    # Go
    go_dir = tmp_path / "go_proj"
    go_dir.mkdir()
    (go_dir / "go.mod").write_text("module test\n", encoding="utf-8")
    info_go = detect_project_test_runner(str(go_dir))
    assert info_go["detected"] is True
    assert info_go["runner"] == "go"


def test_coding_verifier_rejects_when_no_changes(tmp_path):
    old_ws = get_active_workspace()
    # Init git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), check=True, capture_output=True)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    set_active_workspace(tmp_path)
    try:
        verifier = CodingVerifier(workspace=str(tmp_path))
        res = verifier.verify_task("Fix the bug in app.py", auto_run_tests=False)
        assert res.passed is False
        assert res.requires_action is True
        assert "No modifications were made" in res.message
    finally:
        set_active_workspace(old_ws)


def test_coding_verifier_detects_syntax_error(tmp_path):
    old_ws = get_active_workspace()
    # Init git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), check=True, capture_output=True)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    # Introduce invalid python syntax
    (tmp_path / "app.py").write_text("def broken_syntax(\n", encoding="utf-8")

    set_active_workspace(tmp_path)
    try:
        verifier = CodingVerifier(workspace=str(tmp_path))
        res = verifier.verify_task("Fix broken syntax in app.py", auto_run_tests=False)
        assert res.passed is False
        assert res.requires_action is True
        assert "syntax errors detected" in res.message.lower()
    finally:
        set_active_workspace(old_ws)


def test_coding_verifier_passes_on_successful_tests(tmp_path):
    old_ws = get_active_workspace()
    # Init git repo with working pytest setup
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=str(tmp_path), check=True, capture_output=True)
    (tmp_path / "app.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='calc'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    # Modify app.py with valid code
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n\ndef multiply(a, b):\n    return a * b\n", encoding="utf-8")

    set_active_workspace(tmp_path)
    try:
        verifier = CodingVerifier(workspace=str(tmp_path))
        # Mock test execution passing
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.stdout = "1 passed in 0.01s"
        mock_result.stderr = ""
        with patch.object(verifier.sandbox, "execute", return_value=mock_result):
            res = verifier.verify_task("Add multiply function to app.py", auto_run_tests=True)
            assert res.passed is True
            assert res.requires_action is False
            assert "All verification gates passed" in res.message
    finally:
        set_active_workspace(old_ws)

