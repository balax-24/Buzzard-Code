"""
Unit and integration tests for Buzzard Code v1.0 Cross-Platform Native CLI and Setup State.
"""

import sys
import os
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from core.config import (
    get_setup_state_file,
    get_setup_state,
    save_setup_state,
    is_setup_completed,
    get_global_config_dir,
)
from cli.setup_wizard import is_first_run, run_first_run_wizard
from cli.main import main

def test_setup_state_persistence(tmp_path, monkeypatch):
    """Verifies that persistent setup state saves and loads correctly."""
    monkeypatch.setattr("core.config.get_global_config_dir", lambda: tmp_path)

    state = get_setup_state()
    assert state["setup_completed"] is False
    assert is_setup_completed() is False

    state["installation_initialized"] = True
    state["setup_completed"] = True
    state["configured_provider"] = "ollama"
    state["configured_model"] = "qwen3:8b"
    state["sandbox_status"] = "ready"
    save_setup_state(state)

    loaded = get_setup_state()
    assert loaded["setup_completed"] is True
    assert loaded["configured_provider"] == "ollama"
    assert loaded["configured_model"] == "qwen3:8b"
    assert is_setup_completed() is True

def test_is_first_run_state_check(tmp_path, monkeypatch):
    """Verifies that is_first_run reflects setup_completed state."""
    monkeypatch.setattr("core.config.get_global_config_dir", lambda: tmp_path)
    
    assert is_first_run() is True

    state = get_setup_state()
    state["setup_completed"] = True
    save_setup_state(state)

    assert is_first_run() is False

def test_version_option_fast_return():
    """Verifies that buzzard --version returns immediately without running full runtime."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "Buzzard Code, version 1.0.0" in result.output

def test_version_command():
    """Verifies that buzzard version command returns version string."""
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "Buzzard Code v1.0.0" in result.output

def test_first_run_wizard_non_interactive(tmp_path, monkeypatch):
    """Verifies that first-run wizard in non-interactive environment defaults safely and sets state."""
    monkeypatch.setattr("core.config.get_global_config_dir", lambda: tmp_path)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    
    with patch("sandbox.container.is_docker_active", return_value=True):
        ok = run_first_run_wizard(force=True)
        assert ok is True

    state = get_setup_state()
    assert state["installation_initialized"] is True
    assert state["setup_completed"] is True
    assert state["configured_provider"] == "ollama"

def test_uninstall_dry_run():
    """Verifies that uninstall command prompts and aborts safely without --yes."""
    runner = CliRunner()
    result = runner.invoke(main, ["uninstall"], input="n\n")
    assert result.exit_code == 0
    assert "aborted" in result.output.lower()

def test_uninstall_preserves_user_data(tmp_path, monkeypatch):
    """Verifies that uninstall without --purge-data preserves user data."""
    fake_config = tmp_path / "buzzard_config"
    fake_config.mkdir(parents=True, exist_ok=True)
    (fake_config / "config.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr("core.config.get_global_config_dir", lambda: fake_config)

    runner = CliRunner()
    result = runner.invoke(main, ["uninstall", "--yes"])
    assert result.exit_code == 0
    assert "preserved" in result.output.lower()
    # Configuration directory must still exist!
    assert (fake_config / "config.json").is_file()
