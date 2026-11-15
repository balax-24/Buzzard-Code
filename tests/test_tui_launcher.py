"""
Tests for TUI launcher and dual TUI CLI integration.
"""

import sys
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from cli.main import main
from cli.tui_launcher import find_node_executable, resolve_buzzard_tui_dir


def test_find_node_executable():
    node = find_node_executable()
    # On systems with node installed (Windows or WSL), it finds it or returns None cleanly
    assert node is None or isinstance(node, str)


def test_resolve_buzzard_tui_dir():
    tui_dir = resolve_buzzard_tui_dir()
    assert tui_dir is not None
    assert (tui_dir / "package.json").exists()


def test_cli_tui_command_react_flag():
    runner = CliRunner()
    with patch("cli.tui_launcher.launch_react_tui", return_value=0) as mock_launch:
        result = runner.invoke(main, ["tui", "--react"])
        assert result.exit_code == 0
        mock_launch.assert_called_once()


def test_cli_go_command():
    runner = CliRunner()
    with patch("cli.tui_launcher.launch_react_tui", return_value=0) as mock_launch:
        result = runner.invoke(main, ["go"])
        assert result.exit_code == 0
        mock_launch.assert_called_once_with(workspace=None, brand="BUZZARD GO")


def test_cli_root_react_flag():
    runner = CliRunner()
    with patch("cli.tui_launcher.launch_react_tui", return_value=0) as mock_launch:
        result = runner.invoke(main, ["--react"])
        assert result.exit_code == 0
        mock_launch.assert_called_once()
