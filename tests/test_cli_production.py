"""
Comprehensive end-to-end tests for Buzzard Code CLI and slash commands.
"""

import pytest
from click.testing import CliRunner
from cli.main import main
from security.kill_switch import KillSwitch
from core.config import DEFAULT_CONFIG
from core.project import init_project

@pytest.fixture
def runner():
    return CliRunner()

def test_cli_version(runner):
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output

def test_cli_help(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "doctor" in result.output
    assert "status" in result.output
    assert "tools" in result.output
    assert "config" in result.output
    assert "run" in result.output
    assert "init" in result.output

def test_cli_status(runner):
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "BUZZARD CODE STATUS" in result.output
    assert "Version" in result.output
    assert "1.0.0" in result.output

def test_cli_config_commands(runner):
    # show
    r_show = runner.invoke(main, ["config", "show"])
    assert r_show.exit_code == 0
    assert "BUZZARD CODE CONFIGURATION" in r_show.output

    # path
    r_path = runner.invoke(main, ["config", "path"])
    assert r_path.exit_code == 0
    assert "Global Config Path:" in r_path.output

    # validate
    r_val = runner.invoke(main, ["config", "validate"])
    assert r_val.exit_code == 0
    assert "Configuration is valid" in r_val.output

def test_cli_tools_inspection(runner):
    # List all
    r_list = runner.invoke(main, ["tools"])
    assert r_list.exit_code == 0
    assert "REGISTERED BUZZARD CODE TOOLS" in r_list.output or "BUZZARD TOOL REGISTRY" in r_list.output

    # Inspect single tool
    r_single = runner.invoke(main, ["tools", "http.request"])
    assert r_single.exit_code == 0
    assert "TOOL INSPECTION: http.request" in r_single.output or "HTTP_REQUEST" in r_single.output
    assert ("Sandbox Requirement" in r_single.output and "Docker" in r_single.output) or "Sandbox" in r_single.output

def test_cli_init_command(tmp_path, runner):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        res = runner.invoke(main, ["init"])
        assert res.exit_code == 0
        assert "initialized successfully" in res.output

        # Re-running without force should warn
        res2 = runner.invoke(main, ["init"])
        assert "already initialized" in res2.output

        # Re-running with force should succeed
        res3 = runner.invoke(main, ["init", "--force"])
        assert res3.exit_code == 0
        assert "initialized successfully" in res3.output

def test_cli_run_scope_protection(runner):
    # Unauthorized target should immediately be rejected
    res = runner.invoke(main, ["run", "--target", "evil.attacker.com", "scan target"])
    assert res.exit_code == 0
    assert "SCOPE ERROR" in res.output

def test_cli_run_kill_switch_protection(runner):
    ks = KillSwitch.get_instance()
    ks.trigger("Test kill switch")
    try:
        res = runner.invoke(main, ["run", "--target", "localhost", "test task"])
        assert res.exit_code == 0
        assert "EXECUTION BLOCKED" in res.output
    finally:
        ks.reset()
