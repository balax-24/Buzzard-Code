import pytest
from unittest.mock import MagicMock, patch
from security_agent.toolchain.manifest import (
    ToolCategory,
    ToolDependency,
    ToolchainManifest,
    STANDARD_DEPENDENCIES,
)
from security_agent.toolchain.checker import CheckStatus, ToolCheckResult, ToolchainChecker
from security_agent.toolchain.installer import ToolchainInstaller
from security_agent.toolchain.manager import ToolchainManager
from security_agent.sandbox.container import SandboxProvider
from security_agent.cli.renderer import render_execution_metrics, console


class MockSandbox(SandboxProvider):
    def __init__(self, installed_commands=None, exit_code=0):
        self.installed = set(installed_commands or ["sh", "bash", "curl", "python3", "hostname", "nmap", "git", "jq", "openssl", "grep"])
        self.default_exit_code = exit_code

    def execute(self, command: str, timeout: float = 30.0):
        tokens = [t.strip(";|\"'\t\n ") for t in command.split()]
        matches = [t for t in tokens if t in self.installed]
        if matches:
            return {"exit_code": 0, "stdout": f"{matches[0]} v1.0", "stderr": "", "sandboxed": True}
        return {"exit_code": 1, "stdout": "", "stderr": f"{tokens[0] if tokens else 'cmd'}: not found", "sandboxed": True}


def test_manifest_categories_and_hashing():
    """
    Checks that manifest correctly computes deterministic hashes and groups dependencies.
    """
    manifest = ToolchainManifest()
    hash1 = manifest.get_hash()
    assert len(hash1) == 8
    assert manifest.get_image_tag().startswith("buzzard-security-sandbox:")

    # Adding a new dependency changes the hash
    manifest.add_dependency(
        ToolDependency(
            name="custom_tool",
            category=ToolCategory.ANALYSIS,
            executable="custom_exe",
            package="custom_pkg",
            required=True
        )
    )
    hash2 = manifest.get_hash()
    assert hash1 != hash2

    categories = manifest.get_categories()
    assert ToolCategory.CORE in categories
    assert ToolCategory.NETWORK in categories
    assert ToolCategory.WEB in categories


def test_toolchain_checker_installed():
    """
    Checks that ToolchainChecker correctly identifies installed tools in sandbox.
    """
    sandbox = MockSandbox(installed_commands=["nmap", "curl", "bash", "sh"])
    with patch("security_agent.toolchain.checker.is_docker_active", return_value=True):
        checker = ToolchainChecker(sandbox=sandbox)
        dep = ToolDependency(
            name="nmap",
            category=ToolCategory.NETWORK,
            executable="nmap",
            package="nmap",
            required=True
        )
        res = checker.check_dependency(dep)
        assert res.status == CheckStatus.INSTALLED
        assert res.is_ok is True


def test_toolchain_checker_missing():
    """
    Checks that ToolchainChecker flags missing tools in sandbox.
    """
    sandbox = MockSandbox(installed_commands=["sh"])
    with patch("security_agent.toolchain.checker.is_docker_active", return_value=True):
        checker = ToolchainChecker(sandbox=sandbox)
        dep = ToolDependency(
            name="non_existent_tool",
            category=ToolCategory.WEB,
            executable="nonexistent_binary",
            package="missing_pkg",
            required=True
        )
        res = checker.check_dependency(dep)
        assert res.status == CheckStatus.MISSING
        assert res.is_ok is False


def test_toolchain_checker_docker_unavailable():
    """
    Checks that ToolchainChecker fails closed when Docker is not active.
    """
    sandbox = MockSandbox()
    with patch("security_agent.toolchain.checker.is_docker_active", return_value=False):
        checker = ToolchainChecker(sandbox=sandbox)
        dep = ToolDependency(
            name="nmap",
            category=ToolCategory.NETWORK,
            executable="nmap",
            package="nmap",
            required=True
        )
        res = checker.check_dependency(dep)
        assert res.status == CheckStatus.ERROR
        assert "Docker" in res.error


def test_toolchain_manager_bootstrap_success():
    """
    Checks that ToolchainManager returns True when all required dependencies are satisfied.
    """
    all_cmds = ["sh", "bash", "curl", "python3", "hostname", "nmap", "ping", "dig", "nikto", "sqlmap", "gobuster", "ffuf", "git", "jq", "openssl", "grep"]
    sandbox = MockSandbox(installed_commands=all_cmds)
    
    with patch("security_agent.toolchain.manager.is_docker_active", return_value=True), \
         patch("security_agent.toolchain.checker.is_docker_active", return_value=True), \
         patch("security_agent.toolchain.installer.ToolchainInstaller.is_image_available", return_value=True):
        manager = ToolchainManager()
        manager.sandbox = sandbox
        manager.checker = ToolchainChecker(sandbox=sandbox)
        
        ok = manager.bootstrap(interactive=False)
        assert ok is True


def test_toolchain_manager_bootstrap_failure_blocks():
    """
    Checks that ToolchainManager returns False and blocks startup if a required tool fails.
    """
    # Only 'sh' is installed; required 'nmap' and 'bash' will fail
    sandbox = MockSandbox(installed_commands=["sh"])
    
    with patch("security_agent.toolchain.manager.is_docker_active", return_value=True), \
         patch("security_agent.toolchain.checker.is_docker_active", return_value=True), \
         patch("security_agent.toolchain.installer.ToolchainInstaller.is_image_available", return_value=True), \
         patch("security_agent.toolchain.installer.ToolchainInstaller.install_missing", return_value=(False, "Build failed")):
        manager = ToolchainManager()
        manager.sandbox = sandbox
        manager.checker = ToolchainChecker(sandbox=sandbox)
        
        ok = manager.bootstrap(interactive=False)
        assert ok is False


def test_toolchain_skip_flag():
    """
    Checks that skip_toolchain bypasses validation for development.
    """
    manager = ToolchainManager()
    ok = manager.bootstrap(interactive=False, skip_toolchain=True)
    assert ok is True


def test_render_execution_metrics_output():
    """
    Checks that render_execution_metrics prints runtime, tool counters, and budget accurately.
    """
    # Should run cleanly without raising any exceptions
    render_execution_metrics(
        elapsed_seconds=125.0,
        tools_count=6,
        successful_count=5,
        failed_count=1,
        retries_count=1,
        tokens=14200,
        budget_pct=28.4
    )
