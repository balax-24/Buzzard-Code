"""
Regression test for release blocker R1:
Docker unavailable -> sandbox-required tools MUST NOT execute natively.
Native-safe tools MUST continue to execute normally.
"""

from unittest.mock import patch
from tools.registry import create_authoritative_registry
from agent.tool_executor import ToolExecutor

def test_sandbox_required_tool_fails_closed_when_docker_inactive():
    reg = create_authoritative_registry()
    executor = ToolExecutor(registry=reg)

    with patch("sandbox.container.is_docker_active", return_value=False):
        # 1. Test terminal.execute
        res1 = executor.execute("terminal.execute", {"command": "whoami"})
        assert not res1.success
        assert res1.exit_code == 126 or "SECURITY STOP" in res1.raw_output

        # 2. Test nmap_scan
        res2 = executor.execute("nmap_scan", {"target": "127.0.0.1"})
        assert not res2.success
        assert res2.exit_code == 126 or "SECURITY STOP" in res2.raw_output

        # 3. Test file_identify (manifest suite tool)
        raw3 = reg.execute("file_identify", {"path": "pyproject.toml"})
        assert "SECURITY STOP: Sandbox unavailable" in raw3
        assert "Exit code: 126" in raw3

def test_native_safe_tools_allowed_when_docker_inactive():
    reg = create_authoritative_registry()

    with patch("sandbox.container.is_docker_active", return_value=False):
        # calculator is native-safe (sandbox_required=False)
        out = reg.execute("calculator", {"expression": "21 * 2"})
        assert "42" in out
