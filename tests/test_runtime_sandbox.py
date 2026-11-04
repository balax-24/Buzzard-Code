import pytest
from unittest.mock import MagicMock, patch
from sandbox.container import (
    get_sandbox,
    get_security_sandbox_image,
    DockerSandbox,
    BlockedSandbox,
    LocalSandboxFallback,
    ToolResult,
    ToolErrorType
)
from toolchain.manifest import ToolchainManifest
from sandbox.preflight import SandboxPreflightValidator
from cli.commands import run_runtime
from agent.loop import AgentLoop
from model.schemas import TaskStatus


def test_authoritative_sandbox_image_consistency():
    """Verify that get_security_sandbox_image returns the manifest image tag."""
    manifest = ToolchainManifest()
    tag = manifest.get_image_tag()
    assert get_security_sandbox_image() == tag

    # Default DockerSandbox uses get_security_sandbox_image()
    ds = DockerSandbox()
    assert ds.image == tag

    # Default Preflight validator uses get_security_sandbox_image()
    validator = SandboxPreflightValidator()
    assert validator.image == tag


def test_tool_result_classification():
    """Verify structured exit-code semantics and ToolErrorType parsing."""
    # Exit code 0 -> Success
    res_0 = ToolResult.from_sandbox_response({
        "exit_code": 0,
        "stdout": "scan complete",
        "stderr": "",
        "sandbox_image": "test-img",
        "container_id": "test-c",
        "duration": 1.2
    })
    assert res_0.success is True
    assert res_0.error_type == ToolErrorType.NONE
    assert res_0.exit_code == 0
    assert "Status: SUCCESS" in str(res_0)

    # Exit code 127 -> Dependency missing
    res_127 = ToolResult.from_sandbox_response({
        "exit_code": 127,
        "stdout": "",
        "stderr": "sh: nmap: not found",
        "sandbox_image": "test-img",
        "container_id": "test-c",
        "duration": 0.05
    })
    assert res_127.success is False
    assert res_127.error_type == ToolErrorType.DEPENDENCY_MISSING
    assert res_127.exit_code == 127
    assert "Status: FAILED (dependency_missing)" in str(res_127)

    # Exit code 124 -> Timeout
    res_124 = ToolResult.from_sandbox_response({
        "exit_code": 124,
        "stdout": "",
        "stderr": "timed out after 30s",
        "sandbox_image": "test-img",
        "container_id": "test-c",
        "duration": 30.0
    })
    assert res_124.success is False
    assert res_124.error_type == ToolErrorType.TIMEOUT
    assert res_124.exit_code == 124

    # Exit code 126 -> Execution blocked
    res_126 = ToolResult.from_sandbox_response({
        "exit_code": 126,
        "stdout": "",
        "stderr": "POLICY DENIED",
        "sandbox_image": "test-img",
        "container_id": "test-c",
        "duration": 0.0
    })
    assert res_126.success is False
    assert res_126.error_type == ToolErrorType.EXECUTION_BLOCKED
    assert res_126.exit_code == 126

    # Other non-zero -> Tool failure
    res_1 = ToolResult.from_sandbox_response({
        "exit_code": 1,
        "stdout": "",
        "stderr": "connection refused",
        "sandbox_image": "test-img",
        "container_id": "test-c",
        "duration": 0.5
    })
    assert res_1.success is False
    assert res_1.error_type in (ToolErrorType.TOOL_FAILURE, ToolErrorType.CONNECTION_REFUSED)
    assert res_1.exit_code in (1, 111)


def test_run_runtime_probe():
    """Verify run_runtime successfully inspects sandbox environment."""
    mock_sb = MagicMock()
    mock_sb.image = get_security_sandbox_image()
    mock_sb.execute.return_value = {
        "exit_code": 0,
        "stdout": "/usr/bin/nmap\nNmap version 7.99",
        "stderr": ""
    }

    with patch("sandbox.container.get_sandbox", return_value=mock_sb), \
         patch("sandbox.container.is_docker_active", return_value=True):
        passed = run_runtime()
        assert passed is True
        assert mock_sb.execute.call_count >= 5


def test_agent_loop_blocks_on_image_mismatch():
    """Verify that AgentLoop fails-closed if runtime image differs from authoritative toolchain image."""
    mock_provider = MagicMock()
    mock_provider.is_available.return_value = True
    loop = AgentLoop(provider=mock_provider, quiet=True)

    mismatched_sb = DockerSandbox(image="ubuntu:latest")
    with patch("agent.loop.get_sandbox", return_value=mismatched_sb):
        result = loop.run(task_goal="test", target="localhost", scope=["localhost"])
        assert result["status"] == TaskStatus.FAILED.value
        assert "Image mismatch" in result["error"]
