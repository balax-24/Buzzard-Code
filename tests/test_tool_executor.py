"""
Unit tests for the ToolExecutor module (agent/tool_executor.py).

Verifies:
1. Valid tool execution and structured ToolExecutionResult output
2. Invalid schema and missing required arguments rejection
3. Out-of-scope target prevention
4. Placeholder target rejection (<target>, target.com)
5. Unavailable tool handling
6. Quarantined tool rejection
7. Dependency missing classification and auto-quarantine
8. Duplicate invocation / cache lookup
9. Cache hits and repeat failure blocking
10. Sandbox execution failure handling
11. Execution timing metrics and telemetry
"""

import pytest
from unittest.mock import MagicMock
from typing import Dict, Any

from agent.tool_executor import ToolExecutor, ToolExecutionResult
from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    ServiceRecord,
    HTTPState,
    ServiceState,
    VerificationStatus,
)


class MockRegistry:
    def __init__(self, tools_dict: Dict[str, Any] = None):
        self.tools = tools_dict or {
            "nmap_scan": MagicMock(return_value="PORT 80/tcp OPEN http\nPORT 443/tcp OPEN https"),
            "scan_ports": MagicMock(return_value="PORT 80/tcp OPEN"),
            "ping_host": MagicMock(return_value="Host 127.0.0.1 is alive (0.04ms)"),
            "whatweb_scan": MagicMock(return_value="http://127.0.0.1:80 [200 OK] Apache/2.4.41"),
            "missing_dep_tool": MagicMock(return_value="bash: line 1: missing_dep_tool: command not found"),
            "failing_tool": MagicMock(side_effect=RuntimeError("Docker container execution failed")),
        }
        self.quarantine = set()

    def execute(self, name: str, args: Dict[str, Any], context: Dict[str, Any] = None) -> str:
        if name in self.quarantine:
            return f"TOOL QUARANTINED: Tool '{name}' is in quarantine."
        if name not in self.tools:
            return f"Error executing tool {name}: Tool not found"
        tool_fn = self.tools[name]
        if callable(tool_fn):
            return tool_fn(**args)
        return str(tool_fn)


@pytest.fixture
def mock_registry():
    return MockRegistry()


@pytest.fixture
def base_state():
    ctx = AssessmentContext(
        target="127.0.0.1",
        scope={"127.0.0.1", "localhost"},
        objective="Vulnerability Assessment"
    )
    state = AssessmentState(context=ctx)
    state.current_phase = AssessmentPhase.ASSET_DISCOVERY
    return state


@pytest.fixture
def executor(mock_registry):
    return ToolExecutor(registry=mock_registry)


def test_valid_tool_execution(executor, base_state):
    """Verifies successful tool execution returning structured ToolExecutionResult."""
    res = executor.execute(
        tool_name="ping_host",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert isinstance(res, ToolExecutionResult)
    assert res.success is True
    assert res.exit_code == 0
    assert res.error_type == "none"
    assert "Host 127.0.0.1 is alive" in res.raw_output
    assert res.duration >= 0.0
    assert executor.tools_successful == 1


def test_invalid_schema_missing_arguments(executor, base_state):
    """Verifies that tools requiring mandatory parameters are rejected before execution."""
    res = executor.execute(
        tool_name="scan_ports",
        arguments={},  # missing required "ports" parameter
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.exit_code == 2
    assert res.error_type == "invalid_argument"
    assert "ACTION REJECTED" in res.raw_output
    assert executor.tools_failed == 1


def test_out_of_scope_target(executor, base_state):
    """Verifies that targets outside authorized scope are strictly blocked."""
    res = executor.execute(
        tool_name="ping_host",
        arguments={"host": "192.168.100.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.exit_code == 2
    assert "TARGET_OUT_OF_SCOPE" in res.raw_output or "ACTION BLOCKED" in res.raw_output


def test_placeholder_target_rejection(executor, base_state):
    """Verifies that placeholder targets like <target> are blocked."""
    res = executor.execute(
        tool_name="ping_host",
        arguments={"host": "<target>"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.exit_code == 2
    assert "ACTION BLOCKED" in res.raw_output or "ACTION REJECTED" in res.raw_output


def test_unavailable_tool(executor, base_state):
    """Verifies rejection when tool is not registered in the schema."""
    res = executor.execute(
        tool_name="non_existent_tool",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.exit_code == 2
    assert res.error_type == "unavailable"
    assert "TOOL UNAVAILABLE" in res.raw_output


def test_quarantined_tool(executor, base_state):
    """Verifies that quarantined tools cannot be executed."""
    executor.registry.quarantine.add("ping_host")
    res = executor.execute(
        tool_name="ping_host",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.quarantined is True
    assert "TOOL QUARANTINED" in res.raw_output


def test_dependency_missing_triggers_quarantine(executor, base_state):
    """Verifies that exit 127 / command not found automatically quarantines the tool."""
    res = executor.execute(
        tool_name="missing_dep_tool",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert res.exit_code == 127
    assert res.error_type == "dependency_missing"
    assert "missing_dep_tool" in executor.registry.quarantine


def test_caching_and_cache_hit(executor, base_state):
    """Verifies state-scoped caching returns cached results without re-executing."""
    # First execution
    res1 = executor.execute(
        tool_name="ping_host",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res1.cache_hit is False
    assert res1.success is True

    # Second execution with identical args
    res2 = executor.execute(
        tool_name="ping_host",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res2.cache_hit is True
    assert res2.success is True
    assert executor.cache_hits == 1
    assert executor.duplicate_calls_blocked == 1


def test_sandbox_failure_handling(executor, base_state):
    """Verifies that sandbox exceptions are gracefully caught and reported as failures."""
    res = executor.execute(
        tool_name="failing_tool",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.success is False
    assert "Error executing tool failing_tool" in res.raw_output


def test_execution_timing(executor, base_state):
    """Verifies that execution latency is accurately recorded."""
    res = executor.execute(
        tool_name="ping_host",
        arguments={"host": "127.0.0.1"},
        target="127.0.0.1",
        state=base_state
    )
    assert res.duration >= 0.0
    assert len(executor.tool_latencies) == 1
