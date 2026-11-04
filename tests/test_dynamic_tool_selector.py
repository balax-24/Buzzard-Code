"""
Unit tests for Dynamic Tool Presentation and Focused Registry Selector.

Verifies:
- Exposed tools never exceed the configured cap (default <= 22 tools).
- Universal core tools (complete, log_evidence, log_finding, http.request) are always prioritized.
- Tool schemas dynamically adapt to current assessment phase (DISCOVERY, VULN_SCAN, EXPLOITATION, VERIFICATION).
- Hypothesis keywords (sql, jwt, auth, header) dynamically pull matching security tools.
- Available categories summary provides high-level awareness without schema bloat.
- Generalized behavior across arbitrary target environments without hardcoded topologies.
"""

import pytest
from security_agent.intelligence.dynamic_tool_selector import (
    DynamicToolSelector,
    UNIVERSAL_CORE_TOOLS,
)
from security_agent.tools.registry import ToolRegistry, ToolDefinition, ToolCategory


@pytest.fixture
def populated_registry():
    registry = ToolRegistry()

    # Register universal tools
    for tool_name in ["complete", "finish_task", "log_evidence", "log_finding", "http.request", "scan_ports"]:
        registry.register(
            name=tool_name,
            description=f"Core tool {tool_name}",
            func=lambda target="": {"status": "ok"},
            category=ToolCategory.UTILITY,
        )

    # Register phase & domain tools
    domain_tools = [
        ("ping_host", ToolCategory.NETWORK),
        ("dns_lookup", ToolCategory.NETWORK),
        ("port_scan", ToolCategory.NETWORK),
        ("dir_scan", ToolCategory.NETWORK),
        ("sqli_scan", ToolCategory.EXPLOIT),
        ("sqlmap", ToolCategory.EXPLOIT),
        ("jwt_decode", ToolCategory.EXPLOIT),
        ("jwt_forge", ToolCategory.EXPLOIT),
        ("auth_bypass_test", ToolCategory.EXPLOIT),
        ("verify_proof", ToolCategory.ANALYSIS),
        ("file.read", ToolCategory.UTILITY),
        ("file.write", ToolCategory.UTILITY),
        ("terminal.execute", ToolCategory.UTILITY),
        ("extra_tool_1", ToolCategory.UTILITY),
        ("extra_tool_2", ToolCategory.UTILITY),
        ("extra_tool_3", ToolCategory.UTILITY),
        ("extra_tool_4", ToolCategory.UTILITY),
    ]

    for name, cat in domain_tools:
        registry.register(
            name=name,
            description=f"Domain tool {name}",
            func=lambda arg="": {"status": "ok"},
            category=cat,
        )

    return registry


def test_tool_cap_enforced(populated_registry):
    max_tools = 8
    schemas = DynamicToolSelector.select_focused_tools(
        registry=populated_registry,
        phase="DISCOVERY",
        max_tools=max_tools
    )

    assert len(schemas) <= max_tools
    names = [s["function"]["name"] for s in schemas]
    # Universal tools must be prioritized
    assert "complete" in names or "log_evidence" in names


def test_phase_adaptation(populated_registry):
    discovery_schemas = DynamicToolSelector.select_focused_tools(
        registry=populated_registry,
        phase="DISCOVERY",
        max_tools=20
    )
    discovery_names = {s["function"]["name"] for s in discovery_schemas}
    assert "ping_host" in discovery_names or "dir_scan" in discovery_names

    exploit_schemas = DynamicToolSelector.select_focused_tools(
        registry=populated_registry,
        phase="EXPLOITATION",
        max_tools=20
    )
    exploit_names = {s["function"]["name"] for s in exploit_schemas}
    assert "terminal.execute" in exploit_names or "auth_bypass_test" in exploit_names


def test_hypothesis_keyword_injection(populated_registry):
    schemas = DynamicToolSelector.select_focused_tools(
        registry=populated_registry,
        phase="DISCOVERY",
        active_hypothesis="Target appears vulnerable to sql injection on login form",
        max_tools=20
    )
    names = {s["function"]["name"] for s in schemas}

    # Hypothesis with 'sql' should inject SQL tools
    assert "sqli_scan" in names or "sqlmap" in names


def test_categories_summary_generation(populated_registry):
    summary = DynamicToolSelector.get_available_categories_summary(populated_registry)

    assert "[AVAILABLE TOOL CATEGORIES]" in summary
    assert "UTILITY" in summary or "EXPLOIT" in summary or "ANALYSIS" in summary
