"""
Regression tests for Buzzard Code TUI Tool Registry, slash commands,
visual hierarchy, and responsive terminal-native rendering.
"""

import pytest
from textual.widgets import Input, Static
from rich.text import Text
from rich.console import Console

from security_agent.tui.app import BuzzardTUIApp
from security_agent.tui.widgets.chat import ChatView, MessageBubble
from security_agent.tui.models import ChatMessage, MessageRole
from security_agent.tui.test_utils import run_async
from security_agent.tools.registry import create_authoritative_registry, ToolRegistry
from security_agent.tools.inspector import get_tool_details, get_standard_registry, build_tools_view

CANONICAL_TEST_TOOLS = [
    'ping_host', 'scan_ports', 'scan_common_ports', 'subnet_discovery',
    'dns_lookup', 'reverse_dns', 'grab_banner', 'service_detect',
    'http_probe', 'check_headers', 'ssl_check', 'sqli_scan',
    'xss_scan', 'tech_fingerprint', 'redirect_check', 'robots_check',
    'security_txt_check', 'whatweb_scan',
    'certificate_inspect', 'tls_version_check', 'tls_cipher_check',
    'dnssec_check', 'zone_transfer_check',
    'subdomain_enum', 'whois_lookup', 'asn_lookup', 'technology_detect',
    'metadata_extract', 'ioc_extract',
    'process_list', 'listening_ports', 'system_info', 'network_interfaces', 'routing_table',
    'yara_scan', 'entropy_check', 'strings_extract', 'pe_inspect', 'archive_inspect',
    'log_search', 'hash_lookup', 'url_reputation', 'log_summary',
]


def test_authoritative_registry_live_counts():
    """Verify live authoritative registry contains expected definitions, tools, and aliases."""
    reg = create_authoritative_registry()
    alias_map = getattr(reg, "TOOL_ALIASES", {})
    canonical_defs = {k: v for k, v in reg.definitions.items() if k not in alias_map}

    assert len(reg.definitions) == 223, f"Expected 223 definitions, got {len(reg.definitions)}"
    assert len(reg.tools) == 223, f"Expected 223 tools, got {len(reg.tools)}"
    assert len(alias_map) == 47, f"Expected 47 aliases, got {len(alias_map)}"
    assert len(canonical_defs) == 207, f"Expected 207 canonical tools, got {len(canonical_defs)}"

    # Check 78 canonical tools across the 9 primary tool suites
    assert len(CANONICAL_TEST_TOOLS) == 43
    for tool in CANONICAL_TEST_TOOLS:
        assert tool in reg.definitions, f"Canonical tool '{tool}' missing from definitions"
        assert tool in reg.tools, f"Canonical tool '{tool}' missing from tools"

    # Verify not 14 tools
    assert len(reg.tools) > 14


def test_tui_registry_initialization_not_stale():
    """Verify BuzzardTUIApp initializes with the authoritative registry, not the 14-tool fallback."""
    app = BuzzardTUIApp(fake=True)
    assert hasattr(app, "registry"), "app must store live registry instance"
    assert app.registry is not None
    assert len(app.registry.definitions) == 223
    assert len(app.registry.tools) == 223
    assert len(app.registry.definitions) > 14, "FATAL REGRESSION: TUI is using legacy <= 14 tool registry"


def test_tui_slash_tools_no_args_shows_canonical_registry():
    """Verify /tools dynamically displays live counts, terminal table, and no raw Markdown pipe syntax."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # Issue /tools command
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools"))
            await pilot.pause(0.05)

            last_msg = chat_view.message_bubbles[-1].message.content

            # 1. Visual Hierarchy: Prominent Title & Dynamic live counts
            assert "BUZZARD TOOL REGISTRY" in last_msg
            assert f"{len(app.registry.definitions)} definitions" in last_msg
            assert f"{len(app.registry.TOOL_ALIASES)} aliases" in last_msg
            assert "canonical" in last_msg

            # 2. Must NOT be the legacy 14-tool output
            assert "Registered Security Tools (14)" not in last_msg

            # 3. Terminal Table Columns (recommended non-verbose headers)
            for col in ["Tool", "Category", "Risk", "RO", "Destr.", "Net", "Sand", "Scope", "Appr."]:
                assert col in last_msg, f"Column '{col}' missing from /tools table"

            # 4. Strict Markdown Hygiene: NO raw pipe table syntax (|:---|) or pipe delimiters
            assert "|:---" not in last_msg
            assert "|---|" not in last_msg
            assert "|" not in last_msg, "Raw Markdown pipe delimiter leaked into terminal table"

            # 5. No accidental **bold** markers
            assert "**" not in last_msg, "Raw Markdown bold syntax leaked into output"

            # 6. Verify visual indicators
            assert "✓" in last_msg, "Enabled visual indicator '✓' missing"
            assert "—" in last_msg, "Disabled visual indicator '—' missing"

            # 7. Verify representative canonical tools from suites appear
            assert "yara_scan" in last_msg
            assert "ping_host" in last_msg
            assert "certificate_inspect" in last_msg
            assert "subdomain_enum" in last_msg
            assert "dnssec_check" in last_msg
            assert "process_list" in last_msg
            assert "file_read" in last_msg

    run_async(_run())


def test_tui_slash_tools_category_filtering():
    """Verify /tools <category> filters against the canonical registry with terminal table."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # 1. /tools network
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools network"))
            await pilot.pause(0.05)
            net_msg = chat_view.message_bubbles[-1].message.content

            assert "BUZZARD TOOL REGISTRY" in net_msg
            assert "CATEGORY: NETWORK" in net_msg
            assert "ping_host" in net_msg
            assert "scan_ports" in net_msg
            assert "|" not in net_msg
            assert "**" not in net_msg
            # Tools from other suites should not appear in this category view
            assert "yara_scan" not in net_msg
            assert "certificate_inspect" not in net_msg

            # 2. /tools file_analysis
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools file_analysis"))
            await pilot.pause(0.05)
            file_msg = chat_view.message_bubbles[-1].message.content

            assert "CATEGORY: FILE_ANALYSIS" in file_msg
            assert "yara_scan" in file_msg
            assert "entropy_check" in file_msg
            assert "strings_extract" in file_msg
            assert "ping_host" not in file_msg

            # 3. /tools tls
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools tls"))
            await pilot.pause(0.05)
            tls_msg = chat_view.message_bubbles[-1].message.content

            assert "CATEGORY: TLS" in tls_msg
            assert "certificate_inspect" in tls_msg
            assert "tls_version_check" in tls_msg

    run_async(_run())


def test_tui_slash_tools_single_tool_and_schema():
    """Verify /tools <name> displays full schema, parameters, and security requirements without raw Markdown."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # 1. Inspect scan_ports
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools scan_ports"))
            await pilot.pause(0.05)
            msg = chat_view.message_bubbles[-1].message.content

            assert "SCAN_PORTS" in msg
            assert "Category" in msg
            assert "network" in msg
            assert "Risk" in msg
            assert "Read-only" in msg
            assert "Destructive" in msg
            assert "Network" in msg
            assert "Sandbox" in msg
            assert "Scope" in msg
            assert "Approval" in msg
            assert "Parameters" in msg
            assert "host" in msg
            assert "ports" in msg
            # No raw markdown markers
            assert "|" not in msg
            assert "**" not in msg
            assert "###" not in msg

            # 2. Inspect yara_scan
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools yara_scan"))
            await pilot.pause(0.05)
            yara_msg = chat_view.message_bubbles[-1].message.content

            assert "YARA_SCAN" in yara_msg
            assert "file_analysis" in yara_msg
            assert "target_path" in yara_msg or "rule" in yara_msg or "path" in yara_msg
            assert "|" not in yara_msg
            assert "**" not in yara_msg

    run_async(_run())


def test_tui_slash_tools_alias_resolution_and_no_duplicate_counting():
    """Verify aliases resolve properly to canonical tools without pipe tables."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # 1. Alias: ping -> ping_host
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools ping"))
            await pilot.pause(0.05)
            ping_msg = chat_view.message_bubbles[-1].message.content

            assert "PING_HOST" in ping_msg
            assert "ping" in ping_msg
            assert "|" not in ping_msg

            # 2. Alias: port_scan -> scan_ports
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools port_scan"))
            await pilot.pause(0.05)
            port_msg = chat_view.message_bubbles[-1].message.content

            assert "SCAN_PORTS" in port_msg
            assert "port_scan" in port_msg
            assert "|" not in port_msg

            # 3. Check alias resolution helper
            details = get_tool_details("ping", app.registry)
            assert details is not None
            assert details["canonical_name"] == "ping_host"
            assert "ping" in details["aliases"]

    run_async(_run())


def test_tui_rejects_legacy_14_tool_registry():
    """Regression test ensuring explicit failure if any attempt is made to use the 14-tool registry."""
    reg = ToolRegistry()
    from security_agent.tools.basic import register_basic_tools
    from security_agent.tools.security import register_security_tools
    register_basic_tools(reg)
    register_security_tools(reg)

    legacy_count = len(reg.tools)
    assert legacy_count == 14, "Expected legacy basic + security to be exactly 14 tools"

    # App using authoritative registry must have far more tools
    app = BuzzardTUIApp(fake=True)
    assert len(app.registry.tools) > legacy_count, (
        f"Regression detected: TUI registry tool count ({len(app.registry.tools)}) "
        f"matches legacy count ({legacy_count})"
    )


def test_tui_slash_tools_responsive_widths():
    """Verify /tools renders safely and responsively at 80, 100, 120, and 160+ column widths."""
    reg = create_authoritative_registry()

    for width in [80, 100, 120, 160]:
        res = build_tools_view(width=width, registry=reg)
        assert res is not None
        assert "BUZZARD TOOL REGISTRY" in res.clean_text
        assert "223 definitions" in res.clean_text
        assert "207 canonical" in res.clean_text
        assert "47 aliases" in res.clean_text

        # Ensure no pipe syntax or bold delimiters
        assert "|" not in res.clean_text
        assert "**" not in res.clean_text

        # Width 80 specific check: line length must be <= 80 (no wrapping overflow)
        if width == 80:
            lines = res.clean_text.splitlines()
            max_len = max(len(l) for l in lines)
            assert max_len <= 80, f"Rendered width exceeded 80 columns: max line was {max_len}"


def test_normal_ui_text_no_raw_markdown_delimiters():
    """Verify that MessageBubble renders markdown visually and does not display raw delimiters."""
    msg = ChatMessage(
        role=MessageRole.ASSISTANT,
        content="### Analysis Results\n- **Target**: `192.168.1.1`\n- **Status**: *Verified*\n\n```python\nprint('safe')\n```"
    )
    bubble = MessageBubble(msg)
    body = bubble._format_body(msg.content)

    # In Rich Markdown rendering, ast elements represent formatted structures
    # Verify it returns a Rich Markdown renderable
    from rich.markdown import Markdown
    assert isinstance(body, Markdown)

    # Verify rendering via Console produces clean formatted text without raw ** or backticks
    console = Console(record=True, width=80)
    console.print(body)
    rendered = console.export_text()

    assert "**Target**" not in rendered
    assert "*Verified*" not in rendered
    assert "### Analysis Results" not in rendered
