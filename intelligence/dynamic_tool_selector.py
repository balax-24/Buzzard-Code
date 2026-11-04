"""
Dynamic Tool Presentation and Focused Registry Selector for Buzzard Code.

Enforces context-bounded, phase-aware, and hypothesis-driven tool selection.
Prevents context window explosion while guaranteeing that necessary security capabilities
remain accessible across diverse, unseen target topologies.

Invariants:
- Never exposes 140+ tools at once (caps exposed tools to a configurable maximum, default 20-25).
- Always preserves Core universal tools (completion, evidence logging, finding verification).
- Dynamically selects phase-appropriate and hypothesis-relevant tools.
- Never hardcodes specific lab ports, endpoints, or scenario identifiers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from tools.registry import ToolRegistry, ToolCategory, ToolDefinition


UNIVERSAL_CORE_TOOLS: Set[str] = {
    "complete",
    "finish_task",
    "log_evidence",
    "log_finding",
    "http.request",
    "scan_ports",
    "grab_banner",
    "check_headers",
}

PHASE_TOOL_PREFERENCES: Dict[str, Set[str]] = {
    "DISCOVERY": {
        "ping_host",
        "dns_lookup",
        "port_scan",
        "ssl_check",
        "dir_scan",
        "subdomain_enum",
        "whois_lookup",
    },
    "RECON": {
        "ping_host",
        "dns_lookup",
        "port_scan",
        "ssl_check",
        "dir_scan",
        "subdomain_enum",
        "whois_lookup",
    },
    "VULN_SCAN": {
        "cors_scan",
        "jwt_decode",
        "sqli_scan",
        "xss_scan",
        "cookie_audit",
        "csrf_check",
        "security_headers",
        "file.read",
        "file.search",
    },
    "EXPLOITATION": {
        "sqlmap",
        "terminal.execute",
        "python_executor",
        "jwt_forge",
        "auth_bypass_test",
        "hydra",
        "brute_force",
        "file.read",
        "file.write",
    },
    "VERIFICATION": {
        "verify_proof",
        "file.read",
        "check_headers",
    },
    "REPORT": {
        "verify_proof",
    },
}

KEYWORD_TOOL_MAPPING: Dict[str, Set[str]] = {
    "sql": {"sqlmap", "sqli_scan", "sqli_probe"},
    "jwt": {"jwt_decode", "jwt_forge"},
    "auth": {"auth_bypass_test", "hydra", "brute_force"},
    "cookie": {"cookie_audit", "jwt_decode"},
    "file": {"file.read", "file.write", "file.search", "file.list"},
    "header": {"check_headers", "security_headers", "cors_scan"},
    "terminal": {"terminal.execute", "python_executor"},
    "bash": {"terminal.execute"},
    "browser": {"browser_navigate", "browser_click", "browser_snapshot"},
}


class DynamicToolSelector:
    """
    Selects a focused, high-relevance subset of tool schemas for model consumption.
    """

    @classmethod
    def select_focused_tools(
        cls,
        registry: ToolRegistry,
        phase: str = "DISCOVERY",
        active_hypothesis: str = "",
        target: str = "",
        max_tools: int = 22,
    ) -> List[Dict[str, Any]]:
        """
        Returns a bounded list of OpenAI function calling schemas (default <= 22 tools)
        prioritizing core tools, phase alignment, and hypothesis relevance.
        """
        all_active_tools = registry.get_active_tools()
        selected_names: Set[str] = set()

        # 1. Add Universal Core Tools (if present and active in registry)
        for t_name in UNIVERSAL_CORE_TOOLS:
            if t_name in all_active_tools:
                selected_names.add(t_name)

        # 2. Add Phase-Specific Tools
        norm_phase = phase.upper() if phase else "DISCOVERY"
        pref_tools = PHASE_TOOL_PREFERENCES.get(norm_phase, PHASE_TOOL_PREFERENCES["DISCOVERY"])
        for t_name in pref_tools:
            if len(selected_names) >= max_tools:
                break
            if t_name in all_active_tools:
                selected_names.add(t_name)

        # 3. Add Hypothesis-Relevant Tools
        if active_hypothesis:
            hypo_lower = active_hypothesis.lower()
            for kw, kw_tools in KEYWORD_TOOL_MAPPING.items():
                if kw in hypo_lower:
                    for t_name in kw_tools:
                        if len(selected_names) >= max_tools:
                            break
                        if t_name in all_active_tools:
                            selected_names.add(t_name)

        # 4. Fill remaining capacity with healthy Utility/Analysis tools
        if len(selected_names) < max_tools:
            for t_name, tool_def in all_active_tools.items():
                if len(selected_names) >= max_tools:
                    break
                if t_name not in selected_names:
                    selected_names.add(t_name)

        # 5. Export Schemas for selected tools
        schemas: List[Dict[str, Any]] = []
        for name in sorted(selected_names):
            if name in all_active_tools:
                schemas.append(all_active_tools[name].get_schema())

        return schemas

    @classmethod
    def get_available_categories_summary(cls, registry: ToolRegistry) -> str:
        """
        Emits a concise high-level summary of tool categories available in the registry,
        informing the model of broader capabilities without prompt bloat.
        """
        inventory = registry.get_inventory()
        lines = ["[AVAILABLE TOOL CATEGORIES]"]
        for cat, defs in sorted(inventory.items()):
            tool_sample = ", ".join(d.name for d in defs[:4])
            if len(defs) > 4:
                tool_sample += f", +{len(defs)-4} more"
            lines.append(f"• {cat} ({len(defs)} tools): {tool_sample}")
        return "\n".join(lines)
