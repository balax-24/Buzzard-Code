"""
Tool Inspection and Diagnostics System for Buzzard Code.

Renders canonical tool specifications, parameters, risk requirements,
sandbox requirements, and operational status directly from the authoritative ToolRegistry.
"""

import io
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text
from rich import box

from tools.registry import ToolRegistry, create_authoritative_registry
from security.risk import get_tool_risk_metadata, RiskClass

_CACHED_REGISTRY: Optional[ToolRegistry] = None

CATEGORY_STYLES = {
    "network": "#38bdf8",
    "web": "#818cf8",
    "tls": "#a78bfa",
    "dns": "#67e8f9",
    "recon": "#93c5fd",
    "host": "#86efac",
    "file_analysis": "#cbd5e1",
    "defensive_analysis": "#c084fc",
    "browser": "#e879f9",
    "analysis": "#a5b4fc",
    "crypto": "#f472b6",
    "cloud": "#38bdf8",
    "forensics": "#cbd5e1",
    "evidence": "#a78bfa",
    "automation": "#f59e0b",
    "utility": "#94a3b8",
    "core": "#94a3b8",
}


def _format_risk(risk_str: str) -> Text:
    r = (risk_str or "LOW").upper()
    if "CRIT" in r:
        return Text("CRIT", style="bold #ef4444")
    elif "HIGH" in r:
        return Text("HIGH", style="#f97316")
    elif "MED" in r:
        return Text("MED", style="#f59e0b")
    else:
        return Text("LOW", style="#10b981")


def _ind(val: bool, style: str = "#a78bfa") -> Text:
    if val:
        return Text("✓", style=style)
    return Text("—", style="#475569")


def _render_to_text(renderable: Any, width: int = 100) -> str:
    """Renders any Rich renderable to clean plain text without ANSI escape sequences."""
    buf = io.StringIO()
    c = Console(file=buf, width=width, force_terminal=False, color_system=None)
    c.print(renderable)
    return buf.getvalue()


@dataclass
class ToolsViewResult:
    clean_text: str
    renderable: Any
    is_error: bool = False


def get_standard_registry() -> ToolRegistry:
    """Returns populated authoritative ToolRegistry containing all tool suites."""
    global _CACHED_REGISTRY
    if _CACHED_REGISTRY is not None:
        return _CACHED_REGISTRY

    _CACHED_REGISTRY = create_authoritative_registry()
    return _CACHED_REGISTRY


def get_tool_details(tool_name: str, registry: Optional[ToolRegistry] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves deep operational metadata for a single tool directly from ToolDefinition.
    """
    reg = registry or get_standard_registry()
    canonical = reg.TOOL_ALIASES.get(tool_name, tool_name)

    if canonical not in reg.tools and canonical not in reg.definitions:
        # Try stripped dots / underscores
        for name in reg.tools:
            if name.replace(".", "_") == tool_name.replace(".", "_"):
                canonical = name
                break
        if canonical not in reg.tools and canonical not in reg.definitions:
            return None

    defn = reg.definitions.get(canonical)
    aliases = [alias for alias, target in reg.TOOL_ALIASES.items() if target == canonical]

    # Parameters & types from schema or signature
    params = {}
    required_params = []
    if defn and defn.schema:
        func_schema = defn.schema.get("function", defn.schema)
        parameters = func_schema.get("parameters", {})
        props = parameters.get("properties", {})
        required_params = parameters.get("required", [])
        for p_name, p_info in props.items():
            params[p_name] = {
                "type": p_info.get("type", "any"),
                "description": p_info.get("description", ""),
                "required": p_name in required_params,
            }
    elif canonical in reg.tools:
        tool_obj = reg.tools[canonical]
        schema = tool_obj.get_schema()
        func_schema = schema.get("function", schema)
        parameters = func_schema.get("parameters", {})
        props = parameters.get("properties", {})
        required_params = parameters.get("required", [])
        for p_name, p_info in props.items():
            params[p_name] = {
                "type": p_info.get("type", "any"),
                "description": p_info.get("description", ""),
                "required": p_name in required_params,
            }

    risk_meta = get_tool_risk_metadata(canonical)

    risk_str = getattr(defn, "risk_level", None) or risk_meta.risk_class.value
    scope_req = "REQUIRED" if getattr(defn, "scope_required", True) else "LOCAL ONLY"
    approval_req = "REQUIRED" if getattr(defn, "approval_required", False) else ("POLICY DEPENDENT" if risk_meta.requires_approval else "AUTOMATIC")
    sandbox_req = "Docker" if (defn and getattr(defn, "sandbox_required", True)) else "Native (Docker optional)"
    network_req = "REQUIRED" if (defn and getattr(defn, "network_required", False)) else "NONE"
    read_only = "YES" if (defn and getattr(defn, "read_only", True)) else "NO"
    destructive = "YES" if (defn and getattr(defn, "destructive", False)) else "NO"
    provider = getattr(defn, "provider", "local") if defn else "local"
    timeout_sec = getattr(defn, "timeout", 30) if defn else 30

    desc = getattr(defn, "description", "") if defn else ""
    cat = (defn.category.value if hasattr(defn.category, "value") else str(defn.category)) if defn else "General"

    return {
        "canonical_name": canonical,
        "aliases": aliases,
        "description": desc or "Security assessment tool",
        "category": cat.lower(),
        "parameters": params,
        "required_parameters": required_params,
        "risk_level": risk_str,
        "risk_class": risk_str,
        "scope_requirement": scope_req,
        "approval_requirement": approval_req,
        "sandbox_requirement": sandbox_req,
        "network_requirement": network_req,
        "read_only": read_only,
        "destructive": destructive,
        "provider": provider,
        "timeout": f"{timeout_sec}s",
        "permission_requirement": f"{risk_meta.risk_class.value} ({approval_req})",
        "status": "READY" if (not defn or defn.health_state.value == "healthy") else "QUARANTINED",
    }


def build_tools_table(tools_map: Dict[str, Any], width: Optional[int] = None) -> Table:
    """Creates a responsive, terminal-native table of tools."""
    is_compact = bool(width and width < 95)
    t = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold #a78bfa",
        border_style="#334155",
        pad_edge=False,
        padding=(0, 0) if is_compact else (0, 1),
    )
    if is_compact:
        t.add_column("Tool", style="bold #f1f5f9", no_wrap=True, min_width=18, max_width=20)
        t.add_column(" Category", no_wrap=True, min_width=11, max_width=13)
        t.add_column(" Risk", justify="center", no_wrap=True, min_width=5)
        t.add_column(" RO", justify="center", no_wrap=True, min_width=3)
        t.add_column(" Destr.", justify="center", no_wrap=True, min_width=6)
        t.add_column(" Net", justify="center", no_wrap=True, min_width=4)
        t.add_column(" Sand", justify="center", no_wrap=True, min_width=5)
        t.add_column(" Scope", justify="center", no_wrap=True, min_width=6)
        t.add_column(" Appr.", justify="center", no_wrap=True, min_width=6)
    else:
        t.add_column("Tool", style="bold #f1f5f9", no_wrap=True, min_width=20, max_width=28)
        t.add_column("Category", no_wrap=True, min_width=14, max_width=18)
        t.add_column("Risk", justify="center", no_wrap=True)
        t.add_column("RO", justify="center", no_wrap=True)
        t.add_column("Destr.", justify="center", no_wrap=True)
        t.add_column("Net", justify="center", no_wrap=True)
        t.add_column("Sand", justify="center", no_wrap=True)
        t.add_column("Scope", justify="center", no_wrap=True)
        t.add_column("Appr.", justify="center", no_wrap=True)

    for name, defn in sorted(tools_map.items(), key=lambda x: x[0]):
        c_str = ((defn.category.value if hasattr(defn.category, "value") else str(defn.category)) if defn else "general").lower()
        c_style = CATEGORY_STYLES.get(c_str, "#94a3b8")
        risk = getattr(defn, "risk_level", "LOW") or "LOW"
        ro = getattr(defn, "read_only", True)
        dest = getattr(defn, "destructive", False)
        net = getattr(defn, "network_required", False)
        sb = getattr(defn, "sandbox_required", True)
        sc = getattr(defn, "scope_required", True)
        appr = getattr(defn, "approval_required", False)

        risk_t = _format_risk(risk)
        ro_t = _ind(ro, "#10b981")
        dest_t = _ind(dest, "bold #ef4444")
        net_t = _ind(net, "#38bdf8")
        sb_t = _ind(sb, "#a78bfa")
        sc_t = _ind(sc, "#818cf8")
        appr_t = _ind(appr, "bold #f59e0b")

        if is_compact:
            cat_t = Text(" " + c_str, style=c_style)
            t.add_row(
                name,
                cat_t,
                Text(" ") + risk_t,
                Text(" ") + ro_t,
                Text(" ") + dest_t,
                Text(" ") + net_t,
                Text(" ") + sb_t,
                Text(" ") + sc_t,
                Text(" ") + appr_t,
            )
        else:
            cat_t = Text(c_str, style=c_style)
            t.add_row(name, cat_t, risk_t, ro_t, dest_t, net_t, sb_t, sc_t, appr_t)

    return t


def build_tool_detail_card(details: Dict[str, Any], width: Optional[int] = None) -> Group:
    """Builds a polished inspection view for a single tool."""
    elements = []

    # Visually prominent title
    title = Text(details["canonical_name"].upper(), style="bold #c084fc")
    elements.append(title)
    elements.append(Text(""))

    # Key-value metadata table
    meta_table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2))
    meta_table.add_column("Field", style="#94a3b8", min_width=14)
    meta_table.add_column("Value", style="bold #f1f5f9")

    c_str = details["category"]
    c_style = CATEGORY_STYLES.get(c_str, "#94a3b8")
    meta_table.add_row("Category", Text(c_str, style=c_style))
    meta_table.add_row("Risk", _format_risk(details["risk_level"]))
    meta_table.add_row("Read-only", "Yes" if details["read_only"] in ("YES", True) else "No")
    meta_table.add_row("Destructive", "Yes" if details["destructive"] in ("YES", True) else "No")
    meta_table.add_row("Network", "Yes" if details["network_requirement"] not in ("NONE", "None", False) else "No")
    meta_table.add_row("Sandbox", "Yes" if "Docker" in details["sandbox_requirement"] or "Required" in details["sandbox_requirement"] else "No")
    meta_table.add_row("Scope", "Yes" if details["scope_requirement"] not in ("LOCAL ONLY", "Optional", False) else "No")
    meta_table.add_row("Approval", "Yes" if details["approval_requirement"] == "REQUIRED" else "No")
    meta_table.add_row("Provider", details["provider"])
    meta_table.add_row("Timeout", details["timeout"])
    if details["aliases"]:
        meta_table.add_row("Aliases", ", ".join(details["aliases"]))
    meta_table.add_row("Description", details["description"])

    elements.append(meta_table)
    elements.append(Text(""))

    # Parameters & schema
    p_header = Text("Parameters", style="bold #a78bfa")
    elements.append(p_header)

    if details["parameters"]:
        p_table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold #a78bfa",
            border_style="#334155",
            pad_edge=False,
            padding=(0, 1),
        )
        p_table.add_column("Parameter", style="bold #f1f5f9", min_width=14)
        p_table.add_column("Type", style="#94a3b8", min_width=10)
        p_table.add_column("Requirement", min_width=10)
        p_table.add_column("Description", style="dim")

        for p_name, p_info in details["parameters"].items():
            req_style = "bold #ef4444" if p_info["required"] else "dim #94a3b8"
            req_text = "required" if p_info["required"] else "optional"
            p_table.add_row(p_name, p_info["type"], Text(req_text, style=req_style), p_info["description"])
        elements.append(p_table)
    else:
        elements.append(Text("  None required", style="dim #94a3b8"))

    return Group(*elements)


def build_tools_view(
    query: Optional[str] = None,
    registry: Optional[ToolRegistry] = None,
    width: Optional[int] = None,
) -> ToolsViewResult:
    """
    Renders terminal-native output for tool list, category filtered list, or single tool inspection.
    Returns both clean formatted text and Rich renderable.
    """
    reg = registry or get_standard_registry()
    alias_map = getattr(reg, "TOOL_ALIASES", {})
    canonical_defs = {k: v for k, v in reg.definitions.items() if k not in alias_map}

    total_definitions = len(reg.definitions)
    canonical_count = len(canonical_defs)
    alias_count = len(alias_map)

    valid_cats = {
        ((defn.category.value if hasattr(defn.category, "value") else str(defn.category)) if defn else "general").lower()
        for defn in reg.definitions.values()
    }

    render_width = width or 100
    elements = []

    if query:
        q_clean = query.strip().lower()
        matched_cat = next((c for c in valid_cats if q_clean == c or q_clean == c.replace("_", "")), None)

        if matched_cat:
            # Category filtered list
            cat_tools = {
                name: defn for name, defn in canonical_defs.items()
                if ((defn.category.value if hasattr(defn.category, "value") else str(defn.category)) if defn else "").lower() == matched_cat
                or matched_cat in ((defn.category.value if hasattr(defn.category, "value") else str(defn.category)) if defn else "").lower()
            }

            title_t = Text()
            title_t.append("BUZZARD TOOL REGISTRY", style="bold #c084fc")
            title_t.append(f" — CATEGORY: {matched_cat.upper()}\n", style="bold #a78bfa")
            title_t.append(f"{len(cat_tools)} tools in category", style="#94a3b8")
            elements.append(title_t)
            elements.append(Text(""))

            table = build_tools_table(cat_tools, width=render_width)
            elements.append(table)
            elements.append(Text("\nInspect tool details: /tools <tool_name>  ·  All tools: /tools", style="dim #64748b"))

            renderable = Group(*elements)
            clean_text = _render_to_text(renderable, width=render_width)
            return ToolsViewResult(clean_text=clean_text, renderable=renderable)

        # Single tool or alias inspection
        details = get_tool_details(query, reg)
        if details:
            renderable = build_tool_detail_card(details, width=render_width)
            clean_text = _render_to_text(renderable, width=render_width)
            return ToolsViewResult(clean_text=clean_text, renderable=renderable)

        # Not found error
        cat_list = ", ".join(f"`{c}`" for c in sorted(valid_cats))
        err_text = f"Tool or category '{query}' not found.\nSupported categories: {cat_list}"
        err_renderable = Text(err_text, style="#f87171")
        return ToolsViewResult(clean_text=err_text, renderable=err_renderable, is_error=True)

    # Top-level full registry overview
    title_t = Text()
    title_t.append("BUZZARD TOOL REGISTRY\n", style="bold #c084fc")
    title_t.append(
        f"{total_definitions} definitions · {canonical_count} canonical · {alias_count} aliases",
        style="#94a3b8"
    )
    elements.append(title_t)
    elements.append(Text(""))

    table = build_tools_table(canonical_defs, width=render_width)
    elements.append(table)
    elements.append(Text("\nFilter by category: /tools <category>  ·  Inspect: /tools <tool_name>", style="dim #64748b"))

    renderable = Group(*elements)
    clean_text = _render_to_text(renderable, width=render_width)
    return ToolsViewResult(clean_text=clean_text, renderable=renderable)


def render_tools(
    query_or_category: Optional[str] = None,
    registry: Optional[ToolRegistry] = None,
    tool_name: Optional[str] = None,
) -> None:
    """
    Renders formatted CLI/TUI output for tool list, category filtered list, or single tool inspection.
    Direct terminal printer for CLI commands.
    """
    target = query_or_category or tool_name
    console = Console(safe_box=True)
    result = build_tools_view(query=target, registry=registry, width=console.width)
    console.print(result.renderable)
