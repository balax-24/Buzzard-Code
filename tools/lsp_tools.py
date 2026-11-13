"""
Language-server tools for the coding agent (roadmap item B1): exact definitions, references
and diagnostics. Read-only. Positions are 1-based lines and columns, as shown by file_view.
When no language server is available the tools say so and point to the index tools.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from intelligence.lsp_client import LspError, get_lsp_manager, uri_to_path
from tools.filesystem import get_active_workspace, get_safe_path

MAX_RESULTS = 50
SEVERITY = {1: "error", 2: "warning", 3: "info", 4: "hint"}


def _target(path: str) -> Path:
    try:
        safe = Path(get_safe_path(path))
    except PermissionError as error:
        raise LspError(str(error)) from None
    if not safe.is_file():
        raise LspError(f"'{path}' is not a file")
    return safe


def _position(line: Any, column: Any) -> Dict[str, int]:
    try:
        line_number, column_number = int(line), int(column)
    except (TypeError, ValueError):
        raise LspError("line and column must be whole numbers (1-based)") from None
    if line_number < 1 or column_number < 1:
        raise LspError("line and column are 1-based")
    return {"line": line_number - 1, "character": column_number - 1}


def _describe(locations: Any, root: Path) -> List[str]:
    if not locations:
        return []
    if isinstance(locations, dict):
        locations = [locations]
    rows = []
    for location in locations[:MAX_RESULTS]:
        uri = location.get("uri") or location.get("targetUri")
        span = location.get("range") or location.get("targetSelectionRange") or {}
        start = span.get("start", {})
        if not uri:
            continue
        path = uri_to_path(uri)
        line = int(start.get("line", 0)) + 1
        try:
            # resolve both sides, so Windows short names (BALAHA~1) match the server's long names
            shown = os.path.relpath(path.resolve(), root.resolve()).replace("\\", "/")
            if shown.startswith(".."):
                shown = str(path)  # outside the workspace, such as a library or the standard library
        except ValueError:
            shown = str(path)
        text = ""
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for number, content in enumerate(handle, 1):
                    if number == line:
                        text = content.strip()[:160]
                        break
        except OSError:
            pass
        rows.append(f"{shown}:{line}:{int(start.get('character', 0)) + 1}" + (f": {text}" if text else ""))
    return rows


def _fallback(error: LspError, hint: str) -> str:
    return f"Language server unavailable: {error}. {hint}"


def lsp_definition(path: str, line: int, column: int) -> str:
    """
    Finds where the symbol at a position is defined, using the project's language server.
    Arguments:
        path: Source file. line, column: 1-based position of the symbol.
    """
    root = Path(get_active_workspace())
    try:
        target = _target(path)
        server = get_lsp_manager().server_for(root, str(target))
        uri = server.sync(target)
        result = server.request("textDocument/definition", {"textDocument": {"uri": uri}, "position": _position(line, column)})
    except LspError as error:
        return _fallback(error, "Use code_symbols to find the definition by name.")
    rows = _describe(result, root)
    return "\n".join(rows) if rows else "The language server found no definition at that position."


def lsp_references(path: str, line: int, column: int) -> str:
    """
    Finds every reference to the symbol at a position, using the project's language server.
    Arguments:
        path: Source file. line, column: 1-based position of the symbol.
    """
    root = Path(get_active_workspace())
    try:
        target = _target(path)
        server = get_lsp_manager().server_for(root, str(target))
        uri = server.sync(target)
        result = server.request("textDocument/references", {
            "textDocument": {"uri": uri}, "position": _position(line, column), "context": {"includeDeclaration": False}})
    except LspError as error:
        return _fallback(error, "Use code_references to find uses by name.")
    rows = _describe(result, root)
    if not rows:
        return "The language server found no references to that symbol."
    extra = f"\n... more than {MAX_RESULTS}; narrow the search." if result and len(result) > MAX_RESULTS else ""
    return f"{len(result)} reference(s):\n" + "\n".join(rows) + extra


def file_diagnostics(path: Path, root: Path) -> Optional[List[Dict[str, Any]]]:
    """Diagnostics for one file from its language server, or None when none is available."""
    server = get_lsp_manager().server_for(root, str(path))
    import time

    since = time.time()
    uri = server.sync(path)
    if server.capabilities.get("diagnosticProvider"):
        # LSP 3.17 pull model: ask for the report instead of waiting for one to be pushed
        report = server.request("textDocument/diagnostic", {"textDocument": {"uri": uri}})
        if isinstance(report, dict) and report.get("kind") == "full":
            return list(report.get("items", []))
    return server.wait_for_diagnostics(uri, since)


def lsp_diagnostics(path: str) -> str:
    """
    Lists type errors, warnings and other problems the language server reports for a file.
    Arguments:
        path: Source file.
    """
    root = Path(get_active_workspace())
    try:
        target = _target(path)
        diagnostics = file_diagnostics(target, root)
    except LspError as error:
        return _fallback(error, "Run the project's linter or tests instead.")
    if diagnostics is None:
        return "The language server sent no diagnostics for this file in time."
    if not diagnostics:
        return f"No problems reported in {path}."
    rows = []
    for item in diagnostics[:MAX_RESULTS]:
        start = item.get("range", {}).get("start", {})
        severity = SEVERITY.get(item.get("severity", 1), "error")
        rows.append(f"{path}:{int(start.get('line', 0)) + 1}:{int(start.get('character', 0)) + 1}: {severity}: "
                    f"{str(item.get('message', '')).splitlines()[0][:200]}")
    return f"{len(diagnostics)} problem(s):\n" + "\n".join(rows)


def register_lsp_tools(registry) -> None:
    from tools.registry import ToolCategory

    common = dict(category=ToolCategory.AUTOMATION, risk_level="LOW", read_only=True,
                  sandbox_required=False, scope_required=False, approval_required=False, timeout=90)
    registry.register(
        name="lsp_definition",
        description="Exact definition of the symbol at a position, from the project's language server. Arguments: path (str), line (int, 1-based), column (int, 1-based).",
        func=lsp_definition, **common,
    )
    registry.register(
        name="lsp_references",
        description="Every reference to the symbol at a position, from the project's language server. Arguments: path (str), line (int, 1-based), column (int, 1-based).",
        func=lsp_references, **common,
    )
    registry.register(
        name="lsp_diagnostics",
        description="Type errors and other problems in a file, from the project's language server. Arguments: path (str).",
        func=lsp_diagnostics, **common,
    )
