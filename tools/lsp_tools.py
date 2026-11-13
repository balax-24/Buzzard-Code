"""
Language-server tools for the coding agent (roadmap item B1): exact definitions, references
and diagnostics (read-only), plus rename (an approved edit). Positions are 1-based lines and columns, as shown by file_view.
When no language server is available the tools say so and point to the index tools.
"""

from __future__ import annotations

import difflib
import os
import re
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


MAX_RENAME_FILES = 200
MAX_DIFF_CHARS = 8000
_NAME = re.compile(r"^[^\s]{1,200}$")


def _offset(text: str, line_starts: List[int], position: Dict[str, Any]) -> int:
    """String index of an LSP position. LSP columns count UTF-16 code units by default."""
    line = int(position.get("line", 0))
    if line >= len(line_starts):
        return len(text)
    start = line_starts[line]
    end = line_starts[line + 1] if line + 1 < len(line_starts) else len(text)
    wanted, units, index = int(position.get("character", 0)), 0, start
    while index < end and units < wanted and text[index] not in "\r\n":
        units += 2 if ord(text[index]) > 0xFFFF else 1
        index += 1
    return index


def apply_text_edits(text: str, edits: List[Dict[str, Any]]) -> str:
    """Applies LSP TextEdits to a document. Overlapping edits are refused."""
    line_starts = [0] + [match.end() for match in re.finditer(r"\r\n|\r|\n", text)]
    spans = []
    for item in edits:
        span = item.get("range") or {}
        start, end = _offset(text, line_starts, span.get("start", {})), _offset(text, line_starts, span.get("end", {}))
        if end < start:
            raise LspError("the language server sent an edit whose end is before its start")
        spans.append((start, end, str(item.get("newText", ""))))
    spans.sort()
    for (_, previous_end, _), (next_start, _, _) in zip(spans, spans[1:]):
        if next_start < previous_end:
            raise LspError("the language server sent overlapping edits")
    for start, end, new_text in reversed(spans):
        text = text[:start] + new_text + text[end:]
    return text


def _edits_by_file(workspace_edit: Any) -> Dict[str, List[Dict[str, Any]]]:
    if not isinstance(workspace_edit, dict):
        return {}
    by_uri: Dict[str, List[Dict[str, Any]]] = {}
    for change in workspace_edit.get("documentChanges") or []:
        if "kind" in change:  # create, rename or delete a file: never applied automatically
            raise LspError(f"the rename also wants to {change.get('kind')} a file, which lsp_rename does not do")
        uri = (change.get("textDocument") or {}).get("uri")
        if uri:
            by_uri.setdefault(uri, []).extend(change.get("edits") or [])
    if not by_uri:
        for uri, edits in (workspace_edit.get("changes") or {}).items():
            by_uri.setdefault(uri, []).extend(edits or [])
    return by_uri


def lsp_rename(path: str, line: int, column: int, new_name: str) -> str:
    """
    Renames the symbol at a position everywhere it is used, with the project's language server.
    All files are checked first and written together; if any write fails, the others are restored.
    Arguments:
        path: Source file. line, column: 1-based position of the symbol. new_name: The new name.
    """
    from tools.filesystem import _atomic_restore, _record_edit

    root = Path(get_active_workspace())
    if not isinstance(new_name, str) or not _NAME.match(new_name):
        return "TOOL ERROR: new_name must be 1-200 characters with no spaces or line breaks."
    try:
        target = _target(path)
        server = get_lsp_manager().server_for(root, str(target))
        if not server.capabilities.get("renameProvider"):
            raise LspError("this language server does not support rename")
        uri = server.sync(target)
        result = server.request("textDocument/rename", {
            "textDocument": {"uri": uri}, "position": _position(line, column), "newName": new_name})
        by_uri = _edits_by_file(result)
        if not by_uri:
            return "The language server found nothing to rename at that position."
        if len(by_uri) > MAX_RENAME_FILES:
            raise LspError(f"the rename touches {len(by_uri)} files, more than {MAX_RENAME_FILES}")
        planned = []  # (safe path, original bytes, new text, edit count)
        for file_uri, edits in by_uri.items():
            file_path = uri_to_path(file_uri)
            try:
                safe = Path(get_safe_path(str(file_path)))
            except PermissionError:
                raise LspError(f"the rename reaches {file_path}, outside the workspace; nothing was changed") from None
            if safe.is_symlink() or not safe.is_file():
                raise LspError(f"{file_path} is not a regular file; nothing was changed")
            original = safe.read_bytes()
            updated = apply_text_edits(original.decode("utf-8"), edits)
            planned.append((safe, original, updated, len(edits)))
    except LspError as error:
        return _fallback(error, "Use code_references to find each use, then multi_edit.")
    except (OSError, UnicodeDecodeError) as error:
        return f"TOOL ERROR: rename not applied: {error}"

    written = []
    try:
        for safe, original, updated, _ in planned:
            if safe.read_bytes() != original:
                raise OSError(f"{safe.name} changed while the rename was being prepared")
            _atomic_restore(str(safe), updated.encode("utf-8"), safe.stat().st_mode & 0o7777)
            written.append((safe, original))
    except OSError as error:
        for safe, original in reversed(written):
            _atomic_restore(str(safe), original, safe.stat().st_mode & 0o7777)
        return f"TOOL ERROR: rename not applied ({error}); every file was restored."
    diffs, rows = [], []
    for safe, original, updated, count in planned:
        _record_edit(str(safe), original)
        shown = os.path.relpath(safe.resolve(), root.resolve()).replace("\\", "/")
        rows.append(f"- {shown}: {count} edit(s)")
        diffs.append("".join(difflib.unified_diff(
            original.decode("utf-8").splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=f"a/{shown}", tofile=f"b/{shown}", n=1)))
        try:
            server.sync(safe)  # tell the server about the new content
        except (LspError, OSError):
            pass  # the files are written; a stale server view only affects later lsp_* answers
    diff = "".join(diffs)
    if len(diff) > MAX_DIFF_CHARS:
        diff = diff[:MAX_DIFF_CHARS] + "\n... diff truncated; use git_diff for the rest."
    return f"Renamed to '{new_name}' in {len(planned)} file(s):\n" + "\n".join(rows) + f"\n\nDiff:\n{diff}"


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
    registry.register(
        name="lsp_rename",
        description="Renames the symbol at a position in every file that uses it, with the project's language server; all files change together or none do. Arguments: path (str), line (int, 1-based), column (int, 1-based), new_name (str).",
        func=lsp_rename, category=ToolCategory.AUTOMATION, risk_level="MEDIUM", read_only=False, destructive=False,
        sandbox_required=False, scope_required=True, approval_required=True, timeout=120,
    )
