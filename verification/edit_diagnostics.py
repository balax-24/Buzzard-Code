"""Fast, side-effect-free syntax diagnostics for files after an agent edit."""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from tools.filesystem import get_safe_path


EDIT_TOOLS = frozenset({"file_edit", "file_write", "file_move", "multi_edit", "apply_patch", "lsp_rename"})
_PATCH_FILE_HEADER = re.compile(r"^\+\+\+ (.+?)(?:\t.*)?$")


def edited_paths(tool_name: str, arguments: dict[str, Any]) -> list[str]:
    """Extract file paths changed by a supported editing tool call."""
    if tool_name in {"file_edit", "file_write", "multi_edit", "lsp_rename"}:
        path = arguments.get("path")
        return [path] if isinstance(path, str) and path else []
    if tool_name == "file_move":
        destination = arguments.get("destination")
        return [destination] if isinstance(destination, str) and destination else []
    if tool_name != "apply_patch":
        return []

    patch = arguments.get("patch")
    if not isinstance(patch, str):
        return []
    result = []
    for line in patch.splitlines():
        match = _PATCH_FILE_HEADER.match(line)
        if not match:
            continue
        path = match.group(1)
        if path == "/dev/null":
            continue
        if path.startswith(("a/", "b/")):
            path = path[2:]
        result.append(path)
    return result


def diagnose_edited_files(tool_name: str, arguments: dict[str, Any]) -> list[str]:
    """Parse edited Python and JSON files; return actionable diagnostics without running commands."""
    if tool_name not in EDIT_TOOLS:
        return []
    diagnostics: list[str] = []
    seen: set[str] = set()
    for raw_path in edited_paths(tool_name, arguments):
        try:
            safe_path = get_safe_path(raw_path)
            canonical_path = os.path.normcase(os.path.abspath(safe_path))
            if canonical_path in seen:
                continue
            seen.add(canonical_path)
            path = Path(safe_path)
            if not path.is_file() or path.suffix.lower() not in {".py", ".json"}:
                continue
            source = path.read_text(encoding="utf-8")
            if path.suffix.lower() == ".py":
                try:
                    ast.parse(source, filename=path.name)
                except SyntaxError as error:
                    diagnostics.append(
                        f"{raw_path}:{error.lineno or 1}: Python syntax error: {error.msg}"
                    )
            else:
                try:
                    json.loads(source)
                except json.JSONDecodeError as error:
                    diagnostics.append(
                        f"{raw_path}:{error.lineno}: JSON syntax error: {error.msg}"
                    )
        except (OSError, UnicodeError, PermissionError, ValueError) as error:
            diagnostics.append(f"{raw_path}: could not collect syntax diagnostics: {error}")
    return diagnostics
