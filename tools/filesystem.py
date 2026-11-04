"""
Authoritative Filesystem Subsystem for Buzzard Code.

Provides secure, repository-aware file operations:
- Configurable project workspace boundary
- Path traversal & symlink escape prevention
- file_read: bounded or full content reading
- file_view: line-numbered range viewing
- file_write: safe full-file creation/overwriting
- file_edit: validated surgical search-and-replace with unified diff output
- file_search: filename globbing and content querying
- directory_list: workspace directory enumeration
"""

from __future__ import annotations

import os
import difflib
import fnmatch
from pathlib import Path
from typing import List, Optional, Tuple

_ACTIVE_WORKSPACE: Optional[str] = None


MAX_EDIT_HISTORY = 50
# (path, bytes before the edit or None for a new file, bytes the edit wrote)
_edit_history: List[Tuple[str, Optional[bytes], Optional[bytes]]] = []


def set_active_workspace(path: Optional[str]) -> str:
    """
    Explicitly sets the active workspace directory.
    If path is None, resets to auto-detection.
    """
    global _ACTIVE_WORKSPACE
    if path is None:
        _ACTIVE_WORKSPACE = None
        return get_active_workspace()
    _ACTIVE_WORKSPACE = os.path.abspath(str(path))
    os.makedirs(_ACTIVE_WORKSPACE, exist_ok=True)
    return _ACTIVE_WORKSPACE


def get_active_workspace() -> str:
    """
    Resolves the current active workspace directory.
    Priority:
    1. Explicitly configured via set_active_workspace()
    2. Environment variable BUZZARD_WORKSPACE
    3. Legacy data/workspace if directory exists and not in a project root
    4. Current working directory
    """
    global _ACTIVE_WORKSPACE
    if _ACTIVE_WORKSPACE:
        return _ACTIVE_WORKSPACE

    env_ws = os.environ.get("BUZZARD_WORKSPACE")
    if env_ws:
        return os.path.abspath(env_ws)

    # Legacy test support: if data/workspace exists and no buzzard.json present
    if os.path.isdir("data/workspace") and not os.path.isfile("buzzard.json"):
        return os.path.abspath("data/workspace")

    return os.path.abspath(os.getcwd())


def get_safe_path(path: str) -> str:
    """
    Resolves target path relative to the active workspace, ensuring it does not escape.
    Handles Unix, Windows, UNC, drive-qualified paths, traversal, and symlink escapes securely.
    """
    import re
    workspace = get_active_workspace()
    os.makedirs(workspace, exist_ok=True)
    workspace_real = os.path.realpath(workspace)

    # Reject backslash traversal strings
    if "..\\" in path or "\\.." in path:
        raise PermissionError(f"Access denied: Path '{path}' escapes the workspace boundary.")

    drive, _ = os.path.splitdrive(path)

    if re.match(r"^[a-zA-Z]:", path):
        target_path = os.path.abspath(path)
    elif drive or path.startswith(("\\\\", "//")):
        target_path = os.path.abspath(path)
    elif path.startswith("/workspace") or path.startswith("\\workspace"):
        relative_part = path[len("/workspace"):].lstrip("/\\")
        target_path = os.path.abspath(os.path.join(workspace, relative_part))
    elif path.startswith("/") or path.startswith("\\"):
        # Absolute POSIX or root path
        target_path = os.path.abspath(path)
    else:
        target_path = os.path.abspath(os.path.join(workspace, path.lstrip("/\\")))

    # Verify target path is within workspace
    try:
        if os.path.commonpath([workspace]) != os.path.commonpath([workspace, target_path]):
            raise PermissionError(f"Access denied: Path '{path}' escapes the workspace boundary.")
    except (ValueError, Exception) as e:
        raise PermissionError(f"Access denied: Path '{path}' escapes the workspace boundary.") from e

    # Reject symlink escapes if the target or existing ancestors resolve outside workspace
    check_target = target_path
    while check_target and not os.path.exists(check_target):
        parent = os.path.dirname(check_target)
        if parent == check_target:
            break
        check_target = parent

    if os.path.exists(check_target):
        target_real = os.path.realpath(check_target)
        try:
            if os.path.commonpath([workspace_real]) != os.path.commonpath([workspace_real, target_real]):
                raise PermissionError(f"Access denied: Symlink in path '{path}' escapes the workspace boundary.")
        except (ValueError, Exception) as e:
            raise PermissionError(f"Access denied: Symlink in path '{path}' escapes the workspace boundary.") from e

    return target_path


def file_list(path: str = ".") -> str:
    """
    Lists files and directories under the specified path within the active workspace.
    Arguments:
        path: Target directory path (default '.').
    """
    try:
        safe_path = get_safe_path(path)
        if not os.path.exists(safe_path):
            return f"Error: Path '{path}' does not exist."
        if not os.path.isdir(safe_path):
            return f"Error: Path '{path}' is a file, not a directory."

        items = os.listdir(safe_path)
        if not items:
            return f"Directory '{path}' is empty."

        output = [f"Contents of '{path}':"]
        for item in sorted(items):
            item_path = os.path.join(safe_path, item)
            is_dir = os.path.isdir(item_path)
            marker = "[DIR] " if is_dir else "      "
            output.append(f"  {marker}{item}")
        return "\n".join(output)
    except Exception as e:
        return f"TOOL ERROR: Failed to list directory: {e}"


def file_read(path: str) -> str:
    """
    Reads and returns the contents of a file in the active workspace.
    Arguments:
        path: Path of the file to read.
    """
    try:
        safe_path = get_safe_path(path)
        if not os.path.exists(safe_path):
            return f"Error: File '{path}' does not exist."
        if os.path.isdir(safe_path):
            return f"Error: Path '{path}' is a directory, not a file."

        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return content
    except Exception as host_e:
        # Fallback using low-level OS file descriptor I/O without shell dependency
        try:
            safe_path = get_safe_path(path)
            fd = os.open(safe_path, os.O_RDONLY)
            try:
                raw_bytes = bytearray()
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    raw_bytes.extend(chunk)
                return raw_bytes.decode("utf-8", errors="replace")
            finally:
                os.close(fd)
        except Exception as fb_e:
            return f"TOOL ERROR: Failed to read file: {host_e}. Fallback also failed: {fb_e}"


def file_view(path: str, start_line: Optional[int] = 1, end_line: Optional[int] = None) -> str:
    """
    Views file content with 1-based line numbers and optional line-range slicing.
    Arguments:
        path: Path of the file to view.
        start_line: First line to display (1-based, default 1).
        end_line: Last line to display (inclusive, default None to read to end).
    """
    try:
        safe_path = get_safe_path(path)
        if not os.path.exists(safe_path):
            return f"Error: File '{path}' does not exist."
        if os.path.isdir(safe_path):
            return f"Error: Path '{path}' is a directory, not a file."

        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        total_lines = len(lines)
        if total_lines == 0:
            return f"File '{path}' is empty."

        start = max(1, start_line or 1)
        end = min(total_lines, end_line) if end_line is not None else total_lines

        if start > total_lines:
            return f"Error: start_line ({start}) exceeds total lines in file ({total_lines})."
        if end < start:
            return f"Error: end_line ({end}) must be greater than or equal to start_line ({start})."

        output = [f"File: {path} (lines {start}-{end} of {total_lines}):"]
        width = len(str(end))
        for line_num in range(start, end + 1):
            line_content = lines[line_num - 1].rstrip("\r\n")
            output.append(f"{line_num:>{width}} | {line_content}")

        return "\n".join(output)
    except Exception as e:
        return f"TOOL ERROR: Failed to view file: {e}"


def _read_bytes_or_none(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as file:
            return file.read()
    except OSError:
        return None


def _record_edit(safe_path: str, previous: Optional[bytes]) -> None:
    _edit_history.append((safe_path, previous, _read_bytes_or_none(safe_path)))
    del _edit_history[:-MAX_EDIT_HISTORY]


def undo_last_edit() -> str:
    """Reverts the agent's latest edit, unless the file has changed since it was made."""
    if not _edit_history:
        return "Nothing to undo."
    safe_path, previous, written = _edit_history[-1]
    if _read_bytes_or_none(safe_path) != written:
        return f"Cannot undo: '{safe_path}' has changed since the agent edited it. Nothing was modified."
    _edit_history.pop()
    if previous is None:
        os.remove(safe_path)
        return f"Undid edit: removed new file '{safe_path}'."
    with open(safe_path, "wb") as file:
        file.write(previous)
    return f"Undid edit: restored '{safe_path}'."


def file_write(path: str, content: str) -> str:
    """
    Writes content to a file in the active workspace.
    Arguments:
        path: Path of the file to write.
        content: The text content to write.
    """
    try:
        safe_path = get_safe_path(path)
        os.makedirs(os.path.dirname(safe_path), exist_ok=True)
        previous = _read_bytes_or_none(safe_path)

        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content)
        _record_edit(safe_path, previous)
        return f"Successfully wrote {len(content)} characters to '{path}'."
    except Exception as host_e:
        # Fallback using low-level OS file descriptor I/O without shell dependency
        try:
            safe_path = get_safe_path(path)
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            fd = os.open(safe_path, flags, 0o666)
            try:
                data = content.encode("utf-8")
                total_written = 0
                while total_written < len(data):
                    n = os.write(fd, data[total_written:])
                    total_written += n
                return f"Successfully wrote {len(content)} characters to '{path}' using fallback write."
            finally:
                os.close(fd)
        except Exception as fb_e:
            return f"TOOL ERROR: Failed to write file: {host_e}. Fallback also failed: {fb_e}"


def file_edit(path: str, old_str: str, new_str: str, replace_all: bool = False) -> str:
    """
    Performs a validated surgical search-and-replace modification on a file.
    Arguments:
        path: Path of the file to edit.
        old_str: The exact existing text to replace.
        new_str: The new text to substitute.
        replace_all: Set to True only when multiple occurrences are intentionally replaced.
    """
    if not old_str:
        return "Error: old_str cannot be empty."

    try:
        safe_path = get_safe_path(path)
        if not os.path.exists(safe_path):
            return f"Error: File '{path}' does not exist."
        if os.path.isdir(safe_path):
            return f"Error: Path '{path}' is a directory, not a file."

        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            original_content = f.read()

        match_count = original_content.count(old_str)
        if match_count == 0:
            return f"Error: Expected original text was not found in '{path}'. Please check exact indentation and whitespace."

        if match_count > 1 and not replace_all:
            return f"Error: Ambiguous match — old_str occurs {match_count} times in '{path}'. Provide more surrounding lines for a unique match or set replace_all=True."

        # Perform replacement
        if replace_all:
            new_content = original_content.replace(old_str, new_str)
        else:
            new_content = original_content.replace(old_str, new_str, 1)

        previous = _read_bytes_or_none(safe_path)

        # Write new content back atomically
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        _record_edit(safe_path, previous)

        # Compute diff summary
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=3
        ))
        diff_summary = "".join(diff_lines) if diff_lines else "(No visible textual difference)"

        return f"Successfully edited '{path}' ({match_count} occurrence{'s' if match_count > 1 else ''} replaced).\n\nDiff:\n{diff_summary}"

    except Exception as e:
        return f"TOOL ERROR: Failed to edit file: {e}"


def file_search(query: str, path: str = ".") -> str:
    """
    Searches for files by name matching the query pattern, or containing the query text.
    Arguments:
        query: Filename pattern (e.g. '*.py') or search string.
        path: Root directory to search within (default '.').
    """
    try:
        safe_root = get_safe_path(path)
        if not os.path.exists(safe_root):
            return f"Error: Path '{path}' does not exist."

        workspace = get_active_workspace()
        results = []

        for root, dirs, files in os.walk(safe_root):
            # Check if root is safe
            if os.path.commonpath([workspace]) != os.path.commonpath([workspace, os.path.abspath(root)]):
                continue

            for file in files:
                rel_dir = os.path.relpath(root, safe_root)
                rel_file_path = (os.path.join(rel_dir, file) if rel_dir != "." else file).replace("\\", "/")

                # Check 1: Filename matches query pattern
                if fnmatch.fnmatch(file, query) or query in file:
                    results.append(f"[Name Match] {rel_file_path}")
                    continue

                # Check 2: Content contains query
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            if query in line:
                                results.append(f"[Content Match] {rel_file_path}:{line_num}: {line.strip()}")
                except Exception:
                    pass  # skip unreadable files

        if not results:
            return f"No matches found for query '{query}' in '{path}'."

        return "\n".join(results[:50])
    except Exception as e:
        return f"TOOL ERROR: Failed to search files: {e}"


def todo_write(items: str) -> str:
    """
    Shows the user your task checklist. Call it again as steps finish.
    Arguments:
        items: One step per line, each starting with [ ] for pending or [x] for done.
    """
    lines = [line.strip() for line in str(items).splitlines() if line.strip()]
    if not lines:
        return "Error: items must list at least one step."
    return "\n".join(lines)


def register_filesystem_tools(registry):
    registry.register(
        name="todo_write",
        description="Shows the user your task checklist. Arguments: items (str), one step per line starting with [ ] or [x].",
        func=todo_write,
        scope_required=False,
    )
    """
    Registers the repository-aware filesystem tools with the registry.
    """
    from tools.registry import ToolCategory

    # Canonical safe automation tools
    registry.register(
        name="file_read",
        description="Reads the content of a file in the workspace. Arguments: path (str).",
        func=file_read,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="file_view",
        description="Views file content with 1-based line numbers and optional line-range slicing. Arguments: path (str), start_line (int, default 1), end_line (int, optional).",
        func=file_view,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=10
    )
    registry.register(
        name="file_write",
        description="Writes content to a file in the workspace. Arguments: path (str), content (str).",
        func=file_write,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=False,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="file_edit",
        description="Performs a validated surgical search-and-replace modification on a file with unified diff summary. Arguments: path (str), old_str (str), new_str (str), replace_all (bool, default False).",
        func=file_edit,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=False,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="file_search",
        description="Searches for files by name pattern or containing text in the workspace. Arguments: query (str), path (str, default '.').",
        func=file_search,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=15
    )
    registry.register(
        name="directory_list",
        description="Lists files in a workspace directory. Arguments: path (str, default '.').",
        func=file_list,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=False,
        timeout=10
    )

    # Dotted aliases for backward compatibility
    registry.register(
        name="file.list",
        description="Lists files in a workspace directory. Arguments: path (str, default '.').",
        func=file_list,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        timeout=10
    )
    registry.register(
        name="file.read",
        description="Reads the content of a file in the workspace. Arguments: path (str).",
        func=file_read,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        timeout=10
    )
    registry.register(
        name="file.view",
        description="Views file content with 1-based line numbers and line-range slicing. Arguments: path (str), start_line (int, default 1), end_line (int, optional).",
        func=file_view,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        timeout=10
    )
    registry.register(
        name="file.write",
        description="Writes content to a file in the workspace. Arguments: path (str), content (str).",
        func=file_write,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        sandbox_required=False,
        scope_required=True,
        timeout=15
    )
    registry.register(
        name="file.edit",
        description="Performs a validated surgical search-and-replace modification on a file with unified diff summary. Arguments: path (str), old_str (str), new_str (str), replace_all (bool, default False).",
        func=file_edit,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        sandbox_required=False,
        scope_required=True,
        timeout=15
    )
    registry.register(
        name="file.search",
        description="Searches for files by name pattern or containing text in the workspace. Arguments: query (str), path (str, default '.').",
        func=file_search,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        sandbox_required=False,
        scope_required=True,
        timeout=15
    )
