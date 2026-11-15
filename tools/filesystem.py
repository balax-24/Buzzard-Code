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
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_ACTIVE_WORKSPACE: Optional[str] = None


MAX_EDIT_HISTORY = 50
MAX_PATCH_BYTES = 1_000_000
_PATCH_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
@dataclass(frozen=True)
class _MoveHistory:
    source: str
    destination: str
    content: bytes


_EditHistoryEntry = Tuple[str, Optional[bytes], Optional[bytes]] | _MoveHistory
# Edit entries are (path, bytes before, bytes after); moves keep source, destination and bytes.
_edit_history: List[_EditHistoryEntry] = []




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
    3. Current working directory
    The legacy data/workspace folder applies only under the test suite; in real use, a folder
    with that name would silently hide the user's project.
    """
    global _ACTIVE_WORKSPACE
    if _ACTIVE_WORKSPACE:
        return _ACTIVE_WORKSPACE

    env_ws = os.environ.get("BUZZARD_WORKSPACE")
    if env_ws:
        return os.path.abspath(env_ws)

    # Legacy test support: if data/workspace exists and no buzzard.json present
    if os.environ.get("PYTEST_CURRENT_TEST") and os.path.isdir("data/workspace") and not os.path.isfile("buzzard.json"):
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
    entry = _edit_history[-1]
    if isinstance(entry, _MoveHistory):
        if os.path.lexists(entry.source) or _read_bytes_or_none(entry.destination) != entry.content:
            return f"Cannot undo: '{entry.destination}' has changed since it was moved. Nothing was modified."
        try:
            os.replace(entry.destination, entry.source)
        except OSError as error:
            return f"Cannot undo move: {error}"
        _edit_history.pop()
        return f"Undid move: restored '{entry.source}'."
    safe_path, previous, written = entry
    if _read_bytes_or_none(safe_path) != written:
        return f"Cannot undo: '{safe_path}' has changed since the agent edited it. Nothing was modified."
    _edit_history.pop()
    if previous is None:
        os.remove(safe_path)
        return f"Undid edit: removed new file '{safe_path}'."
    with open(safe_path, "wb") as file:
        file.write(previous)
    return f"Undid edit: restored '{safe_path}'."


def file_move(source: str, destination: str) -> str:
    """Move one regular workspace file to a new, unused workspace path."""
    valid_source = isinstance(source, str) and bool(source.strip())
    valid_destination = isinstance(destination, str) and bool(destination.strip())
    if not valid_source or not valid_destination:
        return "TOOL ERROR: source and destination must be non-empty paths."
    try:
        safe_source = get_safe_path(source)
        safe_destination = get_safe_path(destination)
        normalized_source = os.path.normcase(os.path.abspath(safe_source))
        normalized_destination = os.path.normcase(os.path.abspath(safe_destination))
        if normalized_source == normalized_destination:
            return "TOOL ERROR: source and destination refer to the same path."
        if os.path.islink(safe_source) or not os.path.isfile(safe_source):
            return f"TOOL ERROR: source '{source}' must be an existing regular file, not a symlink."
        if os.path.lexists(safe_destination):
            return f"TOOL ERROR: destination '{destination}' already exists."
        if not os.path.isdir(os.path.dirname(safe_destination)):
            return f"TOOL ERROR: destination parent for '{destination}' does not exist."

        with open(safe_source, "rb") as file:
            content = file.read()
        if os.path.lexists(safe_destination) or _read_bytes_or_none(safe_source) != content:
            return "TOOL ERROR: source or destination changed while the move was being prepared."
        os.replace(safe_source, safe_destination)
        _edit_history.append(_MoveHistory(safe_source, safe_destination, content))
        del _edit_history[:-MAX_EDIT_HISTORY]
        return f"Successfully moved '{source}' to '{destination}'."
    except (OSError, ValueError) as error:
        return f"TOOL ERROR: Failed to move '{source}' to '{destination}': {error}"


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


def multi_edit(path: str, edits: List[Dict[str, Any]]) -> str:
    """Apply several validated exact replacements to one file with one atomic write."""
    if not isinstance(path, str) or not path.strip():
        return "TOOL ERROR: path must be a non-empty string."
    if not isinstance(edits, list) or not edits or len(edits) > 100:
        return "TOOL ERROR: edits must contain between 1 and 100 replacements."

    try:
        safe_path = get_safe_path(path)
        if not os.path.isfile(safe_path):
            return f"TOOL ERROR: File '{path}' does not exist or is not a regular file."
        if os.path.islink(safe_path):
            return f"TOOL ERROR: Refusing to edit symlink '{path}'."
        with open(safe_path, "rb") as file:
            previous = file.read()
        original = previous.decode("utf-8")
        updated = original
        summaries = []

        for index, edit in enumerate(edits, start=1):
            if not isinstance(edit, dict):
                return f"TOOL ERROR: edits[{index - 1}] must be an object."
            old_str = edit.get("old_str")
            new_str = edit.get("new_str")
            replace_all = edit.get("replace_all", False)
            if not isinstance(old_str, str) or not old_str:
                return f"TOOL ERROR: edits[{index - 1}].old_str must be a non-empty string."
            if not isinstance(new_str, str):
                return f"TOOL ERROR: edits[{index - 1}].new_str must be a string."
            if not isinstance(replace_all, bool):
                return f"TOOL ERROR: edits[{index - 1}].replace_all must be a boolean."
            match_count = updated.count(old_str)
            if match_count == 0:
                return f"TOOL ERROR: edits[{index - 1}] original text was not found; no changes were written."
            if match_count > 1 and not replace_all:
                return f"TOOL ERROR: edits[{index - 1}] is ambiguous ({match_count} matches); no changes were written."
            updated = updated.replace(old_str, new_str, -1 if replace_all else 1)
            summaries.append(f"{index}: {match_count} replacement(s)")

        if updated == original:
            return f"No changes needed for '{path}'."

        if _read_bytes_or_none(safe_path) != previous:
            return f"TOOL ERROR: '{path}' changed while edits were being prepared; no changes were written."

        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".buzzard-edit-", suffix=".tmp",
                dir=os.path.dirname(safe_path), delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
                temporary_file.write(updated.encode("utf-8"))
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.chmod(temporary_path, stat.S_IMODE(os.stat(safe_path).st_mode))
            os.replace(temporary_path, safe_path)
            temporary_path = None
        finally:
            if temporary_path and os.path.exists(temporary_path):
                os.unlink(temporary_path)

        _record_edit(safe_path, previous)
        diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True), updated.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}", n=3,
        ))
        return f"Successfully applied {len(edits)} edits to '{path}'.\n{'; '.join(summaries)}\n\nDiff:\n{diff}"
    except (OSError, UnicodeDecodeError, PermissionError) as error:
        return f"TOOL ERROR: Failed to apply multi_edit to '{path}': {error}"


def apply_patch(patch: str) -> str:
    """Apply a strict, UTF-8 unified patch to one or more workspace files."""
    if not isinstance(patch, str) or not patch.strip():
        return "TOOL ERROR: patch must be a non-empty unified diff string."
    try:
        patch_size = len(patch.encode("utf-8"))
    except UnicodeEncodeError as error:
        return f"TOOL ERROR: patch must be valid UTF-8 text: {error}"
    if patch_size > MAX_PATCH_BYTES:
        return f"TOOL ERROR: patch exceeds the {MAX_PATCH_BYTES}-byte limit."
    if "\x00" in patch:
        return "TOOL ERROR: patch contains a NUL character."

    try:
        file_patches = _parse_unified_patch(patch)
        if not file_patches:
            return "TOOL ERROR: patch contains no file hunks."
        planned: list[tuple[str, bytes | None, bytes | None, int]] = []
        seen_paths: set[str] = set()

        for file_patch in file_patches:
            old_name, new_name, hunks = file_patch
            relative_path = new_name if new_name != "/dev/null" else old_name
            if not relative_path or relative_path == "/dev/null":
                return "TOOL ERROR: patch file headers do not name a workspace path."
            if old_name != "/dev/null" and new_name != "/dev/null" and old_name != new_name:
                return f"TOOL ERROR: rename patches are not supported ('{old_name}' to '{new_name}')."

            safe_path = get_safe_path(relative_path)
            normalized_path = os.path.normcase(os.path.abspath(safe_path))
            if normalized_path in seen_paths:
                return f"TOOL ERROR: patch includes '{relative_path}' more than once."
            seen_paths.add(normalized_path)
            exists = os.path.lexists(safe_path)
            creating = old_name == "/dev/null"
            deleting = new_name == "/dev/null"
            if creating and exists:
                return f"TOOL ERROR: cannot create '{relative_path}'; it already exists."
            if not creating and not exists:
                return f"TOOL ERROR: cannot patch '{relative_path}'; it does not exist."
            if exists and (os.path.islink(safe_path) or not os.path.isfile(safe_path)):
                return f"TOOL ERROR: refusing to patch non-regular file or symlink '{relative_path}'."
            parent = os.path.dirname(safe_path)
            if not os.path.isdir(parent):
                return f"TOOL ERROR: parent directory for '{relative_path}' does not exist."

            previous = None
            original = ""
            file_mode = 0o644
            if exists:
                with open(safe_path, "rb") as source:
                    previous = source.read()
                original = previous.decode("utf-8")
                file_mode = stat.S_IMODE(os.stat(safe_path).st_mode)
            updated = _apply_file_hunks(original, hunks, relative_path)
            if deleting:
                if updated:
                    return f"TOOL ERROR: deletion patch for '{relative_path}' leaves content behind."
                new_bytes = None
            else:
                new_bytes = updated.encode("utf-8")
            planned.append((safe_path, previous, new_bytes, file_mode))

        return _commit_patch_transaction(planned)
    except (OSError, UnicodeDecodeError, PermissionError, ValueError) as error:
        return f"TOOL ERROR: Patch rejected without changes: {error}"


def _parse_unified_patch(
    patch: str,
) -> list[tuple[str, str, list[tuple[int, int, list[tuple[str, str, bool]]]]]]:
    """Parse standard unified file headers and hunks; reject binary or malformed patches."""
    lines = patch.splitlines(keepends=True)
    parsed: list[tuple[str, str, list[list[tuple[str, str, bool]]]]] = []
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            index += 1
            continue
        old_name = _patch_header_path(lines[index][4:])
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            raise ValueError("expected a '+++ ' file header after '--- '")
        new_name = _patch_header_path(lines[index][4:])
        index += 1
        hunks: list[tuple[int, int, list[tuple[str, str, bool]]]] = []
        while index < len(lines) and not lines[index].startswith("--- "):
            header = _PATCH_HUNK_HEADER.match(lines[index].rstrip("\r\n"))
            if not header:
                index += 1
                continue
            old_count = int(header.group(2) or "1")
            new_count = int(header.group(4) or "1")
            old_start = int(header.group(1))
            index += 1
            hunk: list[tuple[str, str, bool]] = []
            consumed_old = consumed_new = 0
            while index < len(lines) and (consumed_old < old_count or consumed_new < new_count):
                line = lines[index]
                if line.startswith("\\ No newline at end of file"):
                    if not hunk:
                        raise ValueError("newline marker has no preceding hunk line")
                    kind, text, _ = hunk[-1]
                    hunk[-1] = (kind, text, True)
                    index += 1
                    continue
                if not line or line[0] not in " +-":
                    raise ValueError("malformed unified hunk line")
                kind = line[0]
                text = line[1:].rstrip("\r\n")
                hunk.append((kind, text, False))
                consumed_old += kind in " -"
                consumed_new += kind in " +"
                index += 1
            if consumed_old != old_count or consumed_new != new_count:
                raise ValueError("unified hunk line counts do not match its header")
            while index < len(lines) and lines[index].startswith("\\ No newline at end of file"):
                if not hunk:
                    raise ValueError("newline marker has no preceding hunk line")
                kind, text, _ = hunk[-1]
                hunk[-1] = (kind, text, True)
                index += 1
            hunks.append((old_start, old_count, hunk))
        if not hunks:
            raise ValueError(f"file patch for '{old_name}' contains no hunks")
        parsed.append((old_name, new_name, hunks))
    return parsed


def _patch_header_path(value: str) -> str:
    name = value.rstrip("\r\n").split("\t", 1)[0]
    if name == "/dev/null":
        return name
    if name.startswith(("a/", "b/")):
        name = name[2:]
    if not name or "\x00" in name:
        raise ValueError("file header contains an invalid path")
    return name


def _apply_file_hunks(
    original: str,
    hunks: list[tuple[int, int, list[tuple[str, str, bool]]]],
    path: str,
) -> str:
    lines = original.splitlines()
    had_final_newline = original.endswith(("\n", "\r"))
    eol = "\r\n" if "\r\n" in original else "\n"
    offset = 0
    final_newline: bool | None = True if not original else None
    for old_start, old_count, hunk in hunks:
        old_lines = [text for kind, text, _ in hunk if kind in " -"]
        new_lines = [text for kind, text, _ in hunk if kind in " +"]
        expected = (old_start - 1 if old_count else old_start) + offset
        location = _find_hunk_location(lines, old_lines, expected)
        if location is None:
            raise ValueError(f"hunk context did not match '{path}' near line {expected + 1}")
        lines[location:location + len(old_lines)] = new_lines
        offset += len(new_lines) - len(old_lines)
        for kind, _text, no_newline in hunk:
            if no_newline and kind in " +":
                final_newline = False
    output = eol.join(lines)
    if final_newline is None:
        final_newline = had_final_newline
    return output + (eol if output and final_newline else "")


def _find_hunk_location(lines: list[str], old_lines: list[str], expected: int) -> int | None:
    if not old_lines:
        return min(max(expected, 0), len(lines))
    if lines[expected:expected + len(old_lines)] == old_lines:
        return expected
    matches = [
        position for position in range(len(lines) - len(old_lines) + 1)
        if lines[position:position + len(old_lines)] == old_lines
    ]
    return matches[0] if len(matches) == 1 else None


def _commit_patch_transaction(planned: list[tuple[str, bytes | None, bytes | None, int]]) -> str:
    staged: dict[str, str] = {}
    committed: list[str] = []
    try:
        for safe_path, previous, new_bytes, file_mode in planned:
            if new_bytes is None:
                continue
            parent = os.path.dirname(safe_path)
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".buzzard-patch-", suffix=".tmp", dir=parent, delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
                temporary_file.write(new_bytes)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.chmod(temporary_path, file_mode)
            staged[safe_path] = temporary_path

        for safe_path, previous, _new_bytes, _file_mode in planned:
            current_exists = os.path.lexists(safe_path)
            current = _read_bytes_or_none(safe_path) if current_exists else None
            if current_exists != (previous is not None) or current != previous:
                raise OSError(f"'{safe_path}' changed while the patch was being prepared")

        for safe_path, _previous, new_bytes, _file_mode in planned:
            if new_bytes is None:
                os.remove(safe_path)
            else:
                os.replace(staged.pop(safe_path), safe_path)
            committed.append(safe_path)

    except OSError as error:
        rollback_errors = []
        for safe_path in reversed(committed):
            original, mode = next(
                (previous, file_mode)
                for candidate, previous, _new_bytes, file_mode in planned
                if candidate == safe_path
            )
            try:
                if original is None:
                    if os.path.exists(safe_path):
                        os.remove(safe_path)
                else:
                    _atomic_restore(safe_path, original, mode)
            except OSError as rollback_error:
                rollback_errors.append(f"{safe_path}: {rollback_error}")
        detail = f"Patch transaction failed: {error}."
        if rollback_errors:
            detail += " Rollback also failed for " + "; ".join(rollback_errors)
        return "TOOL ERROR: " + detail
    finally:
        for temporary_path in staged.values():
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    for safe_path, previous, _new_bytes, _file_mode in planned:
        _record_edit(safe_path, previous)
    return f"Successfully applied patch to {len(planned)} file(s)."


def _atomic_restore(path: str, content: bytes, mode: int) -> None:
    with tempfile.NamedTemporaryFile(mode="wb", prefix=".buzzard-restore-", dir=os.path.dirname(path), delete=False) as file:
        temporary_path = file.name
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
    try:
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


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
        name="file_move",
        description="Moves one existing regular file to an unused path inside the workspace. The move requires approval and can be undone if the moved file is unchanged. Arguments: source (str), destination (str).",
        func=file_move,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=15,
        schema={
            "type": "object",
            "properties": {"source": {"type": "string"}, "destination": {"type": "string"}},
            "required": ["source", "destination"],
        },
    )
    registry.register(
        name="apply_patch",
        description="Applies a UTF-8 unified diff to workspace files. Existing files can be edited, new files added with /dev/null headers, and files deleted by a patch. All hunks and paths are validated before any write; the operation requests approval and rolls back earlier replacements if a later one fails. Arguments: patch (str).",
        func=apply_patch,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=True,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=60,
        schema={
            "type": "object",
            "properties": {"patch": {"type": "string"}},
            "required": ["patch"],
        },
    )
    registry.register(
        name="multi_edit",
        description="Applies multiple validated exact text replacements to one file in a single atomic write. Arguments: path (str), edits (list of {old_str, new_str, replace_all?}).",
        func=multi_edit,
        category=ToolCategory.AUTOMATION,
        risk_level="MEDIUM",
        read_only=False,
        destructive=False,
        sandbox_required=False,
        scope_required=True,
        approval_required=True,
        timeout=30,
        schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "edits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old_str": {"type": "string"},
                            "new_str": {"type": "string"},
                            "replace_all": {"type": "boolean"},
                        },
                        "required": ["old_str", "new_str"],
                    },
                },
            },
            "required": ["path", "edits"],
        },
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
