"""Workspace and user permission rules that can only tighten tool policy."""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EFFECTS = frozenset({"allow", "ask", "deny"})
MODES = frozenset({"default", "ask", "accept_edits_ask_commands"})
EDIT_TOOLS = frozenset({"file_edit", "file_write", "file_move", "multi_edit", "apply_patch", "lsp_rename"})
COMMAND_TOOLS = frozenset({"terminal.execute"})
MAX_RULES = 1000
MAX_CONFIG_BYTES = 1_000_000


class PermissionConfigError(ValueError):
    """A permission file is malformed or unsafe to read."""


@dataclass(frozen=True)
class PermissionConfig:
    mode: str
    rules: tuple[dict[str, str], ...]


def user_permissions_path() -> Path:
    """Return the user-level permissions file without creating its parent directory."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / ".config") / "buzzard"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "buzzard"
    return base / "permissions.json"


def _read_config(path: Path, *, repository_root: Path | None) -> PermissionConfig:
    if not path.exists():
        return PermissionConfig("default", ())
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise PermissionConfigError(f"{path} exceeds the 1 MB size limit")
        if repository_root is not None:
            resolved = path.resolve(strict=True)
            resolved.relative_to(repository_root)
        raw = json.loads(path.read_text(encoding="utf-8"))
    except PermissionConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise PermissionConfigError(f"cannot read {path}: {error}") from error
    version = raw.get("version") if isinstance(raw, dict) else None
    if not isinstance(raw, dict) or isinstance(version, bool) or version != 1:
        raise PermissionConfigError(f"{path} must be a JSON object with version: 1")
    mode = raw.get("mode", "default")
    if not isinstance(mode, str) or mode not in MODES:
        raise PermissionConfigError(f"{path} mode must be one of: {', '.join(sorted(MODES))}")
    rules = raw.get("rules", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise PermissionConfigError(f"{path} rules must be a list with at most {MAX_RULES} entries")
    validated = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PermissionConfigError(f"{path} rules[{index}] must be an object")
        effect, tool = rule.get("effect"), rule.get("tool")
        argument, pattern = rule.get("argument"), rule.get("pattern")
        if not isinstance(effect, str) or effect not in EFFECTS:
            raise PermissionConfigError(f"{path} rules[{index}].effect must be allow, ask or deny")
        if not isinstance(tool, str) or not tool.strip():
            raise PermissionConfigError(f"{path} rules[{index}].tool must be a non-empty string")
        if argument is None and pattern is not None:
            raise PermissionConfigError(f"{path} rules[{index}] needs an argument when pattern is set")
        if argument is not None and (not isinstance(argument, str) or not argument.strip()):
            raise PermissionConfigError(f"{path} rules[{index}].argument must be a non-empty string")
        if pattern is not None and (not isinstance(pattern, str) or len(pattern) > 512):
            raise PermissionConfigError(f"{path} rules[{index}].pattern must be a string up to 512 characters")
        if set(rule) - {"effect", "tool", "argument", "pattern"}:
            raise PermissionConfigError(f"{path} rules[{index}] contains unsupported fields")
        validated.append({
            "effect": effect,
            "tool": tool.strip(),
            "argument": argument or "",
            "pattern": pattern or "",
        })
    return PermissionConfig(mode, tuple(validated))


def _matched_effect(config: PermissionConfig, tool: str, arguments: dict[str, Any]) -> str | None:
    matched = []
    for rule in config.rules:
        if rule["tool"] not in {"*", tool}:
            continue
        argument = rule["argument"]
        if argument:
            value = arguments.get(argument)
            if not isinstance(value, str) or not fnmatch.fnmatchcase(value, rule["pattern"]):
                continue
        matched.append(rule["effect"])
    # Deny and ask are monotonic restrictions when several rules match.
    if "deny" in matched:
        return "deny"
    if "ask" in matched:
        return "ask"
    if "allow" in matched:
        return "allow"
    return None


def _mode_effect(mode: str, tool: str) -> str | None:
    if mode == "ask":
        return "ask"
    if mode == "accept_edits_ask_commands":
        if tool in EDIT_TOOLS:
            return "allow"
        if tool in COMMAND_TOOLS:
            return "ask"
    return None


def permission_effect(tool: str, arguments: dict[str, Any], workspace: str | Path) -> str | None:
    """Resolve a rule to allow/ask/deny; repository settings never weaken user settings."""
    root = Path(workspace).resolve()
    project_config = _read_config(root / ".buzzard" / "permissions.json", repository_root=root)
    user_config = _read_config(user_permissions_path(), repository_root=None)

    user_effect = _matched_effect(user_config, tool, arguments) or _mode_effect(user_config.mode, tool)
    project_effect = _matched_effect(project_config, tool, arguments) or _mode_effect(project_config.mode, tool)

    if "deny" in {user_effect, project_effect}:
        return "deny"
    if project_effect == "ask" or user_effect == "ask":
        return "ask"
    if user_effect == "allow":
        return "allow"
    # A project allow is deliberately ignored: a repository cannot grant permissions.
    return None
