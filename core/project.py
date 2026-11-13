"""
Project Initialization and Custom Command Loader for Buzzard Code.

Manages:
- 'buzzard init' project scaffolding
- Dynamic custom commands (.buzzard/commands/*.md)
- Safe overwrite checks and gitignore protection
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

from core.config import DEFAULT_CONFIG

SAMPLE_SCAN_MD = """---
description: Perform quick port and service enumeration on an authorized target
args: [target]
---
Perform a thorough reconnaissance and service enumeration on target: {{target}}.
Identify open ports, active services, protocol versions, and potential entry points.
Log all discoveries as structured evidence.
"""

SAMPLE_AUDIT_MD = """---
description: Conduct comprehensive vulnerability audit against authorized target
args: [target, goal]
---
Perform an authorized vulnerability assessment against {{target}}.
Goal: {{goal}}
Inspect web endpoints, headers, and API methods. Validate any potential security risks safely.
"""

SAMPLE_RECON_MD = """---
description: Passive and active domain/DNS intelligence gathering
args: [domain]
---
Collect comprehensive DNS, subdomain, and domain intelligence for {{domain}}.
Query records, certificate transparency logs, and map all accessible assets.
"""

SAMPLE_EXPLAIN_MD = """---
description: Explain a security finding or vulnerability in depth
args: [finding]
---
Provide an in-depth security analysis and risk breakdown for: {{finding}}.
Explain root causes, attack vectors, remediation strategies, and verification steps.
"""

def init_project(
    target_dir: Optional[Union[str, Path]] = None,
    force: bool = False
) -> Tuple[bool, str, List[Path]]:
    """
    Initializes a Buzzard Code project environment.
    Creates:
    - buzzard.json (project configuration)
    - .buzzard/commands/ (custom user commands)
    - .buzzard/policies/ (local policy overrides)
    - .buzzard/sessions/ (local session storage)
    - .gitignore entries for session data & secrets
    """
    root = Path(target_dir) if target_dir else Path.cwd()
    buzzard_json = root / "buzzard.json"
    buzzard_dir = root / ".buzzard"
    commands_dir = buzzard_dir / "commands"
    policies_dir = buzzard_dir / "policies"
    sessions_dir = buzzard_dir / "sessions"

    created_paths: List[Path] = []

    if buzzard_json.exists() and not force:
        return False, f"Project already initialized at {root} (buzzard.json exists). Use --force to overwrite.", []

    # 1. Create directories
    commands_dir.mkdir(parents=True, exist_ok=True)
    policies_dir.mkdir(parents=True, exist_ok=True)
    sessions_dir.mkdir(parents=True, exist_ok=True)

    # 2. Write project config
    clean_cfg = dict(DEFAULT_CONFIG)
    buzzard_json.write_text(json.dumps(clean_cfg, indent=2), encoding="utf-8")
    created_paths.append(buzzard_json)

    # 3. Write default custom commands
    custom_commands = {
        "scan.md": SAMPLE_SCAN_MD,
        "audit.md": SAMPLE_AUDIT_MD,
        "recon.md": SAMPLE_RECON_MD,
        "explain.md": SAMPLE_EXPLAIN_MD,
    }
    for fname, content in custom_commands.items():
        cmd_path = commands_dir / fname
        if not cmd_path.exists() or force:
            cmd_path.write_text(content.strip() + "\n", encoding="utf-8")
            created_paths.append(cmd_path)

    # 4. Update .gitignore if present or create one
    gitignore = root / ".gitignore"
    ignore_entries = [
        "\n# Buzzard Code local runtime & secrets",
        ".buzzard/sessions/",
        "credentials.json",
        "*.kill",
    ]
    if gitignore.exists():
        existing = gitignore.read_text(encoding="utf-8", errors="replace")
        to_append = [e for e in ignore_entries if e and e not in existing]
        if to_append:
            with open(gitignore, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(to_append) + "\n")
    else:
        gitignore.write_text("\n".join(ignore_entries).strip() + "\n", encoding="utf-8")
        created_paths.append(gitignore)

    return True, f"Buzzard Code project initialized successfully at {root}", created_paths

def parse_markdown_command(content: str) -> Dict[str, Any]:
    """
    Parses a markdown custom command file containing frontmatter or markdown sections.
    """
    description = ""
    args = []
    body = content

    # Check YAML-style frontmatter
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
    if fm_match:
        fm_text = fm_match.group(1)
        body = fm_match.group(2).strip()
        for line in fm_text.splitlines():
            line = line.strip()
            if line.startswith("description:"):
                description = line.split(":", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("args:"):
                raw_args = line.split(":", 1)[1].strip()
                if raw_args.startswith("[") and raw_args.endswith("]"):
                    args = [a.strip().strip('"').strip("'") for a in raw_args[1:-1].split(",") if a.strip()]

    if not description:
        # Fallback: extract first heading or first line
        lines = body.splitlines()
        for l in lines:
            if l.startswith("#"):
                description = l.lstrip("#").strip()
                break
        if not description and lines:
            description = lines[0].strip()

    return {
        "description": description or "Custom security command",
        "args": args,
        "template": body
    }

MAX_COMMAND_BYTES = 20_000
_COMMAND_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")


def _user_commands_directory() -> Path:
    import os

    return Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "commands"


def load_custom_commands(project_dir: Optional[Union[str, Path]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Discovers custom markdown commands: the project's .buzzard/commands/*.md, then the user's
    ~/.buzzard/commands/*.md (which win on a name clash). The project folder defaults to the
    active workspace. A command is only prompt text; it runs nothing by itself.
    """
    if project_dir is None:
        from tools.filesystem import get_active_workspace

        project_dir = get_active_workspace()
    commands: Dict[str, Dict[str, Any]] = {}
    for cmd_dir, source in ((Path(project_dir) / ".buzzard" / "commands", "project"), (_user_commands_directory(), "user")):
        if not cmd_dir.is_dir() or cmd_dir.is_symlink():
            continue
        for md_file in sorted(cmd_dir.glob("*.md")):
            cmd_name = md_file.stem.lower()
            if not _COMMAND_NAME.match(cmd_name) or md_file.is_symlink():
                continue
            try:
                if md_file.stat().st_size > MAX_COMMAND_BYTES:
                    continue
                parsed = parse_markdown_command(md_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            parsed["name"] = cmd_name
            parsed["file_path"] = str(md_file)
            parsed["source"] = source
            commands[cmd_name] = parsed
    return commands


def render_custom_command_prompt(
    cmd_def: Dict[str, Any],
    provided_args: List[str]
) -> str:
    """
    Renders the custom prompt template by interpolating arguments.
    """
    template = cmd_def.get("template", "")
    declared_args = cmd_def.get("args", [])
    if "$ARGUMENTS" in template:
        return template.replace("$ARGUMENTS", " ".join(provided_args))

    # Replace declared positional args
    for i, arg_name in enumerate(declared_args):
        val = provided_args[i] if i < len(provided_args) else f"<{arg_name}>"
        template = template.replace(f"{{{{{arg_name}}}}}", val)

    # If extra args, append
    if len(provided_args) > len(declared_args):
        extra = " ".join(provided_args[len(declared_args):])
        template += f"\nAdditional context: {extra}"

    return template


def expand_custom_command(
    text: str, project_dir: Optional[Union[str, Path]] = None, reserved: Optional[List[str]] = None
) -> Optional[str]:
    """The task text for `/name arguments` when `name` is a custom command (not a built-in), else None."""
    stripped = (text or "").strip()
    if not stripped.startswith("/"):
        return None
    name, *arguments = stripped[1:].split()
    name = name.lower()
    if reserved and name in {item.lstrip("/").lower() for item in reserved}:
        return None
    command = load_custom_commands(project_dir).get(name)
    if command is None:
        return None
    return render_custom_command_prompt(command, arguments)
