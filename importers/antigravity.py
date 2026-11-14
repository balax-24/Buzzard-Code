"""
Importer for Antigravity (Gemini) transcripts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from importers.base import ImportedMessage, ImportedSession, sanitize_session_id


def import_antigravity_session(file_path: Path | str) -> ImportedSession:
    """Parses an Antigravity transcript.jsonl into an ImportedSession."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Antigravity transcript file not found: {path}")

    session_id: Optional[str] = None
    workspace: Optional[str] = None
    messages: List[ImportedMessage] = []
    files_touched: Set[str] = set()

    # Look for parent conversation id if in standard path structure (.../brain/<id>/...)
    for part in path.parts:
        if len(part) == 36 and part.count("-") == 4:  # UUID
            session_id = part
            break

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue

            rec_source = record.get("source")
            rec_type = record.get("type")
            content = record.get("content", "")
            tool_calls = record.get("tool_calls")

            # Track files touched from tool calls
            if tool_calls and isinstance(tool_calls, list):
                for tc in tool_calls:
                    args = tc.get("arguments", {})
                    if isinstance(args, dict):
                        for k in ("Path", "path", "file_path", "target_file"):
                            if k in args and isinstance(args[k], str):
                                files_touched.add(args[k])

            if rec_type == "USER_INPUT" or rec_source == "USER_EXPLICIT":
                if content and isinstance(content, str):
                    messages.append(
                        ImportedMessage(
                            role="user",
                            content=content.strip(),
                        )
                    )
            elif rec_type == "PLANNER_RESPONSE" or rec_source == "MODEL":
                if (content and isinstance(content, str)) or tool_calls:
                    messages.append(
                        ImportedMessage(
                            role="assistant",
                            content=content.strip() if isinstance(content, str) else "",
                            tool_calls=tool_calls,
                        )
                    )

    clean_id = sanitize_session_id(session_id or path.parent.name or path.stem, prefix="antigravity")
    title = messages[0].content[:80] if messages else path.stem

    return ImportedSession(
        session_id=clean_id,
        source="antigravity",
        title=title,
        messages=messages,
        workspace=workspace,
        files_touched=files_touched,
        reopen_command=None,
    )
