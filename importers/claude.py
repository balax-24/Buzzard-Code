"""
Importer for Claude Code CLI sessions (from ~/.claude/projects/<project>/<session>.jsonl).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from importers.base import ImportedMessage, ImportedSession, sanitize_session_id


def import_claude_session(file_path: Path | str) -> ImportedSession:
    """Parses a Claude Code session .jsonl file into an ImportedSession."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Claude Code session file not found: {path}")

    session_id: Optional[str] = None
    title: Optional[str] = None
    workspace: Optional[str] = None
    messages: List[ImportedMessage] = []
    files_touched: Set[str] = set()

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except Exception:
                continue

            rec_type = record.get("type")
            if not session_id and record.get("sessionId"):
                session_id = record["sessionId"]

            if rec_type == "custom-title" and record.get("customTitle"):
                title = record["customTitle"]

            if not workspace and record.get("cwd"):
                workspace = record["cwd"]

            if rec_type == "user":
                msg = record.get("message", {})
                content_raw = msg.get("content", "")
                text_content = ""
                if isinstance(content_raw, str):
                    text_content = content_raw
                elif isinstance(content_raw, list):
                    texts = []
                    for block in content_raw:
                        if isinstance(block, dict) and block.get("type") == "text":
                            texts.append(block.get("text", ""))
                    text_content = "\n".join(texts)

                if text_content.strip():
                    messages.append(
                        ImportedMessage(
                            role="user",
                            content=text_content.strip(),
                        )
                    )

            elif rec_type == "assistant":
                msg = record.get("message", {})
                content_raw = msg.get("content", "")
                texts = []
                tool_calls = []

                if isinstance(content_raw, str):
                    texts.append(content_raw)
                elif isinstance(content_raw, list):
                    for block in content_raw:
                        if not isinstance(block, dict):
                            continue
                        b_type = block.get("type")
                        if b_type == "text":
                            texts.append(block.get("text", ""))
                        elif b_type == "tool_use":
                            tool_name = block.get("name", "unknown")
                            tool_input = block.get("input", {})
                            tool_calls.append({
                                "id": block.get("id"),
                                "name": tool_name,
                                "arguments": tool_input,
                            })
                            # Track files touched
                            for key in ("file_path", "path", "target_file", "filename"):
                                if key in tool_input and isinstance(tool_input[key], str):
                                    files_touched.add(tool_input[key])

                full_text = "\n".join(texts).strip()
                if full_text or tool_calls:
                    messages.append(
                        ImportedMessage(
                            role="assistant",
                            content=full_text,
                            tool_calls=tool_calls if tool_calls else None,
                        )
                    )

    clean_id = sanitize_session_id(session_id or path.stem, prefix="claude")
    session_title = title or (messages[0].content[:80] if messages else path.stem)
    reopen_cmd = f"claude --resume {session_id}" if session_id else None

    return ImportedSession(
        session_id=clean_id,
        source="claude_code",
        title=session_title,
        messages=messages,
        workspace=workspace,
        files_touched=files_touched,
        reopen_command=reopen_cmd,
    )
