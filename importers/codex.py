"""
Importer for Codex CLI sessions (from ~/.codex/sessions/YYYY/MM/DD/*.jsonl).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from importers.base import ImportedMessage, ImportedSession, sanitize_session_id


def import_codex_session(file_path: Path | str) -> ImportedSession:
    """Parses a Codex CLI session .jsonl file into an ImportedSession."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Codex session file not found: {path}")

    session_id: Optional[str] = None
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

            if not session_id:
                session_id = record.get("session_id") or record.get("id")

            if not workspace:
                workspace = record.get("workspace") or record.get("cwd")

            role = record.get("role")
            content = record.get("content")

            # Also handle OpenAI messages shape if nested
            if "message" in record and isinstance(record["message"], dict):
                role = record["message"].get("role", role)
                content = record["message"].get("content", content)

            if role in ("user", "assistant", "tool") and content is not None:
                text_content = ""
                if isinstance(content, str):
                    text_content = content
                elif isinstance(content, list):
                    texts = []
                    for item in content:
                        if isinstance(item, str):
                            texts.append(item)
                        elif isinstance(item, dict) and "text" in item:
                            texts.append(item["text"])
                    text_content = "\n".join(texts)

                tool_calls = record.get("tool_calls") or (record.get("message", {}).get("tool_calls") if isinstance(record.get("message"), dict) else None)
                if tool_calls:
                    for tc in tool_calls:
                        fn = tc.get("function", {})
                        args = fn.get("arguments", {})
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                pass
                        if isinstance(args, dict):
                            for key in ("path", "file_path", "filename"):
                                if key in args and isinstance(args[key], str):
                                    files_touched.add(args[key])

                if text_content.strip() or tool_calls:
                    messages.append(
                        ImportedMessage(
                            role=role,
                            content=text_content.strip(),
                            tool_calls=tool_calls,
                        )
                    )

    clean_id = sanitize_session_id(session_id or path.stem, prefix="codex")
    title = messages[0].content[:80] if messages else path.stem
    reopen_cmd = f"codex resume {session_id}" if session_id else None

    return ImportedSession(
        session_id=clean_id,
        source="codex",
        title=title,
        messages=messages,
        workspace=workspace,
        files_touched=files_touched,
        reopen_command=reopen_cmd,
    )
