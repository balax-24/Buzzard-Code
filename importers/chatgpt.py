"""
Importer for official ChatGPT data export (conversations.json).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from importers.base import ImportedMessage, ImportedSession, sanitize_session_id


def import_chatgpt_conversations(file_path: Path | str) -> List[ImportedSession]:
    """Parses a ChatGPT export conversations.json file into a list of ImportedSessions."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"ChatGPT export file not found: {path}")

    with path.open("r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, dict):
        conversations = [data]
    elif isinstance(data, list):
        conversations = data
    else:
        raise ValueError("Invalid ChatGPT export format; expected a JSON array or object.")

    sessions: List[ImportedSession] = []

    for conv in conversations:
        conv_id = conv.get("id") or conv.get("conversation_id")
        title = conv.get("title") or "ChatGPT Conversation"
        create_time = conv.get("create_time") or 0.0
        mapping = conv.get("mapping", {})

        # Extract message nodes
        node_list: List[Dict[str, Any]] = []
        for node in mapping.values():
            if not isinstance(node, dict):
                continue
            msg = node.get("message")
            if not msg or not isinstance(msg, dict):
                continue
            author = msg.get("author", {})
            role = author.get("role")
            if role not in ("user", "assistant"):
                continue

            content_obj = msg.get("content", {})
            parts = content_obj.get("parts", [])
            text_parts = []
            for p in parts:
                if isinstance(p, str):
                    text_parts.append(p)
                elif isinstance(p, dict) and "text" in p:
                    text_parts.append(p["text"])

            full_text = "\n".join(text_parts).strip()
            if full_text:
                node_list.append({
                    "id": msg.get("id"),
                    "role": role,
                    "content": full_text,
                    "create_time": msg.get("create_time") or create_time,
                })

        # Sort messages by create_time
        node_list.sort(key=lambda x: x["create_time"])

        messages = [
            ImportedMessage(
                role=item["role"],
                content=item["content"],
                timestamp=item["create_time"],
            )
            for item in node_list
        ]

        if messages:
            clean_id = sanitize_session_id(conv_id or title, prefix="chatgpt")
            sessions.append(
                ImportedSession(
                    session_id=clean_id,
                    source="chatgpt",
                    title=title,
                    messages=messages,
                    created_at=create_time,
                )
            )

    return sessions
