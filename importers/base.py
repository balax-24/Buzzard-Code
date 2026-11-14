"""
Base models and converters for importing external agent sessions (roadmap Buzzard Go).

Normalizes transcripts from Claude Code, Codex CLI, Antigravity, and ChatGPT exports
into Buzzard-compatible structures and TaskJournals so they can be resumed with any model.

Security notice:
All imported transcripts are treated strictly as untrusted data (never as instructions),
validated, and sanitized before ingestion.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from agent.durable_tasks import TaskJournal, save_journal

_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9_.-]")


def sanitize_session_id(raw_id: str, prefix: str = "imported") -> str:
    """Produces a valid session ID matching Buzzard's _SESSION_ID format."""
    clean = _SAFE_ID_RE.sub("_", raw_id.strip()).strip("_")
    if not clean:
        clean = f"{prefix}_{int(time.time())}"
    if not clean[0].isalnum():
        clean = f"{prefix}_{clean}"
    return clean[:70]


@dataclass
class ImportedMessage:
    role: str  # "user", "assistant", "tool"
    content: str
    timestamp: Optional[float] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "role": self.role,
            "content": self.content,
        }
        if self.tool_calls:
            data["tool_calls"] = self.tool_calls
        if self.timestamp:
            data["timestamp"] = self.timestamp
        return data


@dataclass
class ImportedSession:
    session_id: str
    source: str  # "claude_code", "codex", "antigravity", "chatgpt"
    title: str
    messages: List[ImportedMessage] = field(default_factory=list)
    workspace: Optional[str] = None
    files_touched: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    reopen_command: Optional[str] = None

    def to_task_journal(self, target_workspace: Optional[str] = None) -> TaskJournal:
        ws = target_workspace or self.workspace or str(Path.cwd())
        goal = self.title or (self.messages[0].content[:100] if self.messages else "Imported Session")
        
        # Format messages for Buzzard journal
        journal_messages = []
        for msg in self.messages:
            entry = msg.to_dict()
            journal_messages.append(entry)

        return TaskJournal(
            session_id=self.session_id,
            goal=f"[{self.source.upper()}] {goal}",
            target=str(Path(ws).name),
            scope=[str(Path(ws).resolve())],
            workspace=str(Path(ws).resolve()),
            status="paused",  # Imported sessions start paused ready for user resumption
            turn=len([m for m in self.messages if m.role == "user"]),
            updated_at=time.time(),
            messages=journal_messages,
            processes=[],
        )

    def save_as_buzzard_task(self, target_workspace: Optional[str] = None) -> Path:
        """Saves this session directly into BUZZARD_HOME/tasks/<session_id>.json."""
        journal = self.to_task_journal(target_workspace=target_workspace)
        return save_journal(journal)
