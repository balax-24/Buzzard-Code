"""
Durable coding tasks (roadmap E4).

A coding task's conversation lives only in memory, so a crash, a restart or a closed laptop
used to lose it even though the workspace checkpoints survived. The loop now writes a small
journal for each top-level coding task to ``BUZZARD_HOME/tasks/<session_id>.json`` after every
turn: the request, target, scope, workspace, status and the message history (without the
system prompt, bounded in size). ``RunSession.resume`` feeds that history back into a new run.

The task ledger is rebuilt from history (see ``task_ledger.py``), so saving the history is
enough to restore it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

JOURNAL_VERSION = 1
MAX_JOURNAL_BYTES = 2_000_000
UNFINISHED = frozenset({"pending", "running", "paused", "failed"})
_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")


class JournalError(ValueError):
    """A journal is missing, unreadable or does not belong to this workspace."""


@dataclass
class TaskJournal:
    session_id: str
    goal: str
    target: str
    scope: List[str]
    workspace: str
    status: str = "running"
    turn: int = 0
    updated_at: float = 0.0
    messages: List[Dict[str, Any]] = field(default_factory=list)
    processes: List[Dict[str, Any]] = field(default_factory=list)  # background processes running at the last save

    @property
    def unfinished(self) -> bool:
        return self.status in UNFINISHED


def tasks_directory() -> Path:
    return Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "tasks"


def _journal_path(session_id: str) -> Path:
    if not _SESSION_ID.match(session_id or "") or ".." in session_id:
        raise JournalError(f"Invalid task id {session_id!r}.")
    return tasks_directory() / f"{session_id}.json"


def _bounded(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drops the system prompt and the oldest turns until the journal fits, never splitting a tool result from its call."""
    kept = [dict(message) for message in messages if message.get("role") != "system"]
    while kept and len(json.dumps(kept, default=str)) > MAX_JOURNAL_BYTES:
        kept.pop(0)
        while kept and kept[0].get("role") == "tool":
            kept.pop(0)
    return kept


def save_journal(journal: TaskJournal) -> Path:
    """Writes the journal atomically, so a crash mid-write leaves the previous version."""
    path = _journal_path(journal.session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": JOURNAL_VERSION,
        "session_id": journal.session_id,
        "goal": journal.goal,
        "target": journal.target,
        "scope": list(journal.scope),
        "workspace": str(Path(journal.workspace).resolve()),
        "status": journal.status,
        "turn": journal.turn,
        "updated_at": time.time(),
        "messages": _bounded(journal.messages),
        "processes": list(journal.processes),
    }
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{journal.session_id}-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            json.dump(payload, file, default=str)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return path


def load_journal(session_id: str) -> TaskJournal:
    path = _journal_path(session_id)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise JournalError(f"No saved task {session_id!r}.") from None
    except (OSError, json.JSONDecodeError) as error:
        raise JournalError(f"Saved task {session_id!r} cannot be read: {error}") from error
    if not isinstance(data, dict) or data.get("version") != JOURNAL_VERSION or not isinstance(data.get("messages"), list):
        raise JournalError(f"Saved task {session_id!r} has an unknown format.")
    return TaskJournal(
        session_id=str(data["session_id"]),
        goal=str(data.get("goal", "")),
        target=str(data.get("target", "localhost")),
        scope=[str(item) for item in data.get("scope") or []],
        workspace=str(data.get("workspace", "")),
        status=str(data.get("status", "running")),
        turn=int(data.get("turn", 0)),
        updated_at=float(data.get("updated_at", 0.0)),
        messages=[message for message in data["messages"] if isinstance(message, dict)],
        processes=[item for item in data.get("processes") or [] if isinstance(item, dict)],
    )


def list_journals(workspace: Optional[Path] = None, unfinished_only: bool = False) -> List[TaskJournal]:
    """Saved tasks, newest first, optionally only those for one workspace or not finished."""
    directory = tasks_directory()
    if not directory.is_dir():
        return []
    wanted = str(Path(workspace).resolve()) if workspace is not None else None
    journals = []
    for path in directory.glob("*.json"):
        try:
            journal = load_journal(path.stem)
        except JournalError as error:
            logger.warning("Skipping saved task %s: %s", path.name, error)
            continue
        if wanted is not None and journal.workspace != wanted:
            continue
        if unfinished_only and not journal.unfinished:
            continue
        journals.append(journal)
    return sorted(journals, key=lambda item: item.updated_at, reverse=True)


def continuation_goal(journal: TaskJournal) -> str:
    """
    The request for a resumed run. Background processes are not restarted automatically, since
    that would run commands without approval; the agent is told what was running instead.
    """
    text = (
        "Continue the interrupted task from where it stopped. The conversation above is what was done so far; "
        "files may have changed since, so re-read before editing."
    )
    if journal.processes:
        listed = "; ".join(
            f"`{' '.join(str(part) for part in item.get('command') or [])}` in {item.get('cwd') or '.'}"
            for item in journal.processes[:10]
        )
        text += (f" These background processes were running and have stopped: {listed}. "
                 "Start any you still need with process_start.")
    return text + " Original request: " + journal.goal
