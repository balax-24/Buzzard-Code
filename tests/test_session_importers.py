"""
Tests for cross-agent session importers (roadmap Buzzard Go).

Uses synthetic transcripts only (never real user files).
"""

import json
from pathlib import Path
import pytest

from importers import (
    ImportedSession,
    import_antigravity_session,
    import_chatgpt_conversations,
    import_claude_session,
    import_codex_session,
    sanitize_session_id,
)
from agent.durable_tasks import load_journal


def test_sanitize_session_id():
    assert sanitize_session_id("normal_id-123") == "normal_id-123"
    assert sanitize_session_id("hello world / bad : chars") == "hello_world___bad___chars"
    assert sanitize_session_id("___").startswith("imported_")
    assert sanitize_session_id("", prefix="custom").startswith("custom_")


def test_import_claude_session(tmp_path):
    claude_log = tmp_path / "claude_test.jsonl"
    lines = [
        {"type": "queue-operation", "operation": "start", "sessionId": "c1234-abcd"},
        {"type": "custom-title", "customTitle": "Refactor authentication flow"},
        {"type": "user", "cwd": "/repo/auth", "message": {"role": "user", "content": "Please inspect auth.py"}},
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "I will inspect auth.py now."},
                    {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"file_path": "src/auth.py"}},
                ],
            },
        },
    ]
    with claude_log.open("w", encoding="utf-8") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")

    session = import_claude_session(claude_log)
    assert session.session_id == "c1234-abcd"
    assert session.title == "Refactor authentication flow"
    assert session.workspace == "/repo/auth"
    assert session.source == "claude_code"
    assert len(session.messages) == 2
    assert session.messages[0].role == "user"
    assert session.messages[0].content == "Please inspect auth.py"
    assert session.messages[1].role == "assistant"
    assert "I will inspect auth.py now." in session.messages[1].content
    assert "src/auth.py" in session.files_touched
    assert session.reopen_command == "claude --resume c1234-abcd"


def test_import_codex_session(tmp_path):
    codex_log = tmp_path / "codex_test.jsonl"
    lines = [
        {"session_id": "codex-9876", "workspace": "/workspace/go", "role": "user", "content": "Fix the null check in main.go"},
        {
            "role": "assistant",
            "content": "Fixed.",
            "tool_calls": [{"function": {"name": "edit", "arguments": json.dumps({"path": "cmd/main.go"})}}],
        },
    ]
    with codex_log.open("w", encoding="utf-8") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")

    session = import_codex_session(codex_log)
    assert session.session_id == "codex-9876"
    assert session.source == "codex"
    assert len(session.messages) == 2
    assert "cmd/main.go" in session.files_touched
    assert session.reopen_command == "codex resume codex-9876"


def test_import_antigravity_session(tmp_path):
    brain_dir = tmp_path / "brain" / "4a52ecec-a38e-4125-b1fd-cc659ac92791" / ".system_generated" / "logs"
    brain_dir.mkdir(parents=True)
    antigravity_log = brain_dir / "transcript.jsonl"

    lines = [
        {"step_index": 1, "source": "USER_EXPLICIT", "type": "USER_INPUT", "content": "Explain architecture"},
        {
            "step_index": 2,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "content": "The architecture is structured as follows.",
            "tool_calls": [{"name": "read_file", "arguments": {"Path": "/repo/README.md"}}],
        },
    ]
    with antigravity_log.open("w", encoding="utf-8") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")

    session = import_antigravity_session(antigravity_log)
    assert session.source == "antigravity"
    assert session.session_id == "4a52ecec-a38e-4125-b1fd-cc659ac92791"
    assert len(session.messages) == 2
    assert "/repo/README.md" in session.files_touched


def test_import_chatgpt_conversations(tmp_path):
    chatgpt_file = tmp_path / "conversations.json"
    data = [
        {
            "id": "conv-111",
            "title": "Design Discussion",
            "create_time": 1700000000.0,
            "mapping": {
                "node_1": {
                    "id": "node_1",
                    "message": {
                        "id": "msg_1",
                        "author": {"role": "user"},
                        "content": {"parts": ["What is CQRS?"]},
                        "create_time": 1700000001.0,
                    },
                },
                "node_2": {
                    "id": "node_2",
                    "message": {
                        "id": "msg_2",
                        "author": {"role": "assistant"},
                        "content": {"parts": ["Command Query Responsibility Segregation."]},
                        "create_time": 1700000002.0,
                    },
                },
            },
        }
    ]
    with chatgpt_file.open("w", encoding="utf-8") as f:
        json.dump(data, f)

    sessions = import_chatgpt_conversations(chatgpt_file)
    assert len(sessions) == 1
    session = sessions[0]
    assert session.session_id == "conv-111"
    assert session.source == "chatgpt"
    assert session.title == "Design Discussion"
    assert len(session.messages) == 2
    assert session.messages[0].content == "What is CQRS?"
    assert session.messages[1].content == "Command Query Responsibility Segregation."


def test_session_to_buzzard_task_journal(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "buzzard"))
    session = ImportedSession(
        session_id="test_import_session",
        source="claude_code",
        title="Fix database migrations",
        workspace=str(tmp_path / "app"),
    )
    from importers.base import ImportedMessage
    session.messages.append(ImportedMessage(role="user", content="Add migration file"))
    session.messages.append(ImportedMessage(role="assistant", content="Migration file added."))

    path = session.save_as_buzzard_task(target_workspace=str(tmp_path / "app"))
    assert path.exists()

    loaded = load_journal("test_import_session")
    assert loaded.session_id == "test_import_session"
    assert loaded.status == "paused"
    assert loaded.goal == "[CLAUDE_CODE] Fix database migrations"
    assert len(loaded.messages) == 2
