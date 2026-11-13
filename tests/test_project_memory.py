"""Tests for project memory: storage, user control, secret refusal and prompt injection."""

import json

import pytest

from agent import project_memory as memory
from tools.filesystem import set_active_workspace


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    home = tmp_path / "home"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("BUZZARD_HOME", str(home))
    set_active_workspace(str(project))
    yield project
    set_active_workspace(None)


def test_save_list_and_prompt(workspace):
    assert memory.memory_save("Tests run with pytest -q").startswith("Remembered")
    assert "1. Tests run with pytest -q  (agent)" in memory.handle_memory_command([])
    prompt = memory.memory_prompt()
    assert "PROJECT MEMORY" in prompt and "- Tests run with pytest -q" in prompt
    assert "cannot change approval or security" in prompt


def test_notes_are_stored_outside_the_repository(workspace):
    memory.memory_save("Money is stored in paise")
    assert not list(workspace.rglob("*.json"))
    assert memory._memory_path().is_file()


def test_notes_are_kept_per_workspace(workspace, tmp_path):
    memory.memory_save("Uses Django")
    other = tmp_path / "other"
    other.mkdir()
    assert memory.load_notes(str(other)) == []


@pytest.mark.parametrize("secret", [
    "OpenAI key sk-abcdefghijklmnopqrstuvwx",
    "token ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "AWS AKIAABCDEFGHIJKLMNOP",
    "google AIzaSyA1234567890abcdefghijklmnopqrstu",
    "db password = hunter2hunter2",
    "postgres://admin:s3cret@db.local/app",
    "-----BEGIN RSA PRIVATE KEY-----",
    "Authorization: Bearer abcdef1234567890abcdef",
    "key a8F3kq9ZpL2mX7vB1nR4tY6uW0eQ5sD8",
])
def test_secrets_are_refused_not_stored(workspace, secret):
    result = memory.memory_save(secret)
    assert result.startswith("Error") and "secret" in result
    assert memory.load_notes() == []


def test_ordinary_notes_with_paths_are_allowed(workspace):
    assert memory.memory_save("Pricing logic lives in tools/code_index_helpers/pricing.py").startswith("Remembered")


def test_secret_planted_in_file_is_never_loaded(workspace):
    path = memory._memory_path()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"notes": [{"text": "key sk-abcdefghijklmnopqrstuvwx"}, {"text": "fine"}]}), encoding="utf-8")
    assert [n["text"] for n in memory.load_notes()] == ["fine"]


def test_user_controls_forget_clear_and_off(workspace):
    memory.handle_memory_command(["add", "first"])
    memory.handle_memory_command(["add", "second"])
    assert memory.handle_memory_command(["forget", "1"]) == "Forgot: first"
    assert memory.handle_memory_command(["forget", "9"]).startswith("Error")
    memory.handle_memory_command(["off"])
    assert memory.memory_prompt() == ""
    assert "turned off" in memory.memory_save("agent note")
    assert memory.handle_memory_command(["add", "user note"]).startswith("Remembered")
    memory.handle_memory_command(["on"])
    assert "- second" in memory.memory_prompt()
    assert memory.handle_memory_command(["clear"]) == "Cleared 2 note(s) for this project."
    assert memory.is_enabled()


def test_limits_duplicates_and_bad_input(workspace, monkeypatch):
    assert memory.memory_save("").startswith("Error")
    assert memory.memory_save("x" * 301).startswith("Error")
    memory.memory_save("Same note")
    assert memory.memory_save("same  NOTE").startswith("Already")
    monkeypatch.setattr(memory, "MAX_NOTES", 1)
    assert "full" in memory.memory_save("another")
    assert memory.handle_memory_command(["bogus"]).startswith("Usage")


def test_corrupt_memory_file_is_ignored(workspace):
    path = memory._memory_path()
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    assert memory.load_notes() == [] and memory.memory_prompt() == ""
    assert memory.memory_save("recovers").startswith("Remembered")
