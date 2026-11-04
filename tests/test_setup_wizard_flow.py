"""Walks the first-run wizard as a new user, with answers fed to its real prompts."""

from unittest.mock import patch

import httpx
import pytest

from cli import setup_wizard
from model.openai_compatible import OpenAICompatibleProvider


@pytest.fixture
def wizard(monkeypatch):
    saved = {}
    credentials = {}
    monkeypatch.setattr(setup_wizard, "is_docker_active", lambda: True)
    monkeypatch.setattr(setup_wizard, "save_global_config", lambda config: saved.update(config))
    monkeypatch.setattr(setup_wizard, "get_setup_state", dict)
    monkeypatch.setattr(setup_wizard, "save_setup_state", lambda state: saved.update(state=state))
    monkeypatch.setattr(setup_wizard, "get_credential", credentials.get)
    monkeypatch.setattr(setup_wizard, "set_credential", credentials.__setitem__)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.delenv("BUZZARD_FALLBACK_MODELS", raising=False)

    def run(*answers, confirm=False):
        with patch.object(setup_wizard.Prompt, "ask", side_effect=list(answers)), \
                patch.object(setup_wizard.Confirm, "ask", return_value=confirm):
            assert setup_wizard.run_first_run_wizard(force=True) is True
        return saved, credentials

    return run


def test_openrouter_path_configures_muse_and_saves_key_separately(wizard):
    saved, credentials = wizard("1", "new-key", "meta/muse-glimmer-30b", "")
    assert saved["model"]["provider"] == "openai-compatible"
    assert saved["model"]["endpoint"] == "https://openrouter.ai/api/v1"
    assert saved["model"]["name"] == "meta/muse-glimmer-30b"
    assert credentials["openai-compatible"] == "new-key"
    assert "new-key" not in str(saved)


def test_meta_path(wizard):
    saved, credentials = wizard("2", "meta-key", "muse-spark-1.1", "")
    assert saved["model"]["provider"] == "meta"
    assert credentials["meta"] == "meta-key"


def test_backup_models_are_saved_when_chosen(wizard):
    saved, _ = wizard("2", "k", "muse-spark-1.1", "gemini/backup, ollama/local")
    assert saved["model"]["fallbacks"] == ["gemini/backup", "ollama/local"]


def test_no_backup_by_default_so_code_never_goes_elsewhere_unasked(wizard):
    saved, _ = wizard("2", "k", "muse-spark-1.1", "")
    assert "fallbacks" not in saved["model"]


def test_configure_later_defaults_to_local(wizard):
    saved, _ = wizard("8")
    assert saved["model"]["provider"] == "ollama"


def test_failed_connection_test_is_reported_and_setup_still_finishes(wizard, capsys):
    failure = httpx.Response(401, text="bad key", request=httpx.Request("POST", "https://openrouter.ai"))
    with patch.object(OpenAICompatibleProvider, "chat", side_effect=RuntimeError("API error (401)")):
        saved, _ = wizard("1", "bad-key", "meta/muse-glimmer-30b", "", confirm=True)
    assert saved["state"]["setup_completed"] is True
    assert failure.status_code == 401


def test_rerunning_setup_does_not_change_shared_defaults(wizard):
    wizard("2", "k", "muse-spark-1.1", "gemini/backup")
    assert setup_wizard.DEFAULT_CONFIG["model"].get("provider") != "meta"
    assert "fallbacks" not in setup_wizard.DEFAULT_CONFIG["model"]
