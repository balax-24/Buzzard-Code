"""
Tests for unified configuration precedence, validation, and secure credential handling.
"""

import os
import json
import tempfile
import pytest
from pathlib import Path
from core.config import (
    load_merged_config,
    save_global_config,
    save_project_config,
    validate_config,
    redact_secrets,
    DEFAULT_CONFIG,
)
from core.credentials import (
    get_credential,
    set_credential,
    delete_credential,
    mask_secret,
    list_configured_credentials,
)

def test_default_config_structure():
    cfg = load_merged_config()
    assert cfg["version"] == "1.0.0"
    assert "model" in cfg
    assert cfg["model"]["provider"] == "ollama"
    assert "runtime" in cfg
    assert "security" in cfg
    assert "localhost" in cfg["security"]["scope"]

def test_config_precedence(tmp_path, monkeypatch):
    # Set fake global config dir
    fake_global_dir = tmp_path / "global"
    fake_global_dir.mkdir()
    monkeypatch.setattr("core.config.get_global_config_dir", lambda: fake_global_dir)
    
    global_cfg = {
        "model": {"provider": "openai", "name": "gpt-4o"},
        "security": {"autonomy_level": 3}
    }
    (fake_global_dir / "config.json").write_text(json.dumps(global_cfg), encoding="utf-8")
    
    # Check global override over default
    cfg = load_merged_config(project_dir=tmp_path / "nonexistent")
    assert cfg["model"]["provider"] == "openai"
    assert cfg["model"]["name"] == "gpt-4o"
    assert cfg["security"]["autonomy_level"] == 3
    # Preserves default non-overridden keys
    assert cfg["runtime"]["sandbox"] == "docker"
    
    # Project config override
    proj_dir = tmp_path / "project"
    proj_dir.mkdir()
    proj_cfg = {
        "model": {"name": "claude-3-5-sonnet"},
        "security": {"allow_network": False}
    }
    (proj_dir / "buzzard.json").write_text(json.dumps(proj_cfg), encoding="utf-8")
    
    cfg2 = load_merged_config(project_dir=proj_dir)
    assert cfg2["model"]["provider"] == "openai" # from global
    assert cfg2["model"]["name"] == "claude-3-5-sonnet" # from project
    assert cfg2["security"]["allow_network"] is False # from project
    
    # CLI override over project and global
    cli_overrides = {
        "model": {"name": "qwen3:8b", "provider": "ollama"}
    }
    cfg3 = load_merged_config(cli_overrides=cli_overrides, project_dir=proj_dir)
    assert cfg3["model"]["provider"] == "ollama"
    assert cfg3["model"]["name"] == "qwen3:8b"

def test_secret_redaction():
    payload = {
        "api_key": "sk-proj-1234567890abcdef1234567890",
        "nested": {
            "token": "secret_token_value",
            "normal": "hello_world",
            "url": "https://api.openai.com/v1?key=sk-12345678901234567890"
        },
        "list": [
            {"password": "mypassword123"},
            "regular item"
        ]
    }
    redacted = redact_secrets(payload)
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["nested"]["normal"] == "hello_world"
    assert "[REDACTED]" in redacted["nested"]["url"]
    assert redacted["list"][0]["password"] == "[REDACTED]"
    assert redacted["list"][1] == "regular item"

def test_config_validation():
    valid, errors = validate_config(DEFAULT_CONFIG)
    assert valid is True
    assert len(errors) == 0
    
    invalid_cfg = {"model": {"provider": 123}}
    valid2, errors2 = validate_config(invalid_cfg)
    assert valid2 is False
    assert len(errors2) > 0

def test_credentials_management(tmp_path, monkeypatch):
    fake_creds_dir = tmp_path / "creds"
    fake_creds_dir.mkdir()
    monkeypatch.setattr("core.credentials.get_credentials_dir", lambda: fake_creds_dir)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    
    # Test setting credential
    set_credential("openai", "sk-proj-abcdef1234567890")
    retrieved = get_credential("openai")
    assert retrieved == "sk-proj-abcdef1234567890"
    
    # Test masking
    masked = mask_secret(retrieved)
    assert "..." in masked
    assert "sk-p" in masked
    assert "7890" in masked
    assert "abcdef" not in masked
    
    # Test delete
    assert delete_credential("openai") is True
    assert get_credential("openai") is None
