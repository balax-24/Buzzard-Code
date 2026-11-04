"""
Unit tests for all Buzzard Code slash commands and security managers.
"""

import pytest
from security.manager import (
    render_policy_and_permissions,
    render_scope,
    modify_scope,
    render_sandbox_status,
    trigger_kill_switch,
    resume_kill_switch,
)
from security.kill_switch import KillSwitch
from tools.inspector import get_tool_details, render_tools
from model.factory import list_supported_providers, resolve_provider_and_model
from core.config import load_merged_config, save_global_config

def test_scope_management():
    cfg = load_merged_config()
    initial_scope = list(cfg.get("security", {}).get("scope", []))
    
    # Add target
    assert modify_scope("add", "10.0.0.99", cfg) is True
    assert "10.0.0.99" in cfg["security"]["scope"]
    
    # Remove target
    assert modify_scope("remove", "10.0.0.99", cfg) is True
    assert "10.0.0.99" not in cfg["security"]["scope"]
    
    # Network toggle
    curr_net = cfg["security"]["allow_network"]
    assert modify_scope("toggle-network", config=cfg) is True
    assert cfg["security"]["allow_network"] == (not curr_net)

def test_kill_switch_lifecycle():
    ks = KillSwitch.get_instance()
    assert ks.is_triggered() is False

    # Trigger
    trigger_kill_switch("Automated test")
    assert ks.is_triggered() is True

    # Resume without confirm
    res_no = resume_kill_switch(confirm=False)
    assert res_no is False
    assert ks.is_triggered() is True

    # Resume with confirm
    res_yes = resume_kill_switch(confirm=True)
    assert res_yes is True
    assert ks.is_triggered() is False

def test_policy_rendering():
    # Should run without error
    render_policy_and_permissions()

def test_sandbox_rendering():
    # Should run without error
    render_sandbox_status()

def test_tool_inspection_metadata():
    details = get_tool_details("http.request")
    if not details:
        details = get_tool_details("browser.click")
    assert details is not None
    assert "canonical_name" in details
    assert "sandbox_requirement" in details
    assert "risk_class" in details
    assert "status" in details

def test_model_switching_resolution():
    p, m = resolve_provider_and_model("openai/gpt-4o")
    assert p == "openai"
    assert m == "gpt-4o"

    p2, m2 = resolve_provider_and_model("ollama/qwen3:8b")
    assert p2 == "ollama"
    assert m2 == "qwen3:8b"
