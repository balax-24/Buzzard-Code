"""
Tests for the Buzzard Code lean core split (roadmap H).

Verifies the pure coding package and registry isolation from pentest tools.
"""

from pathlib import Path
import pytest

from agent.loop import CODING_TOOL_NAMES
from coding import (
    CodingLoop,
    CodingOutcome,
    CodingVerifier,
    create_coding_registry,
)
from tools.registry import create_authoritative_registry


PENTEST_TOOL_SAMPLES = [
    "nmap_scan",
    "sqlmap_scan",
    "zap_spider",
    "nuclei_scan",
    "gobuster_dir",
    "hydra_ssh",
    "sslscan",
    "nikto_scan",
]


def test_coding_registry_contains_all_coding_tools():
    coding_reg = create_coding_registry()
    registered = {t.name for t in coding_reg.list_tools()}

    for tool in CODING_TOOL_NAMES:
        assert tool in registered, f"Coding tool '{tool}' missing from coding registry"


def test_coding_registry_excludes_pentest_tools():
    coding_reg = create_coding_registry()
    registered = {t.name for t in coding_reg.list_tools()}

    for tool in PENTEST_TOOL_SAMPLES:
        assert tool not in registered, f"Pentest tool '{tool}' should NOT be in coding registry"


def test_coding_registry_is_substantially_leaner():
    coding_reg = create_coding_registry()
    full_reg = create_authoritative_registry()

    coding_count = len(coding_reg.list_tools())
    full_count = len(full_reg.list_tools())

    # Full registry has ~255 tool definitions
    assert full_count >= 240
    # Coding registry has ~50-60 tool definitions (basic + filesystem + git + code + web + browser + lsp + subagents)
    assert coding_count < 100
    assert coding_count < (full_count / 2)


def test_coding_loop_defaults():
    class DummyProvider:
        model_name = "dummy"
        def is_available(self):
            return True
        def capabilities(self):
            return {"native_tools": True}
        def chat(self, messages, tools=None, options=None):
            return {"message": {"role": "assistant", "content": "Done."}, "done": True, "metrics": {}}

    loop = CodingLoop(provider=DummyProvider())
    registered = {t.name for t in loop.registry.list_tools()}

    assert "file_edit" in registered
    assert "code_symbols" in registered
    assert "page_open" in registered
    assert "nmap_scan" not in registered


def test_coding_outcome_dataclass():
    outcome = CodingOutcome(
        status="completed",
        final_answer="Code fixed.",
        changed_files=["calc.py"],
        tests_passed=True,
    )
    assert outcome.status == "completed"
    assert outcome.tests_passed is True
    assert outcome.changed_files == ["calc.py"]
