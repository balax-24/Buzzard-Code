"""
Unit tests for ContextManager.

Verifies:
1. Bounded context enforcement (no runaway token/character accumulation)
2. Retaining system prompt and initial objective
3. Injecting canonical state snapshot
4. Rolling window compaction of recent turns
5. Tool output compression (e.g. nmap, ffuf, generic) while raw is kept on disk
"""

import pytest
from security_agent.agent.context_manager import ContextManager
from security_agent.agent.assessment_state import AssessmentState, ServiceRecord, ServiceState, VerificationStatus


def test_compress_tool_output_nmap():
    mgr = ContextManager(max_tool_output_chars=300)
    
    # 50 lines of nmap output
    lines = ["Starting Nmap 7.98 at 2026-08-23", "Nmap scan report for 127.0.0.1", "Host is up (0.00002s latency)."]
    for p in range(1, 40):
        lines.append(f"{p}/tcp open service_{p}")
    lines.append("Nmap done: 1 IP address scanned in 2.0 seconds")
    raw = "\n".join(lines)

    compressed = mgr.compress_tool_output("nmap_scan", raw, max_chars=300)
    assert len(compressed) <= len(raw)
    assert "truncated" in compressed or len(compressed) <= 300
    assert "1/tcp open service_1" in compressed


def test_compress_tool_output_generic():
    mgr = ContextManager(max_tool_output_chars=200)
    raw = "A" * 1000
    compressed = mgr.compress_tool_output("generic_tool", raw, max_chars=200)
    assert len(compressed) < len(raw)
    assert "characters truncated" in compressed


def test_compact_messages_bounds():
    mgr = ContextManager(max_recent_turns=4, max_total_history_chars=10000)
    state = AssessmentState()
    state.record_service(host="127.0.0.1", port=80, protocol="tcp", service="http", version="Apache 2.4", state=ServiceState.OPEN)

    raw_messages = [
        {"role": "system", "content": "You are a security auditor."},
        {"role": "user", "content": "Audit 127.0.0.1"}
    ]
    # Add 20 back-and-forth turns
    for i in range(20):
        raw_messages.append({"role": "assistant", "content": f"Running tool {i}", "thinking": "Lengthy reasoning trace " * 20})
        raw_messages.append({"role": "tool", "content": f"Tool {i} output " * 30})

    compact = mgr.compact_messages(raw_messages, state=state)

    # 1. System prompt preserved
    assert compact[0]["role"] == "system"
    assert compact[0]["content"] == "You are a security auditor."

    # 2. Initial user goal preserved
    assert compact[1]["role"] == "user"
    assert compact[1]["content"] == "Audit 127.0.0.1"

    # 3. Canonical state summary injected
    assert any("CANONICAL" in str(m.get("content", "")) or "80/tcp" in str(m.get("content", "")) for m in compact)

    # 4. Rolling window is compact
    assert len(compact) <= 8
    # 5. Thinking stripped from older assistant messages
    for m in compact:
        if m.get("role") == "assistant":
            assert m.get("thinking", "") == ""
