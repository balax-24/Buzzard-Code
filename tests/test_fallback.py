"""Unit tests for the FallbackRunner engine and the arsenal capability chains."""
from __future__ import annotations

import pytest

from security_agent.tools.fallback import FallbackRunner, is_failed_result, strategy_from_cmd
from security_agent.tools import arsenal
from security_agent.tools.registry import ToolRegistry


class FakeSandbox:
    """Sandbox stub that fails on demand and records executed commands."""

    def __init__(self, exit_code=0, stdout="ok", stderr=""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.commands = []

    def execute(self, command, timeout=10):
        self.commands.append(command)
        return {"exit_code": self.exit_code, "stdout": self.stdout,
                "stderr": self.stderr, "sandboxed": True}


def test_chain_tries_next_strategy_on_failure():
    calls = []

    def strat_a(runner, kw):
        calls.append("a")
        return False, "a failed", "a detail"

    def strat_b(runner, kw):
        calls.append("b")
        return True, "b won", "b detail"

    result = FallbackRunner().run("test_cap", [("a", strat_a), ("b", strat_b)], {})
    assert result["ok"] is True
    assert result["winner"] == "b"
    assert calls == ["a", "b"]
    assert [e["status"] for e in result["chain"]] == ["FAIL", "OK"]


def test_chain_stops_at_first_winner():
    calls = []

    def strat_a(runner, kw):
        calls.append("a")
        return True, "a won", "a detail"

    def strat_b(runner, kw):
        calls.append("b")
        return True, "b won", "b detail"

    result = FallbackRunner().run("test_cap", [("a", strat_a), ("b", strat_b)], {})
    assert result["winner"] == "a"
    assert calls == ["a"]


def test_chain_reports_all_failed():
    def strat_a(runner, kw):
        return False, "a failed", ""

    def strat_b(runner, kw):
        raise RuntimeError("b exploded")

    result = FallbackRunner().run("test_cap", [("a", strat_a), ("b", strat_b)], {})
    assert result["ok"] is False
    assert result["winner"] is None
    assert "b exploded" in result["advice"]
    assert result["chain"][1]["status"] == "FAIL"


def test_exception_in_strategy_is_failure():
    def bad(runner, kw):
        raise ValueError("boom")

    result = FallbackRunner().run("x", [("bad", bad)], {})
    assert result["ok"] is False
    assert "boom" in result["output"] or "boom" in result["advice"]


def test_is_failed_result_heuristics():
    assert is_failed_result({"exit_code": 1, "stdout": "", "stderr": ""})
    assert is_failed_result({"exit_code": 0, "stdout": "", "stderr": "command not found"})
    assert not is_failed_result({"exit_code": 0, "stdout": "data", "stderr": ""})


def test_strategy_from_cmd_uses_sandbox():
    sb = FakeSandbox(stdout="nmap scan report")
    strat = strategy_from_cmd("nmap", lambda kw: f"nmap {kw.get('host')}")
    ok, summary, detail = strat(FallbackRunner(sandbox=sb), {"host": "127.0.0.1"})
    assert ok is True
    assert sb.commands == ["nmap 127.0.0.1"]
    assert "nmap scan report" in detail


def test_strategy_from_cmd_fails_when_binary_missing(monkeypatch):
    monkeypatch.setattr("security_agent.tools.fallback.shutil.which", lambda name: None)
    strat = strategy_from_cmd("nmap", lambda kw: "nmap x")
    ok, summary, detail = strat(FallbackRunner(), {})
    assert ok is False
    assert "not installed" in summary


def test_strategy_from_cmd_fails_on_error_exit():
    sb = FakeSandbox(exit_code=127, stderr="connection refused")
    strat = strategy_from_cmd("nmap", lambda kw: "nmap x")
    ok, summary, detail = strat(FallbackRunner(sandbox=sb), {})
    assert ok is False


def test_arsenal_registers_all_capabilities():
    reg = ToolRegistry()
    arsenal.register_arsenal_tools(reg)
    expected = {
        "port_scan", "service_fingerprint", "dir_bruteforce", "api_discovery",
        "ssh_brute", "ftp_brute", "http_login_brute", "crack_hash", "crack_zip",
        "http_stress", "tcp_stress", "udp_stress", "slowloris", "syn_flood",
        "xss_scan", "sqli_scan", "lfi_scan", "ssrf_scan", "cmd_injection_scan",
        "cve_scan", "wifi_scan", "wifi_deauth", "wifi_crack_handshake",
        "payload_generate", "reverse_shell_payload", "exploit_search",
    }
    caps = set(arsenal.list_capabilities())
    assert expected <= caps


def test_arsenal_tool_runs_through_registry():
    reg = ToolRegistry()
    arsenal.register_arsenal_tools(reg)
    out = reg.execute("port_scan", {"host": "127.0.0.1", "ports": "8080"})
    assert "[CAPABILITY: port_scan]" in out
    assert "8080" in out


def test_router_routing():
    from security_agent.model.router import ModelRouter
    r = ModelRouter(available=["k3-sec:latest", "qwen-cyber:latest", "deephat:latest", "qwythos:latest"])
    assert r.route("scan the host for open ports") == "k3-sec:latest"
    assert r.route("exploit the rce on the target") == "qwen-cyber:latest"
    assert r.route("write a python script for the payload") in ("deephat:latest", "qwen-cyber:latest")
    assert r.route("summarize findings into a report") == "qwythos:latest"
    assert r.route("anything", phase="exploitation") == "qwen-cyber:latest"
