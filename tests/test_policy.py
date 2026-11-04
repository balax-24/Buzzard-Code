import pytest
from security_agent.security.scope import is_in_scope, extract_host_and_port
from security_agent.security.policy import PolicyEngine
from security_agent.security.approvals import ApprovalGate
from security_agent.security.autonomy import EnvironmentProfile

def test_extract_host_and_port():
    assert extract_host_and_port("localhost:8080") == ("localhost", 8080)
    assert extract_host_and_port("http://127.0.0.1:3000/api") == ("127.0.0.1", 3000)
    assert extract_host_and_port("https://example.com") == ("example.com", None)
    assert extract_host_and_port("example.com") == ("example.com", None)

def test_is_in_scope():
    scope = ["localhost", "127.0.0.1", "example.com"]
    
    assert is_in_scope("localhost:8080", scope) is True
    assert is_in_scope("http://127.0.0.1:3000", scope) is True
    assert is_in_scope("https://example.com/test", scope) is True
    assert is_in_scope("http://google.com", scope) is False
    assert is_in_scope("10.0.0.1", scope) is False

def test_policy_engine_direct_arguments():
    policy = PolicyEngine(scope=["localhost", "127.0.0.1", "example.com"])
    
    # Allowed host
    permitted, reason = policy.evaluate_tool_call("scan_ports", {"host": "localhost", "ports": "80"})
    assert permitted is True
    
    # Disallowed host
    permitted, reason = policy.evaluate_tool_call("scan_ports", {"host": "google.com", "ports": "80"})
    assert permitted is False
    assert "outside the authorized testing scope" in reason

def test_policy_engine_terminal_command():
    # These positive-path assertions model an explicit operator approval.
    gate = ApprovalGate(
        environment=EnvironmentProfile.LAB,
        approval_callback=lambda tool, args, meta: True,
    )
    policy = PolicyEngine(scope=["localhost", "example.com"], approval_gate=gate)
    
    # Permitted local command
    permitted, reason = policy.evaluate_tool_call("terminal.execute", {"command": "ping -c 1 localhost"})
    assert permitted is True
    
    # Permitted allowed host
    permitted, reason = policy.evaluate_tool_call("terminal.execute", {"command": "curl http://example.com"})
    assert permitted is True
    
    # Disallowed out-of-scope host in command
    permitted, reason = policy.evaluate_tool_call("terminal.execute", {"command": "curl http://google.com"})
    assert permitted is False
    assert "out-of-scope target" in reason
    
    # Disallowed out-of-scope IP in command
    permitted, reason = policy.evaluate_tool_call("terminal.execute", {"command": "ping 8.8.8.8"})
    assert permitted is False
    assert "out-of-scope target" in reason

def test_policy_scope_expansion():
    policy = PolicyEngine(scope=["localhost"])
    
    # Initially blocked
    permitted, _ = policy.evaluate_tool_call("browser.goto", {"url": "https://itechindia.co/"})
    assert permitted is False
    
    # Dynamic expansion
    policy.scope.append("itechindia.co")
    permitted, _ = policy.evaluate_tool_call("browser.goto", {"url": "https://itechindia.co/"})
    assert permitted is True
