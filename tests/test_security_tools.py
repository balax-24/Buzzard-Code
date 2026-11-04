import pytest
from unittest.mock import MagicMock
from security_agent.tools.registry import ToolRegistry
from security_agent.tools.security import (
    terminal_execute,
    ping_host,
    scan_ports,
    grab_banner,
    register_security_tools
)

@pytest.fixture
def mock_sandbox():
    sandbox = MagicMock()
    return sandbox

def test_terminal_execute(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "hello world\n",
        "stderr": "",
        "exit_code": 0
    }
    res = terminal_execute("echo hello", mock_sandbox)
    assert "hello world" in res
    assert "Exit code: 0" in res
    mock_sandbox.execute.assert_called_once_with("echo hello", tool_name="terminal.execute")

def test_ping_host_success(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "64 bytes from 127.0.0.1",
        "stderr": "",
        "exit_code": 0
    }
    res = ping_host("127.0.0.1", mock_sandbox)
    assert "REACHABLE" in res
    assert "64 bytes from 127.0.0.1" in res

def test_ping_host_failure(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "",
        "stderr": "ping: unknown host google.com",
        "exit_code": 1
    }
    res = ping_host("google.com", mock_sandbox)
    assert "UNREACHABLE" in res
    assert "unknown host google.com" in res

def test_scan_ports_open_and_closed(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "22: OPEN\n80: CLOSED\n",
        "stderr": "",
        "exit_code": 0
    }
    res = scan_ports("localhost", "22,80", mock_sandbox)
    assert "Port scan results for localhost:" in res
    assert "OPEN ports: 22" in res
    assert "CLOSED ports: 80" in res

def test_scan_ports_invalid_arguments(mock_sandbox):
    res = scan_ports("localhost", "invalid-port", mock_sandbox)
    assert "Error:" in res

def test_scan_ports_too_many_ports(mock_sandbox):
    res = scan_ports("localhost", ",".join(str(p) for p in range(1, 60)), mock_sandbox)
    assert "Error: Maximum of 50 ports" in res

def test_grab_banner_success(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "SSH-2.0-OpenSSH_8.2p1\n",
        "stderr": "",
        "exit_code": 0
    }
    res = grab_banner("localhost", 22, mock_sandbox)
    assert "Successfully retrieved banner" in res
    assert "SSH-2.0-OpenSSH_8.2p1" in res

def test_grab_banner_failure(mock_sandbox):
    mock_sandbox.execute.return_value = {
        "stdout": "",
        "stderr": "Connection refused",
        "exit_code": 1
    }
    res = grab_banner("localhost", 80, mock_sandbox)
    assert "Failed to connect" in res
    assert "Connection refused" in res

def test_register_security_tools():
    registry = ToolRegistry()
    register_security_tools(registry)
    
    assert "terminal.execute" in registry.tools
    assert "ping_host" in registry.tools
    assert "scan_ports" in registry.tools
    assert "grab_banner" in registry.tools
    assert "ssl_check" in registry.tools
    assert "dns_lookup" in registry.tools
    assert "check_headers" in registry.tools

def test_dns_lookup_localhost():
    from security_agent.tools.security import dns_lookup
    res = dns_lookup("localhost")
    assert "DNS Lookup for localhost" in res
    assert "IP Addresses:" in res

def test_ssl_check_empty():
    from security_agent.tools.security import ssl_check
    res = ssl_check("")
    assert "Error: Host parameter is required." in res
