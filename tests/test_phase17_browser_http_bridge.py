import pytest
from security_agent.benchmark.phase17_bench import MultiHostSyntheticLab

def test_browser_websocket_http_cross_surface():
    lab = MultiHostSyntheticLab()
    # Unlock Host B
    lab.discovered_hosts.add("192.168.1.20")
    lab.active_capabilities.add("ADMIN")

    # Connect to WebSocket bus
    resp, delta, use_class, reason = lab.execute_tool("websocket_connect", {"url": "ws://192.168.1.20:9000/events"}, "192.168.1.20", {"ADMIN"}, {})
    assert resp["status"] == 101
    assert "devops-alerts" in str(resp["events"])
    assert delta.new_evidence_count == 1
