import pytest
from benchmark.phase17_bench import MultiHostSyntheticLab

def test_session_isolation_between_hosts():
    lab = MultiHostSyntheticLab()
    # Discover Host B via Host A auth flow
    lab.execute_tool("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", set(), {})
    assert "192.168.1.20" in lab.discovered_hosts

    # Unauthenticated Host B request fails with 401
    resp, delta, use_class, reason = lab.execute_tool("http_request", {"url": "http://192.168.1.20:8443/admin"}, "192.168.1.20", set(), {})
    assert resp["status"] == 401
    assert use_class == "NO_INFORMATION"
