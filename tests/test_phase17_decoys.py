import pytest
from security_agent.benchmark.phase17_bench import MultiHostSyntheticLab

def test_decoy_vulnerability_refutation():
    lab = MultiHostSyntheticLab()
    resp, delta, use_class, reason = lab.execute_tool("http_request", {"url": "http://192.168.1.10:80/search?q=union+select"}, "192.168.1.10", set(), {})
    assert resp.get("decoy") is True
    assert use_class == "NEW_EVIDENCE"
    assert lab.decoy_attempts.get("decoy_sqli_search") == 1
