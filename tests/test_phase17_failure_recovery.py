import pytest
from security_agent.benchmark.phase17_bench import MultiHostSyntheticLab

def test_failure_recovery_preserves_state():
    lab = MultiHostSyntheticLab()
    # Execute invalid tool
    resp, delta, use_class, _ = lab.execute_tool("invalid_tool", {}, "192.168.1.10", set(), {})
    assert use_class == "NO_INFORMATION"
    assert "192.168.1.10" in lab.discovered_hosts
