import pytest
from benchmark.phase17_bench import MultiHostSyntheticLab, PrivilegeLevel

def test_privilege_transitions_evidence_backed():
    lab = MultiHostSyntheticLab()
    assert lab.current_privilege == PrivilegeLevel.UNAUTHENTICATED

    # Transition to AUTHENTICATED
    lab.execute_tool("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", set(), {})
    assert lab.current_privilege == PrivilegeLevel.AUTHENTICATED

    # Transition to ADMIN
    lab.execute_tool("http_request", {"url": "http://192.168.1.20:8443/admin"}, "192.168.1.20", {"AUTHENTICATED"}, {})
    assert lab.current_privilege == PrivilegeLevel.ADMIN
