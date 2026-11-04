import pytest
from benchmark.phase17_bench import MultiHostSyntheticLab

def test_multi_objective_independent_tracking():
    lab = MultiHostSyntheticLab()
    assert len(lab.objectives) == 4

    # Validate Host A auth
    lab.execute_tool("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", set(), {})
    assert lab.objectives["OBJ_AUTH_BYPASS"].is_verified
    assert not lab.objectives["OBJ_ADMIN_TAKEOVER"].is_verified
    assert not lab.objectives["OBJ_VAULT_EXFIL"].is_verified
