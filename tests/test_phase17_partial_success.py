import pytest
from benchmark.phase17_bench import MultiHostSyntheticLab

def test_partial_success_requires_independent_verification():
    lab = MultiHostSyntheticLab()
    obj = lab.objectives["OBJ_AUTH_BYPASS"]
    assert not obj.is_validated
    assert not obj.is_verified

    # Validate
    lab.execute_tool("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", set(), {})
    assert obj.is_validated
