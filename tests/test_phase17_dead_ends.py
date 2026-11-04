import pytest
from benchmark.phase17_bench import MultiHostSyntheticLab

def test_dead_end_abandonment():
    lab = MultiHostSyntheticLab()
    resp, delta, use_class, reason = lab.execute_tool("http_request", {"url": "http://192.168.1.10:80/dead_end_route"}, "192.168.1.10", set(), {})
    assert use_class == "NO_INFORMATION"
    assert delta.new_findings_count == 0
