"""
Phase 15 Tests: Action Cost & Investigation Efficiency.
Verifies cost breakdown and efficiency calculations.
"""

from security_agent.intelligence.action_cost import ActionCostEngine


def test_cost_estimation_and_efficiency():
    # Fast HTTP request
    cost_http = ActionCostEngine.estimate_cost(
        tool_name="http_request",
        expected_latency_seconds=0.5,
        retry_count=0,
        context_tokens=1000,
        expected_gain=2.0,
    )
    # Heavy port scan with retries
    cost_scan = ActionCostEngine.estimate_cost(
        tool_name="nmap",
        expected_latency_seconds=5.0,
        retry_count=2,
        context_tokens=2000,
        expected_gain=2.0,
    )

    assert cost_http.total_cost < cost_scan.total_cost
    assert cost_http.expected_efficiency > cost_scan.expected_efficiency


def test_actual_efficiency_calculation():
    eff1 = ActionCostEngine.calculate_actual_efficiency(
        actual_gain=4.0,
        actual_latency_seconds=1.0,
        tool_name="http_request",
        retries_used=0,
    )
    # total cost = 0.5 + 0.2 = 0.7 -> eff = 4.0 / 0.7 ~ 5.71
    assert eff1 > 5.0
