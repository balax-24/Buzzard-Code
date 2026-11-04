"""
Phase 16 Tests: Synthetic Environment Integrity.
Verifies that the synthetic environment is deterministic and does NOT cheat with artificial turn mutations.
"""

from benchmark.phase16_bench import SyntheticInvestigationEnvironment, UsefulnessClassification


def test_synthetic_environment_is_deterministic_and_does_not_mutate_without_cause():
    env = SyntheticInvestigationEnvironment()

    # Call 1: Discover home
    _, delta1, use1, _ = env.execute_action("http_request", {"url": "http://127.0.0.1:8080/"}, "127.0.0.1", set(), {})
    assert delta1.new_nodes_count > 0
    assert use1 == UsefulnessClassification.NEW_GRAPH_NODE

    # Call 2: Identical probe without any state changes -> MUST return NO_INFORMATION
    _, delta2, use2, _ = env.execute_action("http_request", {"url": "http://127.0.0.1:8080/"}, "127.0.0.1", set(), {})
    assert delta2.new_nodes_count == 0
    assert delta2.new_evidence_count == 0
    assert use2 == UsefulnessClassification.NO_INFORMATION

    # Call 3: Probe admin without auth -> MUST return 401 and NO_INFORMATION
    resp3, delta3, use3, _ = env.execute_action("http_request", {"url": "http://127.0.0.1:8080/api/v1/admin"}, "127.0.0.1", set(), {})
    assert resp3["status"] == 401
    assert use3 == UsefulnessClassification.NO_INFORMATION

    # Call 4: Acquire auth -> now probe admin with AUTHENTICATED -> MUST return finding
    _, delta4, use4, _ = env.execute_action("http_request", {"url": "http://127.0.0.1:8080/api/v1/admin"}, "127.0.0.1", {"AUTHENTICATED"}, {"token": "JWT_SECRET_TOKEN_ADMIN"})
    assert delta4.new_findings_count == 1
    assert use4 == UsefulnessClassification.NEW_FINDING
