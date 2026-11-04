import pytest
from security_agent.benchmark.phase17_bench import HypothesisLifecycleState, Phase17Hypothesis

def test_hypothesis_lifecycle_transitions():
    hyp = Phase17Hypothesis("HYP-1", "192.168.1.10", "SQLI", HypothesisLifecycleState.PROPOSED)
    assert hyp.state == HypothesisLifecycleState.PROPOSED

    hyp.state = HypothesisLifecycleState.INVESTIGATING
    assert hyp.state == HypothesisLifecycleState.INVESTIGATING

    hyp.state = HypothesisLifecycleState.REFUTED
    hyp.refutation_reason = "WAF filter syntax rejection; confirmed non-exploitable."
    assert hyp.state == HypothesisLifecycleState.REFUTED
    assert "WAF" in hyp.refutation_reason
