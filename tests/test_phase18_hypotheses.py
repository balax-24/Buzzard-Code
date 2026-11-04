import pytest
from benchmark.phase17_bench import HypothesisLifecycleState, Phase17Hypothesis

def test_hypothesis_persistence_state():
    hyp = Phase17Hypothesis("HYP-PERSIST", "192.168.1.10", "AUTH_BYPASS", HypothesisLifecycleState.REFUTED)
    hyp.refutation_reason = "WAF blocked"

    assert hyp.state == HypothesisLifecycleState.REFUTED
    assert hyp.refutation_reason == "WAF blocked"
