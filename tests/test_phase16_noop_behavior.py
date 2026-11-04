"""
Phase 16 Tests: Zero-Information No-Op Detection & Strategy Pivot.
Proves that repeating zero-delta actions triggers strategy diversification.
"""

from security_agent.intelligence.noop_detector import NoOpDetector, ActionDelta


def test_consecutive_noops_trigger_pivot():
    detector = NoOpDetector(pivot_threshold=3)
    empty_delta = ActionDelta()

    assert detector.evaluate_delta(empty_delta, "http_request", "127.0.0.1").should_pivot is False
    assert detector.evaluate_delta(empty_delta, "http_request", "127.0.0.1").should_pivot is False

    eval3 = detector.evaluate_delta(empty_delta, "http_request", "127.0.0.1")
    assert eval3.should_pivot is True
    assert detector.consecutive_noops == 3
