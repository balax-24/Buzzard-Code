"""
Phase 15 Tests: No-Op Action & Stagnation Detection.
Verifies identification of non-productive actions and automatic pivot triggers.
"""

from security_agent.intelligence.noop_detector import NoOpDetector, ActionDelta


def test_noop_stagnation_and_pivot_trigger():
    detector = NoOpDetector(pivot_threshold=3)

    # 1. Productive action
    d1 = ActionDelta(new_evidence_count=1, new_nodes_count=2)
    ev1 = detector.evaluate_delta(d1, "nmap", "127.0.0.1")
    assert ev1.is_noop is False
    assert ev1.consecutive_noops == 0
    assert ev1.should_trigger_pivot is False

    # 2. First no-op action
    d2 = ActionDelta()  # All zero
    ev2 = detector.evaluate_delta(d2, "nmap", "127.0.0.1")
    assert ev2.is_noop is True
    assert ev2.consecutive_noops == 1
    assert ev2.should_trigger_pivot is False

    # 3. Second no-op action
    ev3 = detector.evaluate_delta(ActionDelta(), "nmap", "127.0.0.1")
    assert ev3.consecutive_noops == 2
    assert ev3.should_trigger_pivot is False

    # 4. Third no-op action -> Reaches pivot threshold!
    ev4 = detector.evaluate_delta(ActionDelta(), "nmap", "127.0.0.1")
    assert ev4.consecutive_noops == 3
    assert ev4.should_trigger_pivot is True
    assert "PIVOT REQUIRED" in ev4.rationale
