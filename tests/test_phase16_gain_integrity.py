"""
Phase 16 Tests: Information Gain Integrity & Delta-Based Evaluation.
Verifies that gain is 0 when all deltas are 0, and that successful execution does not imply gain.
"""

from benchmark.phase16_bench import Phase16InvestigationBenchmark, UsefulnessClassification
from intelligence.noop_detector import ActionDelta


def test_zero_gain_when_no_delta():
    empty_delta = ActionDelta(new_nodes_count=0, new_evidence_count=0, new_capabilities_count=0, new_findings_count=0)
    gain = Phase16InvestigationBenchmark.calculate_delta_gain(empty_delta, UsefulnessClassification.NO_INFORMATION)
    assert gain == 0.0


def test_positive_gain_when_material_delta():
    delta = ActionDelta(new_nodes_count=2, new_evidence_count=1, new_capabilities_count=1)
    gain = Phase16InvestigationBenchmark.calculate_delta_gain(delta, UsefulnessClassification.NEW_CAPABILITY)
    assert gain > 5.0
