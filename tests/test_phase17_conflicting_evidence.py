import pytest
from benchmark.phase17_bench import EvidenceConfidence, Phase17Evidence

def test_conflicting_evidence_tracking():
    evi1 = Phase17Evidence("EVI-1", "192.168.1.10", "http", "http_headers", "WAF: ENABLED", 100.0, EvidenceConfidence.PROBABLE)
    evi2 = Phase17Evidence("EVI-2", "192.168.1.10", "http", "http_body", "WAF_STATUS: DISABLED", 101.0, EvidenceConfidence.PROBABLE)

    # Link conflicts
    evi1.conflicting_evidence_ids.append("EVI-2")
    evi2.conflicting_evidence_ids.append("EVI-1")
    evi1.confidence = EvidenceConfidence.CONFLICTING
    evi2.confidence = EvidenceConfidence.CONFLICTING

    assert "EVI-2" in evi1.conflicting_evidence_ids
    assert evi1.confidence == EvidenceConfidence.CONFLICTING
