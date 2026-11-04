"""
Tests for Verification Pipeline and Attack Path Analyzer.
"""

from security_agent.storage.db import StorageManager
from security_agent.intelligence.hypothesis import SecurityHypothesis, HypothesisStatus
from security_agent.verification.pipeline import VerificationPipeline
from security_agent.verification.attack_paths import AttackPathAnalyzer
from security_agent.model.schemas import Finding, Severity, Confidence


def test_verification_pipeline_confirmed_finding(tmp_path):
    db_path = str(tmp_path / "test_verify.db")
    storage = StorageManager(db_path=db_path)
    session_id = "session-verify-001"
    storage.create_session(session_id, "https://target.local", ["target.local"], "Verify SQLi")

    pipeline = VerificationPipeline(storage_manager=storage)
    hypo = SecurityHypothesis(
        id="HYP-001",
        target_asset="https://target.local/products",
        vulnerability_type="SQL Injection",
        description="Candidate SQL flaw on products API"
    )

    evidence_data = {
        "indicators_found": [{
            "probe": "' OR 1=1--",
            "matched_pattern": "sqlite3.OperationalError"
        }]
    }

    finding = pipeline.verify_hypothesis(
        session_id=session_id,
        hypothesis=hypo,
        raw_evidence_data=evidence_data,
        remediation_hint="Use parameterized queries"
    )

    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert hypo.status == HypothesisStatus.VERIFIED

    # Check persistence
    stored_findings = storage.get_findings(session_id)
    assert len(stored_findings) == 1
    assert stored_findings[0].affected_asset == "https://target.local/products"


def test_attack_path_analyzer():
    findings = [
        Finding(
            id="FIND-01",
            title="Missing Auth on Profile Endpoint",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_asset="https://target.local/api/profile",
            description="Unauthenticated access allowed",
            evidence=["EV-01"],
            impact="Unauthorized user profile leakage",
            verification="PoC GET /api/profile",
            remediation="Enforce auth middleware"
        ),
        Finding(
            id="FIND-02",
            title="CORS Arbitrary Origin Reflection",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            affected_asset="https://target.local/api/profile",
            description="CORS misconfiguration",
            evidence=["EV-02"],
            impact="Cross-origin profile reading",
            verification="PoC Origin: attacker.com",
            remediation="Fix ACAO header"
        )
    ]

    analyzer = AttackPathAnalyzer(findings)
    paths = analyzer.analyze_paths()

    assert len(paths) == 1
    path = paths[0]
    assert path.overall_severity == Severity.HIGH
    assert len(path.steps) == 2
    assert "https://target.local/api/profile" in path.title
