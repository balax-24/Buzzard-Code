"""
Tests for Remediation and Retest Subsystems.
"""

from model.schemas import Finding, Severity, Confidence
from remediation.guidance import RemediationGenerator
from remediation.retest import RetestEngine
from range.lab_targets import CyberRangeServer


def test_remediation_generator_sqli():
    gen = RemediationGenerator()
    finding = Finding(
        id="FIND-SQLI-01",
        title="SQL Injection in user parameter",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="https://target.local/users",
        description="Raw SQL query concatenation",
        evidence=[],
        impact="Database compromise",
        verification="PoC probe",
        remediation="Parameterized queries"
    )

    patch = gen.generate_patch(finding)
    assert patch.finding_id == "FIND-SQLI-01"
    assert "parameterized" in patch.summary.lower()
    assert "cursor.execute" in patch.code_diff
    assert len(patch.validation_steps) > 0


def test_retest_engine_regression_script_generation():
    engine = RetestEngine()
    finding = Finding(
        id="FIND-XSS-02",
        title="Reflected XSS in search",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        affected_asset="https://target.local/search",
        description="Unencoded search reflection",
        evidence=[],
        impact="Script execution",
        verification="PoC <script>",
        remediation="Output encode"
    )

    script = engine.generate_regression_test_script(finding)
    assert "def test_security_remediation_FIND_XSS_02():" in script
    assert "https://target.local/search" in script


def test_retest_engine_live_execution():
    server = CyberRangeServer()
    host, port = server.start()
    try:
        engine = RetestEngine()
        finding = Finding(
            id="FIND-LIVE-01",
            title="Safe Homepage Endpoint",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            affected_asset=f"{server.url}/",
            description="Homepage check",
            evidence=[],
            impact="None",
            verification="",
            remediation=""
        )

        result = engine.execute_live_retest(finding)
        assert result.is_remediated is True
        assert result.status_code == 200
    finally:
        server.stop()
