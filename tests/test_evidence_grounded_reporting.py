"""
Tests for Evidence-Grounded Reporting (P2-3).

Validates:
1. Verified finding -> reportable as confirmed.
2. Unverified hypothesis -> not reported as confirmed finding.
3. Missing evidence -> UNKNOWN (no invented/hallucinated data).
4. Contradictory evidence -> unresolved/UNKNOWN as appropriate.
5. Evidence provenance retained (source_tool, target, timestamp, evidence_ids).
6. Secrets remain redacted across Markdown, JSON, and Console.
7. Report survives checkpoint restore (AssessmentState.to_dict -> from_dict).
"""

import json
import pytest
from reports.report_generator import ReportGenerator, redact_secrets
from agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    ServiceState,
    VerificationStatus,
    HypothesisStatus,
    VulnerabilityHypothesis,
)
from model.schemas import Finding, Severity, Confidence, Evidence, EvidenceType


@pytest.fixture
def base_state():
    ctx = AssessmentContext(
        target="127.0.0.1",
        scope=("127.0.0.1", "localhost"),
        objective="Verify system security posture",
    )
    return AssessmentState(context=ctx)


@pytest.fixture
def generator():
    return ReportGenerator()


# ---------------------------------------------------------------------------
# Test 1: Verified finding -> reportable as confirmed
# ---------------------------------------------------------------------------
def test_verified_finding_reportable(generator, base_state):
    """
    Ensures that findings verified by raw evidence are classified as confirmed findings
    and rendered into the detailed technical findings section.
    """
    base_state.add_evidence(
        raw_data="uid=0(root) gid=0(root) groups=0(root)",
        source_tool="ssh_exec",
        target="127.0.0.1:22",
        evidence_id="EVI-SSH-ROOT",
    )

    finding = {
        "id": "FIND-SSH-001",
        "title": "Default Root SSH Credentials",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "affected_asset": "127.0.0.1:22",
        "description": "Default root credentials accepted on SSH daemon.",
        "impact": "Full host compromise with administrative privileges.",
        "verification": "sshpass -p root ssh root@127.0.0.1 id -> uid=0(root)",
        "evidence_ids": ["EVI-SSH-ROOT"],
        "remediation": "Disable root password authentication and enforce SSH keys.",
        "verified": True,
        "verification_status": "VERIFIED",
    }
    base_state.findings.append(finding)

    report = generator.generate_report_data(state=base_state)

    # 1. Classified as confirmed finding
    assert len(report["findings"]) == 1
    assert len(report["confirmed_findings"]) == 1
    conf_f = report["findings"][0]
    assert conf_f["id"] == "FIND-SSH-001"
    assert conf_f["verified"] is True
    assert conf_f["verification_status"] == "VERIFIED"
    assert "EVI-SSH-ROOT" in conf_f["evidence_ids"]

    # 2. Rendered in Markdown
    md = generator.render_markdown(report)
    assert "### 1. [CRITICAL] Default Root SSH Credentials" in md
    assert "CONFIRMED (VERIFIED)" in md
    assert "EVI-SSH-ROOT" in md


# ---------------------------------------------------------------------------
# Test 2: Unverified hypothesis -> not reported as confirmed finding
# ---------------------------------------------------------------------------
def test_unverified_hypothesis_not_reported_as_confirmed(generator, base_state):
    """
    Ensures unverified hypotheses remain explicitly UNVERIFIED and are NOT
    presented as confirmed vulnerabilities.
    """
    # Active unverified hypothesis
    base_state.record_hypothesis(
        target="127.0.0.1",
        service="http",
        port=80,
        vulnerability_type="sql_injection",
        rationale="Possible SQL injection in /search query parameter",
    )

    # Candidate finding without verification
    unconfirmed_finding = {
        "id": "FIND-CAND-001",
        "title": "Suspected Blind SQL Injection",
        "severity": "HIGH",
        "confidence": "HYPOTHESIS",
        "affected_asset": "127.0.0.1:80",
        "description": "Observed database syntax error in verbose error output.",
        "evidence_ids": [],
        "verified": False,
        "verification_status": "UNVERIFIED",
    }
    base_state.findings.append(unconfirmed_finding)

    report = generator.generate_report_data(state=base_state)

    # Confirmed findings must be empty
    assert len(report["findings"]) == 0
    assert len(report["confirmed_findings"]) == 0

    # Must appear in unverified sections
    assert len(report["unverified_hypotheses"]) >= 1
    assert any(h["vulnerability_type"] == "sql_injection" for h in report["unverified_hypotheses"])
    for h in report["unverified_hypotheses"]:
        assert h["verified"] is False
        assert h["verification_status"] == "UNVERIFIED"

    assert len(report["unverified_findings"]) == 1
    assert report["unverified_findings"][0]["id"] == "FIND-CAND-001"
    assert report["unverified_findings"][0]["verified"] is False

    # Markdown must explicitly state these are UNVERIFIED
    md = generator.render_markdown(report)
    assert "No confirmed exploitable vulnerabilities were identified" in md
    assert "Unverified Hypotheses & Potential Leads" in md
    assert "NOT confirmed vulnerabilities" in md


# ---------------------------------------------------------------------------
# Test 3: Missing evidence -> UNKNOWN
# ---------------------------------------------------------------------------
def test_missing_evidence_defaults_to_unknown(generator, base_state):
    """
    Ensures that when evidence is missing, the reporting pipeline uses UNKNOWN
    rather than inventing or guessing details.
    """
    # Open service with unverified banner
    base_state.record_service(
        host="127.0.0.1",
        port=8080,
        protocol="tcp",
        service="http-proxy",
        version="UNKNOWN",
        state=ServiceState.OPEN,
        verification_status=VerificationStatus.UNKNOWN,
    )

    # Finding with empty/missing attributes
    finding = {
        "id": "FIND-BARE-001",
        "title": "Minimal Incomplete Finding",
        "severity": "MEDIUM",
        "affected_asset": "",
        "description": "",
        "impact": "",
        "verification": "",
        "evidence_ids": [],
        "verified": True,
        "verification_status": "VERIFIED",
    }
    base_state.findings.append(finding)

    report = generator.generate_report_data(state=base_state)

    # Service version is UNKNOWN
    srv = [s for s in report["services"] if s["port"] == 8080][0]
    assert srv["version"] == "UNKNOWN"
    assert srv["status"] == "UNKNOWN"

    # Finding had no evidence -> cannot be confirmed
    assert len(report["findings"]) == 0
    assert len(report["unverified_findings"]) == 1
    unv = report["unverified_findings"][0]
    assert unv["affected_asset"] == "127.0.0.1"
    assert unv["description"] == "UNKNOWN"
    assert unv["impact"] == "UNKNOWN"
    assert unv["verification"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# Test 4: Contradictory evidence -> unresolved/UNKNOWN as appropriate
# ---------------------------------------------------------------------------
def test_contradictory_evidence_surfaced_as_unresolved(generator, base_state):
    """
    Ensures that conflicting evidence records cause findings/claims to be marked
    as CONTRADICTED/UNRESOLVED rather than confirmed.
    """
    base_state.add_evidence(
        raw_data="HTTP/1.1 200 OK",
        source_tool="curl_probe",
        target="127.0.0.1:80",
        evidence_id="EVI-HTTP-UP",
    )
    base_state.add_evidence(
        raw_data="Connection refused on 127.0.0.1:80",
        source_tool="nc_probe",
        target="127.0.0.1:80",
        evidence_id="EVI-HTTP-DOWN",
    )

    # Record contradiction
    base_state.contradictions.append({
        "type": "HTTP_AVAILABILITY_CONFLICT",
        "description": "Conflicting evidence on port 80: probe succeeded while TCP handshake failed.",
        "evidence_ids": ["EVI-HTTP-UP", "EVI-HTTP-DOWN"],
    })

    # Finding based on contradicted evidence
    finding = {
        "id": "FIND-CONTRADICTED-001",
        "title": "Exposed Web Console",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "affected_asset": "127.0.0.1:80",
        "description": "Admin web console exposed.",
        "evidence_ids": ["EVI-HTTP-UP"],
        "verified": True,
        "verification_status": "VERIFIED",
    }
    base_state.findings.append(finding)

    report = generator.generate_report_data(state=base_state)

    # Must NOT be in confirmed findings
    assert len(report["findings"]) == 0
    assert len(report["unverified_findings"]) == 1

    unv = report["unverified_findings"][0]
    assert unv["verification_status"] == "CONTRADICTED"
    assert unv["verified"] is False

    # Contradiction documented in report
    assert len(report["contradictions"]) == 1
    assert "EVI-HTTP-UP" in report["contradictions"][0]["evidence_ids"]

    # Markdown alert
    md = generator.render_markdown(report)
    assert "Contradictions Detected & Flagged" in md
    assert "UNRESOLVED" in md


# ---------------------------------------------------------------------------
# Test 5: Evidence provenance retained
# ---------------------------------------------------------------------------
def test_evidence_provenance_retained(generator, base_state):
    """
    Ensures full provenance (source_tool, target, timestamp, evidence_ids)
    is retained for every finding and evidence record.
    """
    eid = base_state.add_evidence(
        raw_data="22/tcp open OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        source_tool="banner_grabber",
        target="127.0.0.1:22",
        evidence_id="EVI-SSH-PROV",
        metadata={"scanner_version": "1.0"},
    )

    finding = {
        "id": "FIND-SSH-BANNER",
        "title": "OpenSSH Version Disclosure",
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "affected_asset": "127.0.0.1:22",
        "description": "Verbose banner disclosure",
        "evidence_ids": [eid],
        "verified": True,
        "verification_status": "VERIFIED",
    }
    base_state.findings.append(finding)

    report = generator.generate_report_data(state=base_state)

    conf_f = report["findings"][0]
    assert "provenance" in conf_f
    prov = conf_f["provenance"]
    assert prov["source_tool"] == "banner_grabber"
    assert prov["target"] == "127.0.0.1:22"
    assert eid in prov["evidence_ids"]
    assert prov["timestamp"] != ""

    # Check evidence table in report
    assert len(report["evidence"]) >= 1
    ev_entry = [e for e in report["evidence"] if e["id"] == eid][0]
    assert ev_entry["source_tool"] == "BANNER_GRABBER"
    assert ev_entry["target"] == "127.0.0.1:22"


# ---------------------------------------------------------------------------
# Test 6: Secrets remain redacted
# ---------------------------------------------------------------------------
def test_secrets_remain_redacted(generator, base_state):
    """
    Ensures credentials, bearer tokens, private keys, session cookies, and JWTs
    are strictly redacted across all output formats.
    """
    secret_pass = "P@ssw0rd987!"
    secret_token = "ghp_1234567890abcdef1234567890abcdef12"
    secret_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END RSA PRIVATE KEY-----"

    # Redact helper unit verification
    assert secret_pass not in redact_secrets(f"password={secret_pass}")
    assert "[REDACTED]" in redact_secrets(f"password={secret_pass}")
    assert secret_token not in redact_secrets(f"token='{secret_token}'")
    assert "[REDACTED]" in redact_secrets(f"api_key: '{secret_token}'")
    assert "[REDACTED]" in redact_secrets(secret_bearer)
    assert priv_key not in redact_secrets(priv_key)
    assert "[REDACTED_PRIVATE_KEY]" in redact_secrets(priv_key)

    # Integration verification in generated report
    base_state.add_evidence(
        raw_data=f"HTTP/1.1 200 OK\nSet-Cookie: session_id=SECRET123; HttpOnly\nAuthorization: Bearer mytoken123\n\n{priv_key}",
        source_tool="http_dumper",
        target="127.0.0.1:80",
        evidence_id="EVI-SECRET-001",
    )
    finding = {
        "id": "FIND-SECRET-001",
        "title": f"Leaked Key: password={secret_pass}",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "affected_asset": "127.0.0.1:80",
        "description": f"Found private key and token={secret_token}",
        "verification": f"curl -H 'Authorization: {secret_bearer}' http://127.0.0.1/admin",
        "evidence_ids": ["EVI-SECRET-001"],
        "verified": True,
        "verification_status": "VERIFIED",
    }
    base_state.findings.append(finding)

    report = generator.generate_report_data(state=base_state)
    json_out = generator.render_json(report)
    md_out = generator.render_markdown(report)

    # None of the raw secrets should appear in JSON or Markdown
    assert secret_pass not in json_out
    assert secret_pass not in md_out
    assert secret_token not in json_out
    assert secret_token not in md_out
    assert "SECRET123" not in json_out
    assert "SECRET123" not in md_out
    assert priv_key not in json_out
    assert priv_key not in md_out


# ---------------------------------------------------------------------------
# Test 7: Report survives checkpoint restore
# ---------------------------------------------------------------------------
def test_report_survives_checkpoint_restore(generator, base_state):
    """
    Ensures that report generation output is identical before and after
    checkpoint serialization (to_dict -> from_dict).
    """
    # 1. Populate rich state
    base_state.record_service(
        host="127.0.0.1",
        port=443,
        protocol="tcp",
        service="https",
        version="nginx 1.18.0",
        state=ServiceState.OPEN,
        evidence_id="EVI-PORT-443",
        verification_status=VerificationStatus.VERIFIED,
    )
    base_state.add_evidence(
        raw_data="TLS cert valid",
        source_tool="ssl_probe",
        target="127.0.0.1:443",
        evidence_id="EVI-PORT-443",
    )
    base_state.add_evidence(
        raw_data="TLSv1.0 accepted in handshake",
        source_tool="sslscan",
        target="127.0.0.1:443",
        evidence_id="EVI-TLS-CONFIRMED",
    )
    base_state.findings.append({
        "id": "FIND-TLS-001",
        "title": "Weak TLS 1.0 Supported",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "affected_asset": "127.0.0.1:443",
        "description": "Server accepts obsolete TLS 1.0 handshakes.",
        "evidence_ids": ["EVI-TLS-CONFIRMED"],
        "verification": "sslscan 127.0.0.1:443 -> TLSv1.0 enabled",
        "verified": True,
        "verification_status": "VERIFIED",
    })
    base_state.record_hypothesis(
        target="127.0.0.1",
        service="https",
        port=443,
        vulnerability_type="weak_cipher",
        rationale="Hypothesis: 3DES ciphers might be accepted",
    )
    base_state.contradictions.append({
        "type": "CIPHER_MISMATCH",
        "description": "Nmap reported RC4 supported but testssl refused handshake.",
        "evidence_ids": ["EVI-PORT-443"],
    })

    # Generate initial report data
    report_orig = generator.generate_report_data(state=base_state, session_id="ckpt-test")

    # Checkpoint serialization
    serialized = base_state.to_dict()
    assert "findings" in serialized
    assert "evidence" in serialized
    assert "contradictions" in serialized

    # Checkpoint deserialization
    restored_state = AssessmentState.from_dict(serialized)
    report_restored = generator.generate_report_data(state=restored_state, session_id="ckpt-test")

    # Verify structural and semantic parity
    assert len(report_restored["findings"]) == len(report_orig["findings"])
    assert len(report_restored["confirmed_findings"]) == len(report_orig["confirmed_findings"])
    assert len(report_restored["unverified_hypotheses"]) == len(report_orig["unverified_hypotheses"])
    assert len(report_restored["contradictions"]) == len(report_orig["contradictions"])
    assert len(report_restored["services"]) == len(report_orig["services"])

    assert report_restored["findings"][0]["id"] == report_orig["findings"][0]["id"]
    assert report_restored["findings"][0]["evidence_ids"] == report_orig["findings"][0]["evidence_ids"]
    assert report_restored["services"][0]["version"] == report_orig["services"][0]["version"]
    assert report_restored["contradictions"][0]["type"] == report_orig["contradictions"][0]["type"]
