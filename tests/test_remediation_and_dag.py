import pytest
from security_agent.remediation.guidance import RemediationGenerator
from security_agent.model.schemas import Finding, Severity, Confidence
from security_agent.intelligence.evidence_parser import (
    AttackSurfaceSnapshot,
    DiscoveredService
)


def test_android_remediation_patch():
    rem_gen = RemediationGenerator()
    finding = Finding(
        id="F-ANDROID-01",
        title="Android Exported Activity and Cleartext Traffic",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="AndroidManifest.xml",
        description="Cleartext traffic allowed and exported activity without permissions.",
        impact="MITM and unauthorized IPC invocation.",
        verification="audit_android_manifest confirmed 2 issues",
        remediation="Disable cleartext and set exported=false"
    )
    patch = rem_gen.generate_patch(finding)
    assert patch.language == "xml"
    assert "android:exported=\"false\"" in patch.code_diff
    assert "network-security-config" in patch.config_snippet


def test_cors_wildcard_remediation_patch():
    rem_gen = RemediationGenerator()
    finding = Finding(
        id="F-CORS-01",
        title="CORS Wildcard Allowed Origin",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        affected_asset="http://127.0.0.1:8080/api",
        description="Access-Control-Allow-Origin: * allows any untrusted domain to read responses.",
        impact="Cross-origin sensitive data leakage.",
        verification="OPTIONS preflight returned Access-Control-Allow-Origin: *",
        remediation="Whitelist specific trusted origins"
    )
    patch = rem_gen.generate_patch(finding)
    assert patch.language == "javascript"
    assert "allowedOrigins" in patch.code_diff


def test_docker_privileged_remediation_patch():
    rem_gen = RemediationGenerator()
    finding = Finding(
        id="F-DOCKER-01",
        title="Docker Container Running as Root with Privileged Flags",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="Dockerfile",
        description="Container runs as root with full host capability privileges.",
        impact="Container breakout risk.",
        verification="audit_configurations confirmed root execution",
        remediation="Create and switch to non-root appuser"
    )
    patch = rem_gen.generate_patch(finding)
    assert patch.language == "dockerfile"
    assert "USER appuser" in patch.code_diff
    assert "cap_drop" in patch.config_snippet


def test_fast_path_dag_generation():
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    snapshot.services.append(DiscoveredService(port=8384, protocol="tcp", state="open", service="http", host="127.0.0.1"))
    snapshot.services.append(DiscoveredService(port=3306, protocol="tcp", state="open", service="mysql", host="127.0.0.1"))

    recs = snapshot.get_prioritized_pending_targets()
    assert len(recs) == 2
    # HTTP port gets whatweb_scan recommendation
    assert any(r.port == 8384 and r.recommended_tool == "whatweb_scan" for r in recs)
    # Database port gets grab_banner recommendation
    assert any(r.port == 3306 and r.recommended_tool == "grab_banner" for r in recs)
