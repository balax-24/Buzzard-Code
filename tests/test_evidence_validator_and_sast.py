import os
import json
import pytest
from pathlib import Path
from security_agent.intelligence.evidence_parser import (
    EvidenceValidator,
    AttackSurfaceSnapshot,
    DiscoveredService
)
from security_agent.model.schemas import Finding, Evidence, EvidenceType, Severity, Confidence
from security_agent.tools.source_audit import (
    audit_android_manifest,
    audit_mobile_storage,
    audit_api_spec
)


def test_evidence_validator_sanitizes_unverified_port_claims():
    validator = EvidenceValidator()
    # Model claims port 39623 was discovered, but confirmed open ports are only 80, 8384
    open_ports = [80, 8384]
    raw_llm_text = (
        "Assessment Summary:\n"
        "Port 8384 was discovered open running Syncthing.\n"
        "Port 39623 was found open and vulnerable to RCE.\n"
        "Port 80 is active."
    )
    sanitized = validator.sanitize_report_claims(raw_llm_text, open_ports=open_ports)
    assert "Port 8384 was discovered" in sanitized
    assert "[UNVERIFIED INFERENCE FLAGGED]" in sanitized
    assert "39623" in sanitized


def test_ground_truth_report_generation():
    snapshot = AttackSurfaceSnapshot(target="127.0.0.1")
    snapshot.services.append(DiscoveredService(port=8384, protocol="tcp", state="open", service="http", version="Syncthing GUI", host="127.0.0.1"))
    
    findings = [
        Finding(
            id="f-1",
            title="Unauthenticated Administrative Interface",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            affected_asset="http://127.0.0.1:8384",
            description="Syncthing web interface accessible without credentials.",
            impact="Full configuration modification possible.",
            verification="HTTP/1.1 200 OK\nServer: Syncthing",
            remediation="Enable GUI password authentication in config.xml"
        )
    ]
    evidence = [
        Evidence(
            id="e-1",
            type=EvidenceType.TERMINAL,
            target="127.0.0.1",
            description="8384/tcp open http Syncthing GUI",
            data="Starting Nmap...\n8384/tcp open http Syncthing GUI",
            timestamp="2026-08-22T12:00:00Z"
        )
    ]

    validator = EvidenceValidator(snapshot=snapshot)
    report = validator.generate_ground_truth_report(
        session_id="test-session-1234",
        target="127.0.0.1",
        goal="Audit exposed web interfaces",
        snapshot=snapshot,
        findings=findings,
        evidence=evidence
    )

    assert "8384/tcp" in report
    assert "Syncthing GUI" in report
    assert "Unauthenticated Administrative Interface" in report
    assert "100% EVIDENCE-GROUNDED" in report


def test_audit_android_manifest_detection(tmp_path):
    manifest_file = tmp_path / "AndroidManifest.xml"
    manifest_file.write_text("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true">
        <activity android:name=".InsecureActivity" android:exported="true" />
    </application>
</manifest>
""")
    res_str = audit_android_manifest(str(manifest_file))
    data = json.loads(res_str)
    assert data["total_issues_found"] >= 3
    titles = [f["title"] for f in data["findings"]]
    assert any("Debuggable" in t for t in titles)
    assert any("Cleartext" in t for t in titles)
    assert any("Exported" in t for t in titles)


def test_audit_mobile_storage_detection(tmp_path):
    code_file = tmp_path / "AuthHelper.kt"
    code_file.write_text("""
package com.example.app
import android.content.Context

class AuthHelper {
    fun save() {
        val sp = ctx.getSharedPreferences("prefs", Context.MODE_WORLD_READABLE)
        val query = db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)
    }
}
""")
    res_str = audit_mobile_storage(str(tmp_path))
    data = json.loads(res_str)
    assert data["mobile_security_findings_count"] >= 2
    titles = [f["title"] for f in data["findings"]]
    assert any("World-Readable" in t for t in titles)
    assert any("SQL Injection" in t for t in titles)


def test_audit_api_spec_detection(tmp_path):
    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "servers": [{"url": "http://api.production.example.com"}],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users"
                }
            }
        }
    }))
    res_str = audit_api_spec(str(spec_file))
    data = json.loads(res_str)
    assert data["total_issues"] >= 2
    titles = [f["title"] for f in data["findings"]]
    assert any("Unencrypted HTTP" in t for t in titles)
    assert any("Security Schemes" in t for t in titles)
