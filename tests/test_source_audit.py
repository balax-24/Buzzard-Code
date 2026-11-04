"""
Tests for Source Code, Secrets, and Configuration Auditing Suite.
"""

import json
from pathlib import Path
from tools.source_audit import scan_source_secrets, audit_configurations


def test_scan_source_secrets(tmp_path):
    test_file = tmp_path / "app_config.py"
    test_file.write_text("AWS_KEY = 'AKIA1234567890ABCDEF'\nOPENAI_KEY = 'sk-123456789012345678901234567890123456789012345678'\n")

    raw_result = scan_source_secrets(str(tmp_path))
    data = json.loads(raw_result)
    assert data["secrets_found_count"] >= 2
    types = [f["secret_type"] for f in data["findings"]]
    assert "AWS Access Key ID" in types
    assert "OpenAI API Key" in types


def test_audit_configurations_dockerfile(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n")

    raw_result = audit_configurations(str(tmp_path))
    data = json.loads(raw_result)
    assert data["configuration_issues_count"] >= 1
    assert any("root USER" in issue["issue"] for issue in data["issues"])


def test_audit_configurations_docker_compose(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("version: '3.8'\nservices:\n  worker:\n    image: worker:latest\n    privileged: true\n")

    raw_result = audit_configurations(str(tmp_path))
    data = json.loads(raw_result)
    assert data["configuration_issues_count"] >= 1
    assert any("privileged" in issue["issue"].lower() for issue in data["issues"])
