"""
Tests for HTTP and API Security Testing Suite.
"""

import json
from security_agent.tools.http_suite import evaluate_security_headers, check_cors_configuration, probe_parameter_injection
from security_agent.range.lab_targets import CyberRangeServer


def test_evaluate_security_headers_lab():
    server = CyberRangeServer()
    host, port = server.start()
    try:
        raw_result = evaluate_security_headers(server.url)
        data = json.loads(raw_result)
        assert data["target"] == server.url
        assert "checks" in data
        assert "score" in data
        assert "recommendations" in data
    finally:
        server.stop()


def test_cors_configuration_detection():
    server = CyberRangeServer()
    host, port = server.start()
    try:
        # /api/user/profile has intentional CORS reflection in lab server
        raw_result = check_cors_configuration(f"{server.url}/api/user/profile", custom_origin="https://evil.attacker.org")
        data = json.loads(raw_result)
        assert data["is_vulnerable"] is True
        assert "CORS" in data["vulnerability_type"]
    finally:
        server.stop()


def test_parameter_injection_sqli_probe():
    server = CyberRangeServer()
    host, port = server.start()
    try:
        # /api/products?id=... has intentional mock SQLi error in lab server
        raw_result = probe_parameter_injection(f"{server.url}/api/products", parameter="id", probe_type="sql_error")
        data = json.loads(raw_result)
        assert data["potential_vulnerability"] is True
        assert len(data["indicators_found"]) > 0
    finally:
        server.stop()
