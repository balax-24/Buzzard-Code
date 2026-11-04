"""
Tests for Cyber Range Lab Targets, Identity Factory, and Benchmark Runner.
"""

from security_agent.range.lab_targets import CyberRangeServer
from security_agent.range.identity_factory import IdentityFactory
from security_agent.range.benchmark import BenchmarkRunner
import httpx


def test_cyber_range_server_lifecycle():
    server = CyberRangeServer()
    host, port = server.start()
    assert port > 0
    try:
        client = httpx.Client(timeout=5.0)
        resp = client.get(f"http://{host}:{port}/")
        assert resp.status_code == 200
        assert "Cyber Range Lab Portal" in resp.text
    finally:
        server.stop()


def test_identity_factory_personas():
    factory = IdentityFactory()
    suite = factory.create_persona_suite()

    assert "admin" in suite
    assert "user_a" in suite
    assert "user_b" in suite
    assert "guest" in suite

    assert suite["admin"].role == "admin"
    assert "Bearer" in suite["admin"].auth_header.get("Authorization", "")
    assert suite["user_b"].tenant_id != suite["user_a"].tenant_id


def test_benchmark_runner_execution():
    runner = BenchmarkRunner()
    scorecard = runner.run_suite()

    assert scorecard.total_challenges == 3
    assert scorecard.detected_count >= 2
    assert scorecard.detection_rate >= 0.66
    assert len(scorecard.challenge_results) == 3
