"""
Tests for Security Intelligence: AssetGraph, ThreatModeler, HypothesisEngine, and IndependentJudge.
"""

from intelligence.asset_graph import AssetGraph, AssetType
from intelligence.threat_model import ThreatModeler, STRIDECategory
from intelligence.hypothesis import HypothesisEngine, HypothesisStatus
from intelligence.judge import IndependentJudge
from model.schemas import Severity, Confidence
from events.bus import EventBus


def test_asset_graph_and_topology():
    graph = AssetGraph()
    graph.add_host("api.target.internal", ip="10.0.1.5")
    graph.add_service("api.target.internal", 443, "HTTPS/Nginx")
    graph.add_endpoint("https://api.target.internal/v1/auth", method="POST", auth_required=False)
    graph.add_parameter("https://api.target.internal/v1/auth", "username")

    summary = graph.summary()
    assert "1 host" in summary
    assert "1 endpoint" in summary
    assert "1 parameter" in summary

    d = graph.to_dict()
    assert d["node_count"] == 4
    assert d["edge_count"] == 2


def test_threat_modeler_scenarios():
    graph = AssetGraph()
    graph.add_endpoint("https://target.local/api/user", method="GET", auth_required=True)
    graph.add_parameter("https://target.local/api/user", "user_id")

    modeler = ThreatModeler(graph)
    scenarios = modeler.generate_threat_scenarios()

    assert len(scenarios) >= 2
    categories = [s.category for s in scenarios]
    assert STRIDECategory.ELEVATION_OF_PRIVILEGE in categories
    assert STRIDECategory.TAMPERING in categories


def test_hypothesis_engine_lifecycle():
    bus = EventBus()
    engine = HypothesisEngine(event_bus=bus)

    hypo = engine.create_hypothesis(
        target_asset="https://target.local/api/login",
        vulnerability_type="SQL Injection",
        description="Login form may be vulnerable to SQL syntax injection"
    )
    assert hypo.status == HypothesisStatus.HYPOTHESIS
    assert len(engine.get_pending()) == 1

    engine.update_status(hypo.id, HypothesisStatus.VERIFIED, evidence_id="EV-100")
    assert hypo.status == HypothesisStatus.VERIFIED
    assert hypo.confidence_score == 1.0
    assert len(engine.get_verified()) == 1


def test_independent_judge_sqli_verdict():
    judge = IndependentJudge()
    evidence_sqli = {
        "indicators_found": [{
            "probe": "' OR '1'='1",
            "matched_pattern": "SQL syntax.*MySQL"
        }]
    }

    verdict = judge.evaluate_finding(
        candidate_title="SQLi Test",
        affected_asset="https://target.local/search",
        evidence_data=evidence_sqli,
        vulnerability_type="sql_injection"
    )
    assert verdict.is_confirmed is True
    assert verdict.severity == Severity.HIGH
    assert verdict.confidence == Confidence.CONFIRMED
