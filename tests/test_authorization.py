"""
Tests for Assessment Authorization and AuthorizationEngine.
"""

from datetime import datetime, timezone, timedelta
import pytest

from security.autonomy import AutonomyLevel, EnvironmentProfile
from security.risk import RiskClass
from security.authorization import (
    AssessmentAuthorization,
    AuthorizationEngine,
    create_default_authorization,
)


def test_authorization_creation_and_defaults():
    auth = AssessmentAuthorization(
        operator_name="Alice SecOps",
        target_hosts=["target.local", "192.168.1.10"],
        environment=EnvironmentProfile.LAB,
    )
    assert auth.id.startswith("AUTH-")
    assert auth.operator_name == "Alice SecOps"
    assert auth.environment == EnvironmentProfile.LAB
    assert auth.signature is not None
    assert not auth.is_expired()


def test_authorization_expiration():
    past_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    auth = AssessmentAuthorization(
        operator_name="Bob",
        target_hosts=["example.com"],
        expires_at=past_time,
    )
    assert auth.is_expired()

    engine = AuthorizationEngine(auth)
    valid, msg = engine.validate_authorization()
    assert not valid
    assert "expired" in msg.lower()


def test_authorization_target_check():
    auth = AssessmentAuthorization(
        target_hosts=["app.example.internal", "api.example.internal"],
        environment=EnvironmentProfile.STAGING,
    )
    engine = AuthorizationEngine(auth)

    ok, _ = engine.is_target_authorized("https://app.example.internal/login")
    assert ok

    ok_out, msg = engine.is_target_authorized("https://malicious.external.com")
    assert not ok_out
    assert "not covered" in msg.lower()


def test_authorization_risk_class():
    auth = AssessmentAuthorization(
        allowed_risk_classes=[RiskClass.R0_PASSIVE, RiskClass.R1_LOW],
    )
    engine = AuthorizationEngine(auth)
    assert engine.is_risk_class_permitted(RiskClass.R0_PASSIVE)
    assert engine.is_risk_class_permitted(RiskClass.R1_LOW)
    assert not engine.is_risk_class_permitted(RiskClass.R3_HIGH)


def test_create_default_authorization_factory():
    auth = create_default_authorization(
        target="http://localhost:8080",
        scope=["test.local"],
        environment=EnvironmentProfile.LAB,
        operator="TestRunner",
    )
    assert auth.operator_name == "TestRunner"
    assert "localhost" in auth.target_hosts
    assert "test.local" in auth.target_hosts
