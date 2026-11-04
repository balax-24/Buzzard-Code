"""
Tests for the Control Plane: PolicyEngine, Risk Management, Approval Gates, and Environment Guardrails.
"""

import pytest
from security_agent.events.bus import EventBus
from security_agent.events.types import EventType
from security_agent.security.autonomy import AutonomyLevel, EnvironmentProfile
from security_agent.security.risk import RiskClass, get_tool_risk_metadata
from security_agent.security.authorization import AssessmentAuthorization
from security_agent.security.approvals import ApprovalGate
from security_agent.security.policy import PolicyEngine, PolicyDecision
from security_agent.security.kill_switch import KillSwitch


@pytest.fixture(autouse=True)
def reset_ks():
    KillSwitch.reset()
    yield
    KillSwitch.reset()


def test_policy_passive_tool_allowed_in_all_envs():
    bus = EventBus()
    for env in [EnvironmentProfile.LAB, EnvironmentProfile.STAGING, EnvironmentProfile.PRODUCTION]:
        policy = PolicyEngine(
            scope=["localhost", "127.0.0.1"],
            environment=env,
            event_bus=bus,
        )
        decision = policy.evaluate("check_headers", {"url": "http://localhost:8000"})
        assert decision.permitted
        assert decision.risk_class == RiskClass.R0_PASSIVE


def test_policy_production_blocks_high_risk_tools():
    bus = EventBus()
    # In production, scan_ports is disabled by default
    policy = PolicyEngine(
        scope=["localhost", "127.0.0.1"],
        environment=EnvironmentProfile.PRODUCTION,
        event_bus=bus,
    )
    decision = policy.evaluate("scan_ports", {"host": "localhost", "ports": "80,443"})
    assert not decision.permitted
    assert "not permitted in the 'production' environment" in decision.reason


def test_policy_blocks_out_of_scope_target():
    bus = EventBus()
    policy = PolicyEngine(
        scope=["target.local"],
        environment=EnvironmentProfile.LAB,
        event_bus=bus,
    )
    decision = policy.evaluate("browser.open", {"url": "https://unauthorized-domain.com"})
    assert not decision.permitted
    assert "outside the authorized testing scope" in decision.reason


def test_policy_blocks_on_kill_switch():
    bus = EventBus()
    ks = KillSwitch.get_instance(event_bus=bus)
    policy = PolicyEngine(
        scope=["localhost"],
        kill_switch=ks,
        event_bus=bus,
    )
    ks.trigger("Emergency halt triggered by operator")

    decision = policy.evaluate("browser.open", {"url": "http://localhost"})
    assert not decision.permitted
    assert "Kill switch is ACTIVE" in decision.reason


def test_approval_gate_integration():
    bus = EventBus()
    approval_events = []
    bus.subscribe(EventType.APPROVAL_REQUESTED, lambda e: approval_events.append(e))

    # Reject callback
    approval_gate = ApprovalGate(
        autonomy_level=AutonomyLevel.LEVEL_2_SAFE_ACTIVE,
        environment=EnvironmentProfile.LAB,
        event_bus=bus,
        approval_callback=lambda tool, args, meta: False,  # Denied by operator
    )

    policy = PolicyEngine(
        scope=["localhost"],
        environment=EnvironmentProfile.LAB,
        approval_gate=approval_gate,
        event_bus=bus,
    )

    # terminal.execute requires approval
    decision = policy.evaluate("terminal.execute", {"command": "echo test"})
    assert not decision.permitted
    assert "Operator Approval Denied" in decision.reason
    assert len(approval_events) == 1


def test_lab_policy_does_not_auto_approve_high_risk_actions():
    """A lab profile alone must never turn an unattended call into consent."""
    policy = PolicyEngine(
        scope=["localhost"],
        environment=EnvironmentProfile.LAB,
    )

    assert policy.approval_gate.auto_approve_lab is False
    decision = policy.evaluate("terminal.execute", {"command": "echo test"})

    assert not decision.permitted
    assert decision.requires_approval
    assert not decision.approved
    assert "Operator Approval Denied" in decision.reason


def test_tool_call_quota_enforcement():
    policy = PolicyEngine(
        scope=["localhost"],
        environment=EnvironmentProfile.LAB,
    )
    meta = get_tool_risk_metadata("dns_lookup")
    meta.max_calls_per_assessment = 3

    assert policy.evaluate("dns_lookup", {"host": "localhost"}).permitted
    assert policy.evaluate("dns_lookup", {"host": "localhost"}).permitted
    assert policy.evaluate("dns_lookup", {"host": "localhost"}).permitted
    
    # 4th call should be blocked by quota
    decision = policy.evaluate("dns_lookup", {"host": "localhost"})
    assert not decision.permitted
    assert "exceeded maximum allowed invocations" in decision.reason
