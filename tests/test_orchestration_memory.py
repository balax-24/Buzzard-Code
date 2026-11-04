"""
Tests for Assessment Memory and Multi-Agent Orchestrator.
"""

from security_agent.agent.memory import AssessmentMemory
from security_agent.agent.orchestrator import MultiAgentOrchestrator, WorkerRole
from security_agent.tools.registry import ToolRegistry
from security_agent.tools.basic import register_basic_tools
from security_agent.tools.security import register_security_tools
from security_agent.security.policy import PolicyEngine
from security_agent.events.bus import EventBus
from security_agent.events.types import EventType


def test_assessment_memory_store_and_recall(tmp_path):
    db_path = str(tmp_path / "test_memory.db")
    memory = AssessmentMemory(db_path=db_path)

    memory.store("target.local", "tech_stack", {"server": "nginx", "framework": "fastapi"})
    memory.store("target.local", "open_ports", [80, 443, 8080])

    val = memory.recall("target.local", "tech_stack")
    assert val["framework"] == "fastapi"

    all_k = memory.get_all_target_knowledge("target.local")
    assert "open_ports" in all_k
    assert 443 in all_k["open_ports"]


def test_multi_agent_orchestrator_dispatch():
    registry = ToolRegistry()
    register_basic_tools(registry)
    register_security_tools(registry)

    bus = EventBus()
    events = []
    bus.subscribe(EventType.WORKER_STARTED, lambda e: events.append(e))

    policy = PolicyEngine(scope=["localhost", "127.0.0.1"])
    orchestrator = MultiAgentOrchestrator(registry=registry, policy_engine=policy, event_bus=bus)

    task = orchestrator.dispatch_task(
        role=WorkerRole.RECON,
        objective="Analyze response headers on target",
        target="http://localhost:8000"
    )

    assert task.completed is True
    assert task.result is not None
    assert len(events) == 1
    assert events[0].payload["role"] == "recon_worker"
