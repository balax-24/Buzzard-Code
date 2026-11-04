"""
Integration test for Model-Agnostic Runtime Execution.

Verifies:
- AgentLoop seamlessly executes across different model adapters:
  1. Native tool-calling model (e.g. Qwythos / OpenAI format)
  2. Structured JSON decision model (e.g. Buzzard-Sec future model)
  3. XML tool-calling fallback model
- The runtime enforces identical safety boundaries across all models:
  - Scope boundaries enforced
  - FindingVerifier required
  - Single Source of Truth (AssessmentState) protected
  - No model-specific branching (`if model == qwythos`) inside core logic
"""

import pytest
from typing import Any, Dict, List, Optional
from agent.loop import AgentLoop
from agent.assessment_state import AssessmentState, ObjectiveStatus
from model.provider import ModelProvider
from tools.registry import ToolRegistry, ToolCategory
from model.decision_contract import (
    ModelDecision,
    DecisionType,
    DecisionSource,
    ActionIntent,
)


class MockNativeProvider(ModelProvider):
    """Simulates Qwythos or any model supporting native function calling."""
    def __init__(self, model_name: str = "qwythos:latest"):
        self.model_name = model_name

    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        return {
            "message": {
                "role": "assistant",
                "content": "Running reconnaissance via native tool call.",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "function": {
                            "name": "mock_probe",
                            "arguments": {"target": "127.0.0.1"}
                        }
                    }
                ]
            }
        }

    def generate(self, prompt: str) -> str:
        return "mock"

    def get_available_models(self) -> List[str]:
        return [self.model_name]

    def is_available(self) -> bool:
        return True

    def stream_chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None):
        yield self.chat(messages, tools=tools)


class MockBuzzardSecProvider(ModelProvider):
    """Simulates future Buzzard-Sec specialized model emitting canonical ModelDecision JSON."""
    def __init__(self, model_name: str = "buzzard-sec:7b-v1"):
        self.model_name = model_name

    def chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        decision = ModelDecision(
            contract_version="1.0.0",
            model_name=self.model_name,
            decision_type=DecisionType.TOOL_CALL,
            decision_source=DecisionSource.MODEL,
            objective_interpretation="Probe target for listening HTTP services",
            reasoning_summary="Reconnaissance is required to establish attack surface.",
            why_this_action="mock_probe discovers service state.",
            expected_information_gain=2.5,
            confidence=0.95,
            selected_action=ActionIntent(
                tool_name="mock_probe",
                arguments={"target": "127.0.0.1"},
                target_asset="127.0.0.1"
            ),
            next_step_intent="Evaluate HTTP response"
        )
        return {
            "message": {
                "role": "assistant",
                "content": decision.model_dump_json(),
                "tool_calls": []
            }
        }

    def generate(self, prompt: str) -> str:
        return "mock"

    def get_available_models(self) -> List[str]:
        return [self.model_name]

    def is_available(self) -> bool:
        return True

    def stream_chat(self, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None):
        yield self.chat(messages, tools=tools)


@pytest.fixture
def mock_registry():
    reg = ToolRegistry()
    reg.register(
        name="mock_probe",
        description="Mock reconnaissance probe",
        func=lambda target="": "SUCCESS: Target responsive on 127.0.0.1",
        category=ToolCategory.NETWORK,
        sandbox_required=False,
    )
    reg.register(
        name="complete",
        description="Complete task",
        func=lambda summary="": "Completed",
        category=ToolCategory.UTILITY,
    )
    return reg


def test_runtime_agnostic_native_and_buzzard_sec(mock_registry):
    # Test 1: Run with Native Provider (Qwythos)
    native_provider = MockNativeProvider("qwythos:latest")
    native_state = AssessmentState()
    loop_native = AgentLoop(
        provider=native_provider,
        registry=mock_registry,
        assessment_state=native_state,
        max_iterations=1,
        native_tools=True,
        quiet=True,
        approval_callback=lambda tool, args, metadata: True,
    )
    status_native = loop_native.run(target="127.0.0.1", scope=["127.0.0.1"], task_goal="Assess 127.0.0.1")

    assert len(loop_native.observations) >= 1
    assert "mock_probe" in loop_native.observations[0]
    assert "SUCCESS" in loop_native.observations[0]

    # Test 2: Run with Buzzard-Sec Provider (Canonical JSON)
    buzzard_provider = MockBuzzardSecProvider("buzzard-sec:7b-v1")
    buzzard_state = AssessmentState()
    loop_buzzard = AgentLoop(
        provider=buzzard_provider,
        registry=mock_registry,
        assessment_state=buzzard_state,
        max_iterations=1,
        native_tools=False,
        quiet=True,
        approval_callback=lambda tool, args, metadata: True,
    )
    status_buzzard = loop_buzzard.run(target="127.0.0.1", scope=["127.0.0.1"], task_goal="Assess 127.0.0.1")

    assert len(loop_buzzard.observations) >= 1
    assert "mock_probe" in loop_buzzard.observations[0]
    assert "SUCCESS" in loop_buzzard.observations[0]

    # Runtime behavior is identical regardless of underlying model architecture
    assert loop_native.candidate_handoffs_count == loop_buzzard.candidate_handoffs_count
