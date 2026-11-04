"""
Canonical Model Decision Contract for Buzzard Code.

Defines a strict, typed, schema-validated, versioned data contract for all
model decisions across Qwythos, external providers, and future Buzzard-Sec models.

Invariants:
- All decisions pass through this validated contract.
- Free-form model output CANNOT directly mutate AssessmentState.
- Hidden chain-of-thought is excluded; only concise operational reasoning summaries are preserved.
- Graceful recovery from malformed output produces a traceable fallback decision.
"""

from __future__ import annotations

import ast
import json
import re
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class DecisionType(str, Enum):
    TOOL_CALL = "TOOL_CALL"
    VERIFICATION = "VERIFICATION"
    PIVOT = "PIVOT"
    RECOVERY = "RECOVERY"
    COMPLETE = "COMPLETE"
    PAUSE = "PAUSE"
    FALLBACK = "FALLBACK"


class DecisionSource(str, Enum):
    MODEL = "MODEL"
    CONTROLLER = "CONTROLLER"
    FALLBACK = "FALLBACK"
    EXPERT = "EXPERT"


class ActionIntent(BaseModel):
    tool_name: str = Field(description="Name of the registered security tool to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Structured arguments for tool execution")
    target_asset: Optional[str] = Field(None, description="Target host, IP, or URL string")
    risk_level: str = Field(default="SAFE", description="SAFE, MODERATE, AGGRESSIVE")

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("tool_name cannot be empty")
        return cleaned


class HypothesisIntent(BaseModel):
    statement: str = Field(default="", description="Hypothesis assertion (e.g. 'Target endpoint vulnerable to unauthenticated bypass')")
    vulnerability_type: Optional[str] = Field(default=None, description="Vulnerability class (e.g. SQLI, XSS, EXPOSED_SERVICE)")
    target: Optional[str] = Field(default=None, description="Target host or URI")
    port: Optional[int] = Field(default=None, description="Target port")
    rationale: Optional[str] = Field(default=None, description="Underlying reasoning")
    test_approach: str = Field(default="", description="Planned test to confirm or refute")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence rating between 0.0 and 1.0")
    status: str = Field(default="ACTIVE", description="ACTIVE, VERIFIED, REFUTED, ABANDONED")


class RecoveryIntent(BaseModel):
    is_recovery: bool = Field(default=False, description="Whether this decision addresses a prior failure")
    failed_action_diagnosed: str = Field(default="", description="Summary of the failed previous action")
    failure_category: str = Field(default="", description="Categorization of the failure mode")
    pivot_strategy: str = Field(default="", description="Strategic change to recover")


class VerificationIntent(BaseModel):
    claim_title: str = Field(description="Title of finding to verify")
    proof_marker: str = Field(default="", description="Expected or observed proof token/flag")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of ground-truth evidence records")
    severity: str = Field(default="MEDIUM", description="INFO, LOW, MEDIUM, HIGH, CRITICAL")


class CompletionAssessment(BaseModel):
    is_complete: bool = Field(default=False, description="Whether the overall task is deemed complete")
    status: str = Field(default="IN_PROGRESS", description="IN_PROGRESS, OBJECTIVE_ACHIEVED, OBJECTIVE_FAILED")
    rationale: str = Field(default="", description="Evidence-backed rationale for completion state")


class ModelDecision(BaseModel):
    """
    Canonical, versioned model decision contract.
    """
    contract_version: str = Field(default="1.0.0", description="Contract schema version")
    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:8]}", description="Unique decision ID")
    timestamp: float = Field(default_factory=time.time, description="Creation timestamp")
    model_name: str = Field(default="qwythos:latest", description="Model producing the decision")
    decision_type: DecisionType = Field(default=DecisionType.TOOL_CALL, description="Type of decision")
    decision_source: DecisionSource = Field(default=DecisionSource.MODEL, description="Decision authority")

    # Operational reasoning (concise, non-CoT)
    objective_interpretation: str = Field(default="", description="Model's interpretation of current objective")
    reasoning_summary: str = Field(default="", description="Concise operational justification under 3 sentences")
    why_this_action: str = Field(default="", description="Specific justification for selecting this action over alternatives")
    expected_information_gain: float = Field(default=1.0, ge=0.0, le=10.0, description="Predicted information gain")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Model decision confidence")

    # Action intent
    selected_action: Optional[ActionIntent] = Field(None, description="Tool action intent if tool_call")

    # Cognitive state tracking
    hypothesis: Optional[HypothesisIntent] = Field(None, description="Active or newly formulated hypothesis")
    observed_evidence_interpretation: Optional[str] = Field(None, description="Model interpretation of last observation")
    next_step_intent: str = Field(default="", description="Planned subsequent step")

    # Specialized reasoning channels
    recovery_decision: Optional[RecoveryIntent] = Field(None, description="Failure recovery details if applicable")
    verification_intent: Optional[VerificationIntent] = Field(None, description="Verification intent if applicable")
    completion_assessment: Optional[CompletionAssessment] = Field(None, description="Task completion assessment if applicable")

    # Fault tolerance & provenance
    is_malformed_recovery: bool = Field(default=False, description="Flagged true if parsed via heuristic error recovery")
    raw_response_snippet: Optional[str] = Field(None, description="Truncated snippet of raw model output for audit")

    @property
    def action(self) -> Optional[ActionIntent]:
        return self.selected_action

    def to_tool_call(self) -> Optional[Dict[str, Any]]:
        """
        Converts the selected action to standard OpenAI tool call format.
        """
        if not self.selected_action or self.decision_type in (DecisionType.COMPLETE, DecisionType.PAUSE):
            return None
        return {
            "function": {
                "name": self.selected_action.tool_name,
                "arguments": self.selected_action.arguments or {},
            }
        }

    def to_summary_dict(self) -> Dict[str, Any]:
        """
        Emits summary dictionary for dashboard, events, and telemetry.
        """
        return {
            "decision_id": self.decision_id,
            "decision": self.selected_action.tool_name if self.selected_action else self.decision_type.value,
            "tool": self.selected_action.tool_name if self.selected_action else None,
            "arguments": self.selected_action.arguments if self.selected_action else {},
            "type": self.decision_type.value,
            "reason": self.reasoning_summary or self.why_this_action or "Selecting next assessment action",
            "expected_information": f"Exp Gain {self.expected_information_gain:.1f}",
            "next_step": self.next_step_intent or "Continue exploration",
            "decision_source": self.decision_source.value,
            "is_malformed_recovery": self.is_malformed_recovery,
        }


class ModelDecisionParser:
    """
    Robust, fault-tolerant parser that converts raw model outputs, native tool calls,
    or structured JSON into the canonical ModelDecision contract.
    """

    @classmethod
    def parse(
        cls,
        raw_content: str = "",
        native_tool_calls: Optional[List[Dict[str, Any]]] = None,
        model_name: str = "qwythos:latest",
        fallback_tool: Optional[str] = None,
        fallback_target: str = "127.0.0.1",
        content: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        reasoning: Optional[str] = None,
    ) -> ModelDecision:
        """
        Parses raw model response into a validated ModelDecision.
        Never throws; returns a traceable fallback ModelDecision on unparseable output.
        """
        if content is not None and not raw_content:
            raw_content = content
        if tool_calls is not None and native_tool_calls is None:
            native_tool_calls = tool_calls
        raw_content = raw_content or ""

        # Case 0: Direct canonical ModelDecision JSON parsing
        if raw_content and "{" in raw_content and not native_tool_calls:
            try:
                clean_json = raw_content.strip()
                if clean_json.startswith("```"):
                    j_lines = clean_json.split("\n")
                    clean_json = "\n".join(j_lines[1:-1] if j_lines[-1].startswith("```") else j_lines[1:])
                if "decision_type" in clean_json:
                    dec = ModelDecision.model_validate_json(clean_json)
                    if not dec.model_name and model_name:
                        dec.model_name = model_name
                    if not dec.raw_response_snippet:
                        dec.raw_response_snippet = raw_content[:200]
                    return dec
            except Exception:
                pass

        # Case 1: Native tool calls present (standard OpenAI / Ollama tool format)
        if native_tool_calls and isinstance(native_tool_calls, list) and len(native_tool_calls) > 0 and isinstance(native_tool_calls[0], dict):
            primary_call = native_tool_calls[0]
            func = primary_call.get("function", {})
            t_name = func.get("name", "lab_probe")
            t_args = func.get("arguments", {})
            if isinstance(t_args, str):
                try:
                    t_args = json.loads(t_args)
                except Exception:
                    t_args = {}

            # Parse optional structured summary from content
            extracted_json = cls._extract_json(raw_content)
            reason = ""
            why = ""
            next_step = ""
            hypo = None

            if extracted_json:
                reason = extracted_json.get("reason", extracted_json.get("thought", ""))
                why = extracted_json.get("why_this_action", "")
                next_step = extracted_json.get("next_step", "")
                if "hypothesis" in extracted_json:
                    h_val = extracted_json["hypothesis"]
                    if isinstance(h_val, str):
                        hypo = HypothesisIntent(statement=h_val)
                    elif isinstance(h_val, dict):
                        hypo = HypothesisIntent(**h_val)

            if not reason:
                reason = raw_content.strip()[:200] if raw_content else f"Executing {t_name} on target"

            return ModelDecision(
                model_name=model_name,
                decision_type=DecisionType.TOOL_CALL,
                decision_source=DecisionSource.MODEL,
                reasoning_summary=reason[:300],
                why_this_action=why[:200] if why else f"Targeting service surface via {t_name}",
                selected_action=ActionIntent(
                    tool_name=t_name,
                    arguments=t_args,
                    target_asset=t_args.get("target") or t_args.get("url") or fallback_target,
                ),
                hypothesis=hypo,
                next_step_intent=next_step or "Evaluate tool observation",
                raw_response_snippet=raw_content[:200] if raw_content else None,
            )

        # Case 2: JSON payload embedded in content
        extracted = cls._extract_json(raw_content)
        if extracted:
            # Check if extracted is already a full or partial ModelDecision schema
            if "decision_type" in extracted:
                try:
                    dec = ModelDecision.model_validate(extracted)
                    if not dec.model_name and model_name:
                        dec.model_name = model_name
                    if not dec.raw_response_snippet:
                        dec.raw_response_snippet = raw_content[:200]
                    return dec
                except Exception:
                    pass

            d_type = str(extracted.get("decision_type") or extracted.get("type") or "").upper()

            # Check for pause / clarification request
            if d_type in ("PAUSE", "CLARIFY", "CLARIFICATION"):
                why = extracted.get("why_this_action") or extracted.get("reason") or extracted.get("thought") or "Operator clarification required"
                return ModelDecision(
                    model_name=model_name,
                    decision_type=DecisionType.PAUSE,
                    decision_source=DecisionSource.MODEL,
                    reasoning_summary=str(extracted.get("reason", extracted.get("thought", why)))[:300],
                    why_this_action=str(why)[:200],
                    raw_response_snippet=raw_content[:200],
                )

            # Check for recovery
            if d_type in ("RECOVERY", "RECOVER"):
                action_data = extracted.get("selected_action") or {}
                t_name = action_data.get("tool_name") or extracted.get("tool") or fallback_tool or "http.request"
                t_args = action_data.get("arguments") or extracted.get("arguments") or {}
                return ModelDecision(
                    model_name=model_name,
                    decision_type=DecisionType.RECOVERY,
                    decision_source=DecisionSource.MODEL,
                    reasoning_summary=str(extracted.get("reason", extracted.get("thought", "Recovery action")))[:300],
                    why_this_action=str(extracted.get("why_this_action", "Executing recovery"))[:200],
                    selected_action=ActionIntent(
                        tool_name=t_name,
                        arguments=t_args,
                        target_asset=t_args.get("target") or t_args.get("url") or fallback_target,
                    ),
                    raw_response_snippet=raw_content[:200],
                )

            # Check for completion / refusal
            if d_type in ("COMPLETE", "REFUSAL") or extracted.get("type") in ("complete", "refusal"):
                comp_data = extracted.get("completion_assessment")
                if isinstance(comp_data, dict):
                    status = comp_data.get("status", extracted.get("status", "OBJECTIVE_ACHIEVED"))
                    rationale = comp_data.get("rationale", extracted.get("rationale", extracted.get("summary", "Assessment complete")))
                    is_complete = comp_data.get("is_complete", True)
                else:
                    status = extracted.get("status", "OBJECTIVE_ACHIEVED")
                    rationale = extracted.get("rationale", extracted.get("summary", extracted.get("reason", "Assessment complete")))
                    is_complete = True

                return ModelDecision(
                    model_name=model_name,
                    decision_type=DecisionType.COMPLETE,
                    decision_source=DecisionSource.MODEL,
                    reasoning_summary=str(extracted.get("reason", extracted.get("thought", rationale)))[:300],
                    completion_assessment=CompletionAssessment(
                        is_complete=is_complete,
                        status=status,
                        rationale=str(rationale),
                    ),
                    raw_response_snippet=raw_content[:200],
                )

            # Check for tool call in JSON
            tool_name = extracted.get("tool") or extracted.get("tool_name") or extracted.get("decision")
            if not tool_name and isinstance(extracted.get("selected_action"), dict):
                tool_name = extracted["selected_action"].get("tool_name")
            if tool_name and isinstance(tool_name, str):
                tool_args = extracted.get("arguments") or extracted.get("tool_arguments") or extracted.get("parameters") or {}
                if not tool_args and isinstance(extracted.get("selected_action"), dict):
                    tool_args = extracted["selected_action"].get("arguments", {})
                if not isinstance(tool_args, dict):
                    tool_args = {}

                return ModelDecision(
                    model_name=model_name,
                    decision_type=DecisionType.TOOL_CALL,
                    decision_source=DecisionSource.MODEL,
                    reasoning_summary=str(extracted.get("thought", extracted.get("reason", "")))[:300],
                    why_this_action=str(extracted.get("why_this_action", ""))[:200],
                    selected_action=ActionIntent(
                        tool_name=tool_name,
                        arguments=tool_args,
                        target_asset=tool_args.get("target") or tool_args.get("url") or fallback_target,
                    ),
                    next_step_intent=str(extracted.get("next_step", "Evaluate tool observation")),
                    raw_response_snippet=raw_content[:200],
                )

        # Case 3: XML tags fallback (<tool_call><name>...</name>...</tool_call>)
        xml_tool, xml_args = cls._extract_xml_tool(raw_content)
        if xml_tool:
            return ModelDecision(
                model_name=model_name,
                decision_type=DecisionType.TOOL_CALL,
                decision_source=DecisionSource.MODEL,
                reasoning_summary="Tool invocation extracted from XML markers",
                selected_action=ActionIntent(
                    tool_name=xml_tool,
                    arguments=xml_args,
                    target_asset=xml_args.get("target") or xml_args.get("url") or fallback_target,
                ),
                raw_response_snippet=raw_content[:200],
            )

        # Case 4: Heuristic fallback (plain text with no identifiable tool call)
        chosen_tool = fallback_tool or "http.request"
        return ModelDecision(
            model_name=model_name,
            decision_type=DecisionType.FALLBACK,
            decision_source=DecisionSource.FALLBACK,
            is_malformed_recovery=True,
            reasoning_summary=f"Malformed model response; fast-pathing to safe exploration with {chosen_tool}",
            selected_action=ActionIntent(
                tool_name=chosen_tool,
                arguments={"target": fallback_target, "url": f"http://{fallback_target}"},
                target_asset=fallback_target,
            ),
            raw_response_snippet=raw_content[:200] if raw_content else "Empty response",
        )

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict[str, Any]]:
        if not text or not text.strip():
            return None
        raw = text.strip()
        # Markdown fences
        if "```" in raw:
            for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL):
                try:
                    data = json.loads(match.group(1))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    pass
        # Balanced bracket scanner
        start_idx = raw.find('{')
        while start_idx != -1:
            depth = 0
            in_string = False
            escape = False
            for i in range(start_idx, len(raw)):
                ch = raw[i]
                if escape:
                    escape = False
                    continue
                if ch == '\\':
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            candidate = raw[start_idx:i+1]
                            try:
                                data = json.loads(candidate)
                                if isinstance(data, dict):
                                    return data
                            except Exception:
                                try:
                                    data = ast.literal_eval(candidate)
                                    if isinstance(data, dict):
                                        return data
                                except Exception:
                                    pass
                            break
            start_idx = raw.find('{', start_idx + 1)
        return None

    @staticmethod
    def _extract_xml_tool(text: str) -> Tuple[Optional[str], Dict[str, Any]]:
        if not text:
            return None, {}
        m = re.search(r"<tool_call>\s*<(?:name|tool_name)>([^<]+)</(?:name|tool_name)>(?:\s*<arguments>(.*?)</arguments>)?\s*</tool_call>", text, re.DOTALL)
        if m:
            t_name = m.group(1).strip()
            args_raw = m.group(2)
            t_args = {}
            if args_raw:
                try:
                    t_args = json.loads(args_raw)
                except Exception:
                    pass
            return t_name, t_args
        return None, {}
