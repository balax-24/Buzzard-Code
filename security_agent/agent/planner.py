"""
Assessment Planner for Buzzard Code.

Responsible for:
1. Building compact planner context and message history management
2. Parsing and validating model outputs (native tool calls, XML tags, JSON decisions)
3. Tracking planner latency and enforcing the planner latency cap
4. Handling planner timeouts and generating structured fallback decisions
5. Validating candidate actions against target bounds, scope, and evidence state
6. Selecting deterministic / priority-driven fallback actions without redundant LLM calls
"""

from __future__ import annotations

import re
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    AssessmentContext,
    CandidateActionValidator,
    TargetValidator,
    TargetValidationResult,
    ServiceState,
    HTTPState,
)


@dataclass
class PlannerDecision:
    """
    Structured representation of a candidate decision produced by the planner.
    """
    tool_name: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    expected_information: str = "N/A"
    next_step: str = "N/A"
    decision_type: str = "tool_call"  # "tool_call", "complete", "pause", "error", "unsupported"
    thinking: str = ""
    is_fallback: bool = False
    priority: str = "NORMAL"
    validation_error: Optional[str] = None

    def to_tool_call(self) -> Optional[Dict[str, Any]]:
        """Converts to native tool call dictionary format if tool_name is present."""
        if not self.tool_name or self.decision_type in ("complete", "pause", "error"):
            return None
        return {
            "function": {
                "name": self.tool_name,
                "arguments": self.arguments or {}
            }
        }

    def to_summary_dict(self) -> Dict[str, Any]:
        """Converts to summary dict format matching loop decision summaries."""
        return {
            "decision": self.tool_name or self.decision_type,
            "tool": self.tool_name,
            "type": self.decision_type,
            "reason": self.reason or self.thinking or "Analyzing next step",
            "expected_information": self.expected_information,
            "next_step": self.next_step,
            "arguments": self.arguments,
            "is_fallback": self.is_fallback,
        }


class Planner:
    """
    Dedicated component for assessment planning, context formatting,
    output validation, and deterministic fallback execution.
    """

    def __init__(self, max_planner_time: float = 45.0):
        self.max_planner_time = float(max_planner_time)
        self.latencies: List[float] = []
        from security_agent.agent.context_manager import ContextManager
        self.context_manager = ContextManager()


    def record_latency(self, latency: float) -> None:
        """Records planner execution latency."""
        self.latencies.append(latency)

    def compact_message_history(
        self,
        raw_messages: List[Dict[str, Any]],
        state: Optional[AssessmentState] = None,
        attack_surface: Any = None
    ) -> List[Dict[str, Any]]:
        """
        Prevents runaway token accumulation delegating to ContextManager.
        """
        return self.context_manager.compact_messages(
            raw_messages=raw_messages,
            state=state,
            attack_surface=attack_surface
        )


    def parse_xml_tool_call(self, content: str) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """
        Parses XML tool call tags and thinking blocks from raw model output.
        Returns (tool_name, arguments, thinking).
        """
        if not content:
            return None, None, None

        # Extract thinking block
        thinking_match = re.search(r"<thinking>(.*?)</thinking>", content, re.DOTALL)
        thinking = thinking_match.group(1).strip() if thinking_match else ""

        # Check for JSON object inside <tool_call> e.g. <tool_call>{"name": "...", "arguments": {...}}</tool_call>
        json_tool_match = re.search(r"<tool_call>\s*({.*?})\s*(?:</tool_call>|</tool>|$)", content, re.DOTALL)
        if json_tool_match:
            try:
                data = json.loads(json_tool_match.group(1).strip())
                if isinstance(data, dict) and "name" in data:
                    t_name = data["name"]
                    t_args = data.get("arguments") or {}
                    return t_name, t_args, thinking
            except Exception:
                pass

        # Find tool_call tag with name attribute
        tool_call_match = re.search(
            r"<tool_call\s+name=[\"']([^\"']+)[\"']\s*>(.*?)(?:</tool_call>|</tool>|$)",
            content,
            re.DOTALL
        )
        if not tool_call_match:
            # Check self-closing tag e.g. <tool_call name="..." />
            tool_call_match = re.search(r"<tool_call\s+name=[\"']([^\"']+)[\"']\s*/>", content, re.DOTALL)
            if tool_call_match:
                tool_name = tool_call_match.group(1).strip()
                return tool_name, {}, thinking
            return None, None, thinking

        tool_name = tool_call_match.group(1).strip()
        inner_content = tool_call_match.group(2).strip()

        # Strip optional <arguments>...</arguments> wrapper
        arg_wrapper_match = re.match(r"^\s*<arguments>(.*)</arguments>\s*$", inner_content, re.DOTALL)
        if arg_wrapper_match:
            inner_content = arg_wrapper_match.group(1).strip()

        # Extract child tag parameters
        arguments: Dict[str, Any] = {}
        param_matches = list(re.finditer(r"<(\w+)>(.*?)(?:</\1>|$)", inner_content, re.DOTALL))
        for match in param_matches:
            key = match.group(1).strip()
            val = match.group(2).strip()
            try:
                parsed_val = json.loads(val)
                if isinstance(parsed_val, (dict, list, int, float, bool)):
                    arguments[key] = parsed_val
                else:
                    arguments[key] = val
            except Exception:
                arguments[key] = val

        # Fallback: single raw string inner content mapped to primary tool parameter
        if not arguments and inner_content and not inner_content.startswith("<"):
            raw_text = inner_content.strip()
            if tool_name in ("browser.open", "browser.goto"):
                arguments["url"] = raw_text
            elif tool_name in ("browser.get_text", "browser.click", "browser.get_links"):
                arguments["selector"] = raw_text
            elif tool_name in ("terminal.execute",):
                arguments["command"] = raw_text
            elif tool_name in ("ping_host", "scan_ports"):
                arguments["host"] = raw_text
            elif tool_name in ("complete", "finish_task"):
                arguments["summary"] = raw_text

        return tool_name, arguments, thinking

    def parse_json_decision(self, response_text: str) -> Dict[str, Any]:
        """
        Parses JSON-formatted decision dictionary from model response.
        """
        text = response_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except Exception:
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                    if isinstance(data, dict):
                        return data
                except Exception:
                    pass

        return {
            "type": "error",
            "summary": "Failed to parse model response",
            "reason": "Model output was not valid JSON",
            "tool": None,
            "arguments": {},
            "expected_observation": "Valid JSON response"
        }

    def resolve_decision(
        self,
        content: str,
        raw_tool_calls: Optional[List[Dict[str, Any]]] = None,
        thinking_text: str = "",
        available_tools: Optional[Set[str]] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Extracts structured tool calls and decision summary from model output.
        Handles:
        1. Native function calling
        2. XML <tool_call> syntax
        3. Raw JSON structured decisions
        """
        tool_calls: List[Dict[str, Any]] = []
        decision_summary: Dict[str, Any] = {}

        # 1. Native tool calls
        if raw_tool_calls:
            for tc in raw_tool_calls:
                func = tc.get("function", {})
                t_name = func.get("name")
                t_args = func.get("arguments") or {}
                if isinstance(t_args, str):
                    try:
                        t_args = json.loads(t_args)
                    except Exception:
                        t_args = {}
                tool_calls.append({
                    "id": tc.get("id"),
                    "function": {
                        "name": t_name,
                        "arguments": t_args
                    }
                })
            if tool_calls:
                decision_summary = {
                    "decision": tool_calls[0]["function"]["name"],
                    "reason": thinking_text or content or "Executing native tool call",
                    "expected_information": "N/A",
                    "next_step": "N/A",
                    "arguments": tool_calls[0]["function"]["arguments"]
                }
                return tool_calls, decision_summary

        # 2. XML tag parsing
        if content:
            xml_tool, xml_args, xml_thinking = self.parse_xml_tool_call(content)
            if xml_tool:
                tool_calls.append({
                    "function": {
                        "name": xml_tool,
                        "arguments": xml_args or {}
                    }
                })
                decision_summary = {
                    "decision": xml_tool,
                    "reason": xml_thinking or thinking_text or "Executing XML tool call",
                    "expected_information": "N/A",
                    "next_step": "N/A",
                    "arguments": xml_args or {}
                }
                return tool_calls, decision_summary

        # 3. JSON decision fallback
        if content and ("{" in content and "}" in content):
            json_data = self.parse_json_decision(content)
            if json_data and json_data.get("type") != "error":
                d_type = json_data.get("type") or "tool_call"
                t_name = json_data.get("tool") or json_data.get("decision")
                t_args = json_data.get("arguments") or {}

                if t_name in ("complete", "finish_task") or d_type in ("complete", "finish", "done"):
                    tool_calls = []
                elif t_name:
                    tool_calls.append({
                        "function": {
                            "name": t_name,
                            "arguments": t_args
                        }
                    })

                decision_summary = {
                    "decision": t_name or d_type,
                    "tool": t_name,
                    "type": d_type,
                    "reason": json_data.get("reason") or json_data.get("summary") or thinking_text or "Executing JSON decision",
                    "expected_information": json_data.get("expected_observation") or "N/A",
                    "next_step": json_data.get("next_step") or "N/A",
                    "arguments": t_args
                }
                return tool_calls, decision_summary

        # Default fallback summary if model produced free text
        decision_summary = {
            "decision": "complete" if not tool_calls else tool_calls[0]["function"]["name"],
            "reason": thinking_text or content or "Analyzing next step",
            "expected_information": "N/A",
            "next_step": "N/A"
        }
        return tool_calls, decision_summary

    def handle_timeout(
        self,
        state: Optional[AssessmentState] = None,
        attack_surface: Any = None,
        target: str = "127.0.0.1",
        native_tools: bool = True
    ) -> Tuple[Dict[str, Any], PlannerDecision]:
        """
        Handles planner latency cap expiration by generating an authoritative fast-path decision.
        Returns (synthetic_model_response, planner_decision).
        """
        # Determine best pending action
        pending_recs = []
        if state is not None:
            det_action = state.get_deterministic_next_action()
            if det_action:
                pending_recs.append(det_action)

        if not pending_recs and attack_surface is not None and hasattr(attack_surface, "get_prioritized_pending_targets"):
            surface_recs = attack_surface.get_prioritized_pending_targets()
            for r in surface_recs:
                pending_recs.append({
                    "tool": r.recommended_tool,
                    "args": r.recommended_args,
                    "reason": r.rationale,
                    "target": r.target
                })

        if pending_recs:
            top_rec = pending_recs[0]
            tool_name = top_rec.get("tool") or top_rec.get("recommended_tool")
            tool_args = top_rec.get("args") or top_rec.get("recommended_args") or {}
            rationale = top_rec.get("reason") or top_rec.get("rationale") or f"Executing prioritized action on {target}"
        else:
            clean_host = target.split("://")[-1].split("/")[0].split(":")[0] or "127.0.0.1"
            tool_name = "nmap_scan"
            tool_args = {"host": clean_host, "ports": "1-10000"}
            rationale = f"Planner latency limit reached. Executing fast port discovery on {clean_host}."

        synthetic_content = f"<thinking>{rationale}</thinking>\n<tool_call name=\"{tool_name}\">\n"
        for k, v in tool_args.items():
            synthetic_content += f"  <{k}>{v}</{k}>\n"
        synthetic_content += "</tool_call>"

        decision = PlannerDecision(
            tool_name=tool_name,
            arguments=tool_args,
            reason=rationale,
            thinking=rationale,
            is_fallback=True,
            decision_type="tool_call"
        )

        response_payload = {
            "message": {
                "role": "assistant",
                "content": synthetic_content,
                "tool_calls": [
                    {
                        "function": {
                            "name": tool_name,
                            "arguments": tool_args
                        }
                    }
                ] if native_tools else []
            },
            "done": True,
            "metrics": {"prompt_eval_count": 0, "eval_count": 0}
        }

        return response_payload, decision

    def check_target_prompt_interception(
        self,
        content: str,
        state: Optional[AssessmentState] = None,
        attack_surface: Any = None,
        target: str = "127.0.0.1",
        task_goal: str = "",
        iteration: int = 1
    ) -> Optional[PlannerDecision]:
        """
        Intercepts model attempts to ask the user for target or objective when already canonical.
        Returns an auto-dispatched PlannerDecision if intercepted, or None.
        """
        clean_low = (content or "").lower()
        phrases = (
            "what is the target", "what is your objective", "please specify the target",
            "target host/ip", "what is the host", "what is the ip", "provide the target"
        )
        if not any(phrase in clean_low for phrase in phrases):
            return None

        # Check for pending recommended actions
        pending_recs = []
        if state is not None:
            det_action = state.get_deterministic_next_action()
            if det_action:
                pending_recs.append(det_action)

        if not pending_recs and attack_surface is not None and hasattr(attack_surface, "get_prioritized_pending_targets"):
            surface_recs = attack_surface.get_prioritized_pending_targets()
            for r in surface_recs:
                pending_recs.append({
                    "tool": r.recommended_tool,
                    "args": r.recommended_args,
                    "reason": r.rationale
                })

        if pending_recs:
            top_rec = pending_recs[0]
            tool_name = top_rec.get("tool") or top_rec.get("recommended_tool")
            tool_args = top_rec.get("args") or top_rec.get("recommended_args") or {}
            reason = f"Target is locked to {target}. Executing priority recommendation: {top_rec.get('reason', '')}"
            return PlannerDecision(
                tool_name=tool_name,
                arguments=tool_args,
                reason=reason,
                is_fallback=True
            )
        elif (state is None or not state.services) and iteration <= 2:
            target_h = target.split("://")[-1].split("/")[0].split(":")[0] or "127.0.0.1"
            return PlannerDecision(
                tool_name="nmap_scan",
                arguments={"host": target_h, "ports": "1-10000"},
                reason=f"Target is locked to {target}. Launching fast initial port discovery.",
                is_fallback=True
            )

        return None

    def validate_candidate_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        state: AssessmentState
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates candidate tool and arguments against target authorization,
        required schemas, and evidence state.
        Returns (is_valid, validation_message, normalized_arguments).
        """
        return CandidateActionValidator.validate_candidate(
            tool_name=tool_name,
            args=arguments,
            state=state
        )
