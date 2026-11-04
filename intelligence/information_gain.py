"""
Phase 14 Information Gain Engine & Semantic Duplicate Action Detector.

Formalizes:
1. Information gain per action (evidence, nodes, edges, capabilities, findings, reachable surface).
2. Semantic action normalization (e.g. GET /admin vs http.request(method='GET', url='/admin')).
3. Gain decay for repeated/stagnant strategies.
4. Action efficiency calculation (actual_gain / cost).
5. Comprehensive telemetry for CompletionEngine decision-making.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from enum import Enum


@dataclass
class ActionRecord:
    action_id: str
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    canonical_action_key: str
    expected_gain: float = 1.0
    actual_gain: float = 0.0
    action_cost: float = 1.0
    action_efficiency: float = 0.0
    is_duplicate: bool = False
    turn_number: int = 0
    branch_id: str = "default"
    model_name: str = "default"
    timestamp: float = 0.0


@dataclass
class InformationGainMetrics:
    total_information_gain: float = 0.0
    total_actions_evaluated: int = 0
    average_gain_per_action: float = 0.0
    recent_gain_per_action: float = 0.0  # Rolling window (last 10 actions)
    duplicate_action_count: int = 0
    duplicate_action_rate: float = 0.0
    recovered_duplicate_rate: float = 0.0
    gain_by_branch: Dict[str, float] = field(default_factory=dict)
    gain_by_tool: Dict[str, float] = field(default_factory=dict)
    gain_by_model: Dict[str, float] = field(default_factory=dict)


class InformationGainEngine:
    """
    Tracks and quantifies the empirical information gain and action efficiency of agent actions.
    """

    def __init__(self, rolling_window_size: int = 10):
        self.action_history: List[ActionRecord] = []
        self.seen_action_keys: Dict[str, int] = {}  # key -> execution count
        self.rolling_window_size = rolling_window_size
        self.metrics = InformationGainMetrics()

    @classmethod
    def normalize_action(cls, tool_name: str, parameters: Dict[str, Any]) -> str:
        """
        Produces a canonical semantic action key across different syntax variations.
        For example:
          - curl -X GET http://127.0.0.1:8080/admin
          - http_request(method='GET', url='http://127.0.0.1:8080/admin')
          - web_probe(url='/admin')
        All map to canonical form: HTTP:GET:http://127.0.0.1:8080/admin
        """
        tool_norm = tool_name.strip().lower()

        # Handle HTTP / Web tools
        if tool_norm in ("http_request", "http_client", "http", "curl", "web_probe", "browser_navigate", "url_fetch"):
            url = str(parameters.get("url") or parameters.get("target") or parameters.get("endpoint") or "").strip()
            method = str(parameters.get("method") or "GET").strip().upper()

            # Normalize command strings in bash/curl
            cmd = str(parameters.get("command") or parameters.get("cmd") or "").strip()
            if cmd and ("curl" in cmd or "http" in cmd):
                m_match = re.search(r"-X\s+([A-Z]+)", cmd)
                if m_match:
                    method = m_match.group(1).upper()
                u_match = re.search(r"https?://[^\s\"']+", cmd)
                if u_match:
                    url = u_match.group(0)

            # Strip trailing slash and query params sorting for consistency
            if url:
                parsed = urllib.parse.urlparse(url)
                path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
                norm_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                if parsed.query:
                    q_params = urllib.parse.parse_qsl(parsed.query)
                    sorted_q = urllib.parse.urlencode(sorted(q_params))
                    norm_url += f"?{sorted_q}"
                return f"HTTP:{method}:{norm_url}"

        # Handle Port Scans
        if tool_norm in ("nmap", "port_scan", "service_scan", "network_recon"):
            target = str(parameters.get("target") or parameters.get("host") or "").strip()
            ports = str(parameters.get("ports") or parameters.get("port") or "all").strip()
            return f"SCAN:{target}:{ports}"

        # Handle SQLi / Vulnerability Scans
        if tool_norm in ("sqlmap", "sqli_scan", "vulnerability_scan", "vuln_check"):
            target = str(parameters.get("url") or parameters.get("target") or "").strip()
            param = str(parameters.get("param") or parameters.get("parameter") or "").strip()
            return f"VULN:{tool_norm}:{target}:{param}"

        # Generic parameters hash
        param_str = json_canonical_repr(parameters)
        return f"TOOL:{tool_norm}:{param_str}"

    def record_action(
        self,
        action_id: str,
        tool_name: str,
        target: str,
        parameters: Dict[str, Any],
        before_state_counts: Dict[str, int],
        after_state_counts: Dict[str, int],
        action_cost: float = 1.0,
        turn_number: int = 0,
        branch_id: str = "default",
        model_name: str = "default",
        timestamp: float = 0.0,
    ) -> ActionRecord:
        """
        Calculates the information gain of an action by delta comparison.
        """
        canonical_key = self.normalize_action(tool_name, parameters)
        execution_count = self.seen_action_keys.get(canonical_key, 0)
        is_duplicate = execution_count > 0

        # Calculate Raw Gain
        delta_evidence = max(0, after_state_counts.get("evidence", 0) - before_state_counts.get("evidence", 0))
        delta_nodes = max(0, after_state_counts.get("nodes", 0) - before_state_counts.get("nodes", 0))
        delta_edges = max(0, after_state_counts.get("edges", 0) - before_state_counts.get("edges", 0))
        delta_caps = max(0, after_state_counts.get("capabilities", 0) - before_state_counts.get("capabilities", 0))
        delta_findings = max(0, after_state_counts.get("findings", 0) - before_state_counts.get("findings", 0))
        delta_hypotheses_refuted = max(0, after_state_counts.get("refuted_hypotheses", 0) - before_state_counts.get("refuted_hypotheses", 0))

        raw_gain = (
            (delta_evidence * 1.0) +
            (delta_nodes * 2.0) +
            (delta_edges * 1.5) +
            (delta_caps * 5.0) +
            (delta_findings * 10.0) +
            (delta_hypotheses_refuted * 1.5)
        )

        # Apply decay for repeated actions (approaches 0 exponentially)
        decay_factor = 1.0 / (1.0 + (execution_count * 2.0))
        actual_gain = raw_gain * decay_factor

        efficiency = actual_gain / max(0.1, action_cost)

        rec = ActionRecord(
            action_id=action_id,
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            canonical_action_key=canonical_key,
            expected_gain=1.0 if not is_duplicate else 0.2,
            actual_gain=actual_gain,
            action_cost=action_cost,
            action_efficiency=efficiency,
            is_duplicate=is_duplicate,
            turn_number=turn_number,
            branch_id=branch_id,
            model_name=model_name,
            timestamp=timestamp
        )

        self.action_history.append(rec)
        self.seen_action_keys[canonical_key] = execution_count + 1

        # Update metrics
        self._update_metrics(rec)
        return rec

    def _update_metrics(self, latest_record: ActionRecord) -> None:
        self.metrics.total_actions_evaluated = len(self.action_history)
        self.metrics.total_information_gain += latest_record.actual_gain

        if self.metrics.total_actions_evaluated > 0:
            self.metrics.average_gain_per_action = (
                self.metrics.total_information_gain / self.metrics.total_actions_evaluated
            )

        # Rolling average
        window = self.action_history[-self.rolling_window_size:]
        if window:
            self.metrics.recent_gain_per_action = sum(a.actual_gain for a in window) / len(window)

        if latest_record.is_duplicate:
            self.metrics.duplicate_action_count += 1

        self.metrics.duplicate_action_rate = (
            self.metrics.duplicate_action_count / self.metrics.total_actions_evaluated
        )

        # Group gains
        b = latest_record.branch_id
        self.metrics.gain_by_branch[b] = self.metrics.gain_by_branch.get(b, 0.0) + latest_record.actual_gain

        t = latest_record.tool_name
        self.metrics.gain_by_tool[t] = self.metrics.gain_by_tool.get(t, 0.0) + latest_record.actual_gain

        m = latest_record.model_name
        self.metrics.gain_by_model[m] = self.metrics.gain_by_model.get(m, 0.0) + latest_record.actual_gain

    def calculate_and_record_gain(
        self,
        tool_name: str,
        target: str,
        parameters: Dict[str, Any],
        state_delta: Dict[str, int],
        cost: float = 1.0,
        branch_id: str = "default",
    ) -> float:
        """Calculates information gain using a state delta dict."""
        before_counts = {
            "evidence": 0, "nodes": 0, "edges": 0,
            "capabilities": 0, "findings": 0, "refuted_hypotheses": 0
        }
        after_counts = {
            "evidence": state_delta.get("new_evidence", 0),
            "nodes": state_delta.get("new_nodes", 0),
            "edges": state_delta.get("new_edges", 0),
            "capabilities": state_delta.get("new_capabilities", 0),
            "findings": state_delta.get("new_findings", 0),
            "refuted_hypotheses": state_delta.get("new_refuted_hypotheses", 0)
        }
        rec = self.record_action(
            action_id=f"act-{len(self.action_history) + 1}",
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            before_state_counts=before_counts,
            after_state_counts=after_counts,
            action_cost=cost,
            branch_id=branch_id
        )
        return rec.actual_gain

    def get_decay_factor(self, tool_name: str, parameters: Dict[str, Any]) -> float:
        """Returns the empirical decay factor for a given tool action."""
        canonical_key = self.normalize_action(tool_name, parameters)
        execution_count = self.seen_action_keys.get(canonical_key, 0)
        return 1.0 / (1.0 + (execution_count * 2.0))


def json_canonical_repr(obj: Any) -> str:
    """Produces a deterministic sorted JSON representation."""
    import json
    try:
        return json.dumps(obj, sort_keys=True)
    except Exception:
        return str(obj)
