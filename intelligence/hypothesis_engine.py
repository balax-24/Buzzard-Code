"""
Hypothesis Engine — Structured, multi-hypothesis manager for Buzzard Code.

Responsibilities:
  1. Maintain a typed registry of VulnerabilityHypothesis objects with explicit lifecycle states.
  2. Score and rank hypotheses by evidence strength and precondition satisfaction.
  3. Propose the highest-priority, evidence-justified next action (tool + args) for each hypothesis.
  4. Update hypothesis status after tool execution results.
  5. Derive new hypotheses when the AttackGraph exposes unexplored PENDING nodes.

This replaces the ad-hoc `derive_hypotheses_from_evidence()` method in AssessmentState
with a proper, testable, standalone engine that:
  - Never makes decisions based purely on LLM output
  - Always grounds proposals in concrete evidence IDs
  - Returns typed HypothesisProposal objects, not raw strings
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from agent.assessment_state import (
    AssessmentState,
    ServiceState,
    HypothesisStatus,
    VulnerabilityHypothesis,
)
from intelligence.attack_graph import AttackGraph, NodeKind, NodeStatus
from intelligence.capability import Capability, CapabilityType


# ---------------------------------------------------------------------------
# Proposal types
# ---------------------------------------------------------------------------

class ProposalConfidence(str, Enum):
    HIGH   = "HIGH"    # Direct evidence supports the hypothesis
    MEDIUM = "MEDIUM"  # Circumstantial evidence (service type, port, banner)
    LOW    = "LOW"     # Inferred from target type / objective only


@dataclass
class HypothesisProposal:
    """
    A ranked, evidence-grounded proposal for the next exploitation/validation action.
    The CompletionEngine and AgentLoop consume these to drive autonomous continuation.
    """
    hypothesis_id: str
    vulnerability_type: str
    target: str
    port: int
    tool_name: str
    tool_args: Dict[str, Any]
    rationale: str
    evidence_ids: List[str]
    confidence: ProposalConfidence = ProposalConfidence.MEDIUM
    priority: int = 50             # 0 = highest priority
    verification_plan: str = ""
    capability_context: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def identity(self) -> str:
        return f"{self.target}::{self.port}::{self.vulnerability_type}::{self.capability_context}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "vulnerability_type": self.vulnerability_type,
            "target": self.target,
            "port": self.port,
            "tool": self.tool_name,
            "args": self.tool_args,
            "rationale": self.rationale,
            "evidence_ids": self.evidence_ids,
            "confidence": self.confidence.value,
            "priority": self.priority,
            "verification_plan": self.verification_plan,
            "capability_context": self.capability_context,
            "identity": self.identity,
        }

    def to_context_line(self) -> str:
        return (
            f"  [{self.confidence.value}] {self.vulnerability_type} on {self.target}:{self.port} "
            f"→ {self.tool_name} | Evidence: {', '.join(self.evidence_ids) or 'None'} | "
            f"Rationale: {self.rationale}"
        )


# ---------------------------------------------------------------------------
# Hypothesis scoring rules
# ---------------------------------------------------------------------------

# Vulnerability type → (base_priority, confidence_boost_if_endpoint_found)
_VULN_PRIORITY_MAP: Dict[str, Tuple[int, int]] = {
    "auth_bypass_sqli":     (10, -10),
    "sql_injection":        (15, -10),
    "rce":                  ( 5, -15),
    "lfi":                  (20, -5),
    "path_traversal":       (20, -5),
    "xss":                  (35, 0),
    "ssrf":                 (30, 0),
    "command_injection":    (10, -15),
    "idor":                 (25, 0),
    "open_redirect":        (40, 0),
    "weak_credentials":     (20, -5),
    "default_credentials":  (15, -10),
    "directory_traversal":  (20, -5),
    "information_disclosure": (45, 0),
}

_SERVICE_VULN_MAP: Dict[str, List[Tuple[str, str, str, int]]] = {
    # service_name → [(vuln_type, tool, verification_plan, priority)]
    "http":  [
        ("auth_bypass_sqli",  "sqlmap_attack",  "Check /login for SQL injection bypass",   10),
        ("lfi",               "lfi_scan",       "Check ?file= params for path traversal",  20),
        ("xss",               "xss_scan",       "Check input fields for reflected XSS",    35),
        ("command_injection", "cmd_injection_scan", "Check /ping for OS injection",         15),
    ],
    "https": [
        ("auth_bypass_sqli",  "sqlmap_attack",  "Check /login for SQL injection bypass",   10),
        ("lfi",               "lfi_scan",       "Check ?file= params for path traversal",  20),
    ],
    "ssh":   [
        ("weak_credentials",  "ssh_brute",      "Brute force SSH with common credentials", 25),
    ],
    "ftp":   [
        ("weak_credentials",  "ftp_brute",      "Brute force FTP anonymous/default creds", 25),
        ("default_credentials", "ftp_brute",    "Test anonymous FTP access",               20),
    ],
    "smb":   [
        ("weak_credentials",  "smb_brute",      "Brute force SMB with common credentials", 25),
    ],
    "mysql": [
        ("weak_credentials",  "generic_service_brute", "Brute force MySQL root password",  20),
    ],
    "postgres": [
        ("weak_credentials",  "generic_service_brute", "Brute force PostgreSQL postgres",  20),
    ],
}


# ---------------------------------------------------------------------------
# Hypothesis Engine
# ---------------------------------------------------------------------------

class HypothesisEngine:
    """
    Multi-hypothesis manager with evidence-grounded proposal generation.

    Usage:
        engine = HypothesisEngine()
        proposals = engine.propose_next_actions(state, graph)
        for proposal in proposals:
            # Hand proposal.tool_name + proposal.tool_args to ToolExecutor
            ...
        engine.update_from_result(hypothesis_id, success, raw_output)
    """

    def __init__(self) -> None:
        # Registry of all hypotheses ever created in this engine instance
        self._proposals_generated: int = 0
        self._proposals_executed: int  = 0
        self._refuted_hypotheses: Set[str] = set()

    # ------------------------------------------------------------------
    # Proposal generation
    # ------------------------------------------------------------------

    def propose_next_actions(
        self,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        max_proposals: int = 5,
    ) -> List[HypothesisProposal]:
        """
        Returns a ranked list of evidence-grounded HypothesisProposal objects.
        Does NOT modify state or graph — purely advisory.

        Priority order:
          1. Active hypotheses with satisfied preconditions (highest confidence)
          2. Uninvestigated services that map to known vuln patterns
          3. Pending graph nodes that have no hypothesis yet
        """
        proposals: List[HypothesisProposal] = []
        seen_hyps: Set[str] = set()

        # ---- Phase 1: Existing hypotheses with satisfied preconditions ----
        for hyp in state.get_active_hypotheses():
            if hyp.id in seen_hyps:
                continue
            candidates = state.generate_exploit_candidates()
            for cand in candidates:
                if cand.hypothesis_id == hyp.id:
                    eligible, _ = cand.evaluate_preconditions(state)
                    if eligible:
                        prop = HypothesisProposal(
                            hypothesis_id=hyp.id,
                            vulnerability_type=hyp.vulnerability_type,
                            target=hyp.target,
                            port=hyp.port,
                            tool_name=cand.allowed_tool,
                            tool_args=cand.tool_arguments,
                            rationale=hyp.rationale or f"Active hypothesis: {hyp.vulnerability_type} on port {hyp.port}",
                            evidence_ids=list(hyp.evidence_ids),
                            confidence=ProposalConfidence.HIGH,
                            priority=self._score_hypothesis(hyp, state),
                            verification_plan=cand.verification_plan,
                        )
                        proposals.append(prop)
                        seen_hyps.add(hyp.id)
                        break

        # ---- Phase 2: Derive from uninvestigated services ----
        target_host = state.context.target.split("://")[-1].split("/")[0].split(":")[0]

        for srv in state.services.values():
            if srv.state != ServiceState.OPEN:
                continue

            svc_lower = srv.service.lower()
            vuln_patterns = _SERVICE_VULN_MAP.get(svc_lower, [])

            # HTTP services: always check common web vulns if no hypothesis exists
            if not vuln_patterns and srv.is_http_compatible():
                vuln_patterns = _SERVICE_VULN_MAP.get("http", [])

            for vuln_type, tool_name, verification_plan, base_priority in vuln_patterns:
                hyp_id = f"HYP-{vuln_type.upper()}-{srv.port}"
                if hyp_id in seen_hyps:
                    continue

                # Check if we already have this hypothesis in state and no new evidence
                if self._is_refuted_without_new_evidence(hyp_id, list(srv.evidence_ids), state):
                    continue

                # Build tool arguments
                scheme = "https" if srv.port == 443 else "http"
                base_url = f"{scheme}://{target_host}:{srv.port}"
                tool_args = self._build_tool_args(tool_name, target_host, srv.port, base_url)

                # Determine confidence from available evidence
                confidence = ProposalConfidence.HIGH if srv.evidence_ids else ProposalConfidence.MEDIUM

                prop = HypothesisProposal(
                    hypothesis_id=hyp_id,
                    vulnerability_type=vuln_type,
                    target=base_url,
                    port=srv.port,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    rationale=(
                        f"Service {srv.service} on port {srv.port} is known to be susceptible "
                        f"to {vuln_type}. Grounded evidence: {', '.join(srv.evidence_ids) or 'service discovery'}."
                    ),
                    evidence_ids=list(srv.evidence_ids),
                    confidence=confidence,
                    priority=base_priority,
                    verification_plan=verification_plan,
                )
                proposals.append(prop)
                seen_hyps.add(hyp_id)

        # ---- Phase 2.5: Capability-Driven Expansion (Phase 7B) ----
        for cap in getattr(state, "capabilities", {}).values():
            if not getattr(cap, "verified", True):
                continue
            cap_type = cap.capability_type
            cap_eids = list(cap.source_evidence_ids)
            cap_type_val = cap_type.value if hasattr(cap_type, "value") else str(cap_type)

            # Discover unlocked endpoints directly from capability or graph
            unlocked_urls: List[str] = list(cap.metadata.get("unlocked_endpoints", []))
            if graph is not None:
                for node in graph.nodes.values():
                    if node.kind == NodeKind.ENDPOINT and node.metadata.get("unlocked_by_capability") == cap.capability_id:
                        node_url = node.metadata.get("url") or node.label.replace("HTTP:", "")
                        if node_url and node_url not in unlocked_urls:
                            unlocked_urls.append(node_url)

            for ep_url in unlocked_urls:
                url_str = ep_url if isinstance(ep_url, str) else ep_url.get("url", "")
                if not url_str:
                    continue

                port = 80
                try:
                    host_part = url_str.split("://")[-1].split("/")[0]
                    if ":" in host_part:
                        port = int(host_part.split(":")[-1])
                except Exception:
                    port = 80

                # Determine target vulnerability type based on capability & endpoint semantics
                if cap_type == CapabilityType.AUTHENTICATED:
                    if any(k in url_str.lower() for k in ("backup", "file", "download", "log", "view", "page", "read")):
                        v_type = "lfi"
                        t_name = "lfi_scan"
                        priority = 12
                    elif any(k in url_str.lower() for k in ("ping", "exec", "cmd", "run", "tools", "system")):
                        v_type = "command_injection"
                        t_name = "cmd_injection_scan"
                        priority = 10
                    else:
                        v_type = "idor"
                        t_name = "web_fetch"
                        priority = 18
                elif cap_type == CapabilityType.FILE_READ:
                    v_type = "command_injection"
                    t_name = "cmd_injection_scan"
                    priority = 10
                elif cap_type in (CapabilityType.COMMAND_EXECUTION, CapabilityType.ADMIN_ACCESS):
                    v_type = "post_exploit_proof"
                    t_name = "web_fetch"
                    priority = 5
                else:
                    v_type = "endpoint_investigation"
                    t_name = "web_fetch"
                    priority = 25

                hyp_id = f"HYP-{v_type.upper()}-{cap.capability_id[:8]}-{abs(hash(url_str)) % 10000}"
                if hyp_id in seen_hyps or self._is_refuted_without_new_evidence(hyp_id, cap_eids, state):
                    continue

                tool_args = {"url": url_str}
                if "headers" in cap.metadata:
                    tool_args["headers"] = cap.metadata["headers"]

                prop = HypothesisProposal(
                    hypothesis_id=hyp_id,
                    vulnerability_type=v_type,
                    target=url_str,
                    port=port,
                    tool_name=t_name,
                    tool_args=tool_args,
                    rationale=f"Capability {cap_type_val} unlocks new attack surface at {url_str}",
                    evidence_ids=cap_eids,
                    confidence=ProposalConfidence.HIGH,
                    priority=priority,
                    verification_plan=f"Validate {v_type} with granted capability {cap_type_val} on {url_str}",
                    capability_context=cap.capability_id,
                )
                proposals.append(prop)
                seen_hyps.add(hyp_id)

        # ---- Phase 2.6: Application-Surface, Forms & WebSockets (Phase 9) ----
        # A. Forms Reasoning
        state_forms = getattr(state, "forms", {})
        for f_key, frm in state_forms.items():
            f_action = getattr(frm, "action", "")
            f_method = getattr(frm, "method", "GET").upper()
            f_eids = list(getattr(frm, "evidence_ids", []))
            if not f_action:
                continue

            port = 80
            try:
                h_p = f_action.split("://")[-1].split("/")[0]
                if ":" in h_p:
                    port = int(h_p.split(":")[-1])
            except Exception:
                port = 80

            is_login = getattr(frm, "is_login_form", False)
            has_csrf = getattr(frm, "has_csrf", True)
            has_file_upload = any(getattr(f, "type", "") == "file" for f in getattr(frm, "fields", []))

            if is_login:
                hyp_id = f"HYP-AUTH-SQLI-{port}-{abs(hash(f_action)) % 10000}"
                if hyp_id not in seen_hyps and not self._is_refuted_without_new_evidence(hyp_id, f_eids, state):
                    proposals.append(HypothesisProposal(
                        hypothesis_id=hyp_id,
                        vulnerability_type="auth_bypass_sqli",
                        target=f_action,
                        port=port,
                        tool_name="sqli_scan",
                        tool_args={"url": f_action, "method": f_method},
                        rationale=f"Discovered authentication form with action '{f_action}'. Known injection point.",
                        evidence_ids=f_eids,
                        confidence=ProposalConfidence.HIGH,
                        priority=12,
                        verification_plan="Attempt authentication bypass payload on discovered login form.",
                    ))
                    seen_hyps.add(hyp_id)

            if has_file_upload:
                hyp_id = f"HYP-UPLOAD-RCE-{port}-{abs(hash(f_action)) % 10000}"
                if hyp_id not in seen_hyps and not self._is_refuted_without_new_evidence(hyp_id, f_eids, state):
                    proposals.append(HypothesisProposal(
                        hypothesis_id=hyp_id,
                        vulnerability_type="unrestricted_file_upload",
                        target=f_action,
                        port=port,
                        tool_name="file_upload_probe",
                        tool_args={"url": f_action, "method": "POST"},
                        rationale=f"Discovered file upload form at '{f_action}'. Susceptible to arbitrary file upload / RCE.",
                        evidence_ids=f_eids,
                        confidence=ProposalConfidence.HIGH,
                        priority=14,
                        verification_plan="Upload polyglot file payload and confirm execution.",
                    ))
                    seen_hyps.add(hyp_id)

            if not has_csrf and f_method in ("POST", "PUT", "DELETE") and not is_login:
                hyp_id = f"HYP-CSRF-{port}-{abs(hash(f_action)) % 10000}"
                if hyp_id not in seen_hyps and not self._is_refuted_without_new_evidence(hyp_id, f_eids, state):
                    proposals.append(HypothesisProposal(
                        hypothesis_id=hyp_id,
                        vulnerability_type="csrf",
                        target=f_action,
                        port=port,
                        tool_name="web_fetch",
                        tool_args={"url": f_action, "method": f_method},
                        rationale=f"State-changing {f_method} form at '{f_action}' lacks anti-CSRF token protection.",
                        evidence_ids=f_eids,
                        confidence=ProposalConfidence.MEDIUM,
                        priority=19,
                        verification_plan="Verify state modification succeeds without valid anti-forgery token.",
                    ))
                    seen_hyps.add(hyp_id)

        # B. WebSockets Reasoning
        state_ws = getattr(state, "websockets", {})
        for w_key, ws in state_ws.items():
            ws_url = getattr(ws, "url", w_key)
            ws_eids = list(getattr(ws, "evidence_ids", []))
            if not ws_url:
                continue

            hyp_id = f"HYP-WS-HIJACK-80-{abs(hash(ws_url)) % 10000}"
            if hyp_id not in seen_hyps and not self._is_refuted_without_new_evidence(hyp_id, ws_eids, state):
                proposals.append(HypothesisProposal(
                    hypothesis_id=hyp_id,
                    vulnerability_type="websocket_hijacking",
                    target=ws_url,
                    port=80,
                    tool_name="web_fetch",
                    tool_args={"url": ws_url},
                    rationale=f"Discovered WebSocket connection at '{ws_url}'. Potential cross-site WebSocket hijacking or unauthenticated access.",
                    evidence_ids=ws_eids,
                    confidence=ProposalConfidence.MEDIUM,
                    priority=22,
                    verification_plan="Initiate WebSocket handshake with unauthorized Origin header to confirm origin validation.",
                ))
                seen_hyps.add(hyp_id)

        # ---- Phase 3: Uninvestigated graph nodes ----
        if graph is not None:
            for node in graph.pending_nodes():
                if node.kind == NodeKind.ENDPOINT:
                    url = node.metadata.get("url", "")
                    if not url:
                        continue
                    hyp_id = f"HYP-ENDPOINT-{node.node_id}"
                    if hyp_id in seen_hyps or self._is_refuted_without_new_evidence(hyp_id, list(node.evidence_ids), state):
                        continue
                    prop = HypothesisProposal(
                        hypothesis_id=hyp_id,
                        vulnerability_type="endpoint_investigation",
                        target=url,
                        port=int(url.split("://")[-1].split("/")[0].split(":")[-1]) if ":" in url.split("://")[-1].split("/")[0] else 80,
                        tool_name="web_fetch",
                        tool_args={"url": url},
                        rationale=f"Uninvestigated endpoint node: {node.label}",
                        evidence_ids=list(node.evidence_ids),
                        confidence=ProposalConfidence.LOW,
                        priority=node.priority + 20,
                        verification_plan="Fetch endpoint, inspect response for injection points or sensitive data.",
                    )
                    proposals.append(prop)
                    seen_hyps.add(hyp_id)

        # Sort and deduplicate by priority
        proposals.sort(key=lambda p: p.priority)
        self._proposals_generated += len(proposals)
        if state and hasattr(state, "hypotheses_considered"):
            state.hypotheses_considered += len(proposals)
        return proposals[:max_proposals]

    def _is_refuted_without_new_evidence(
        self,
        hypothesis_id: str,
        proposal_evidence_ids: List[str],
        state: AssessmentState,
    ) -> bool:
        """
        Returns True if this hypothesis was previously VERIFIED, REFUTED, FAILED, or ABANDONED
        and NO new evidence IDs have arrived since that failure.
        """
        if hypothesis_id in self._refuted_hypotheses and not proposal_evidence_ids:
            return True
        existing = state.hypotheses.get(hypothesis_id)
        if not existing:
            return hypothesis_id in self._refuted_hypotheses and not proposal_evidence_ids
        if existing.status == HypothesisStatus.VERIFIED:
            return True
        if existing.status in (
            HypothesisStatus.REFUTED,
            HypothesisStatus.FAILED,
            HypothesisStatus.ABANDONED,
            HypothesisStatus.REJECTED,
        ):
            if not existing.evidence_ids:
                return True
            if set(proposal_evidence_ids).issubset(set(existing.evidence_ids)):
                return True
        return False

    # ------------------------------------------------------------------
    # Hypothesis lifecycle updates
    # ------------------------------------------------------------------

    def update_from_result(
        self,
        state: AssessmentState,
        hypothesis_id: str,
        tool_name: str,
        raw_output: str,
        success: bool,
    ) -> None:
        """
        Updates the hypothesis lifecycle based on a tool execution result.
        Called by the AgentLoop after each ToolExecutor.execute() call.
        """
        self._proposals_executed += 1
        hyp = state.hypotheses.get(hypothesis_id)
        if not hyp:
            return

        # Positive markers in output → hypothesis VERIFIED
        predicates = getattr(state, "predicates", None)
        proof_markers = getattr(predicates, "proof_markers", None) or getattr(state, "proof_markers", None)
        session_indicators = getattr(predicates, "session_indicators", None)
        if not proof_markers or session_indicators is None:
            from agent.assessment_state import VerificationPredicates
            default_pred = VerificationPredicates()
            proof_markers = proof_markers or default_pred.proof_markers
            session_indicators = session_indicators if session_indicators is not None else default_pred.session_indicators
        all_markers = (proof_markers or []) + (session_indicators or [])
        if success and any(m in raw_output for m in all_markers):
            hyp.status = HypothesisStatus.VERIFIED
            hyp.verified = True
            return

        # Failure markers → hypothesis FAILED
        if not success or any(m in raw_output.lower() for m in [
            "connection refused", "not found", "404", "not supported",
            "blocked", "quarantined", "dependency_missing"
        ]):
            if hyp.status != HypothesisStatus.VERIFIED:
                hyp.status = HypothesisStatus.FAILED

    def ensure_hypotheses_in_state(
        self,
        state: AssessmentState,
        proposals: List[HypothesisProposal],
    ) -> None:
        """
        For each proposal, ensure the corresponding VulnerabilityHypothesis exists
        in state.hypotheses. Called before the AgentLoop injects the proposal into context.
        """
        for p in proposals:
            if p.hypothesis_id not in state.hypotheses:
                state.record_hypothesis(
                    target=p.target,
                    service=p.vulnerability_type,
                    port=p.port,
                    vulnerability_type=p.vulnerability_type,
                    rationale=p.rationale,
                    evidence_ids=p.evidence_ids,
                    suggested_tools=[p.tool_name],
                    hypothesis_id=p.hypothesis_id,
                )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _score_hypothesis(self, hyp: VulnerabilityHypothesis, state: AssessmentState) -> int:
        """Lower = higher priority."""
        base, _ = _VULN_PRIORITY_MAP.get(hyp.vulnerability_type, (50, 0))

        # Boost if evidence IDs are populated
        if hyp.evidence_ids:
            base -= 5

        # Boost for critical vulnerability types
        if hyp.vulnerability_type in ("rce", "auth_bypass_sqli", "command_injection"):
            base -= 10

        return max(0, base)

    def _build_tool_args(
        self,
        tool_name: str,
        host: str,
        port: int,
        base_url: str,
    ) -> Dict[str, Any]:
        """Constructs default tool arguments for common exploitation tools."""
        mapping: Dict[str, Dict[str, Any]] = {
            "sqlmap_attack": {
                "url": f"{base_url}/login",
                "data": "username=admin&password=admin",
                "level": "2",
            },
            "lfi_scan": {
                "url": base_url,
            },
            "xss_scan": {
                "url": base_url,
            },
            "cmd_injection_scan": {
                "url": f"{base_url}/ping",
            },
            "ssrf_scan": {
                "url": base_url,
            },
            "ssh_brute": {
                "host": host,
                "port": port,
            },
            "ftp_brute": {
                "host": host,
                "port": port,
            },
            "generic_service_brute": {
                "host": host,
                "port": port,
            },
            "web_fetch": {
                "url": base_url,
            },
            "whatweb_scan": {
                "url": base_url,
            },
            "ffuf_fuzz": {
                "url": f"{base_url}/FUZZ",
                "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            },
        }
        return mapping.get(tool_name, {"host": host, "port": port, "url": base_url})

    # ------------------------------------------------------------------
    # Context formatting
    # ------------------------------------------------------------------

    def format_context_block(self, proposals: List[HypothesisProposal]) -> str:
        """Formats proposals as a compact LLM context injection block."""
        if not proposals:
            return "HYPOTHESIS ENGINE: No active proposals — all services exhausted or no attack surface discovered yet."

        lines = [
            "=== HYPOTHESIS ENGINE — NEXT CANDIDATE ACTIONS ===",
            f"({len(proposals)} evidence-grounded proposals, ranked by priority)",
        ]
        for i, p in enumerate(proposals, 1):
            lines.append(f"\n[{i}] {p.vulnerability_type.upper()} | Priority: {p.priority} | Confidence: {p.confidence.value}")
            lines.append(f"    Target: {p.target}:{p.port}")
            lines.append(f"    Tool: {p.tool_name}")
            lines.append(f"    Args: {p.tool_args}")
            lines.append(f"    Rationale: {p.rationale}")
            lines.append(f"    Verification: {p.verification_plan}")
            lines.append(f"    Evidence IDs: {', '.join(p.evidence_ids) or 'None'}")
        lines.append("====================================================")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Hypothesis Lifecycle State Machine
    # ------------------------------------------------------------------

    def mark_hypothesis_selected(self, hypothesis_id: str, state: Optional[AssessmentState] = None) -> None:
        """Marks a hypothesis as SELECTED by the planner."""
        if state and hasattr(state, "hypotheses_selected"):
            state.hypotheses_selected += 1
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.INVESTIGATING

    def mark_hypothesis_testing(self, hypothesis_id: str, state: Optional[AssessmentState] = None) -> None:
        """Marks a hypothesis as actively TESTING."""
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.INVESTIGATING

    def mark_hypothesis_verified(self, hypothesis_id: str, state: Optional[AssessmentState] = None) -> None:
        """Marks a hypothesis as VERIFIED after independent evidence acquisition."""
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.CONFIRMED

    def mark_hypothesis_refuted(self, hypothesis_id: str, reason: str = "", state: Optional[AssessmentState] = None) -> None:
        """Marks a hypothesis as REFUTED with documented justification."""
        self._refuted_hypotheses.add(hypothesis_id)
        if state and hasattr(state, "hypotheses_refuted"):
            state.hypotheses_refuted += 1
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.REFUTED
            if reason and hasattr(state.hypotheses[hypothesis_id], "refutation_reason"):
                state.hypotheses[hypothesis_id].refutation_reason = reason

    def mark_hypothesis_abandoned(self, hypothesis_id: str, reason: str = "", state: Optional[AssessmentState] = None) -> None:
        """Marks a hypothesis as ABANDONED (e.g. out-of-scope or blocked prerequisites)."""
        if state and hasattr(state, "hypotheses_abandoned"):
            state.hypotheses_abandoned += 1
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.ABANDONED

    def mark_hypothesis_reopened(self, hypothesis_id: str, state: Optional[AssessmentState] = None) -> None:
        """Reopens a previously refuted/abandoned hypothesis upon receipt of new evidence."""
        self._refuted_hypotheses.discard(hypothesis_id)
        if state and hasattr(state, "hypotheses_reopened"):
            state.hypotheses_reopened += 1
        if state and hasattr(state, "hypotheses") and hypothesis_id in state.hypotheses:
            state.hypotheses[hypothesis_id].status = HypothesisStatus.UNTESTED
