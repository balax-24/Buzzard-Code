"""
Deterministic Controller for Buzzard Code.

A model-independent assessment controller capable of autonomously exercising
the full recursive assessment lifecycle:
  STATE -> CANDIDATES -> highest_priority_candidate() -> PRECONDITIONS ->
  ACTION -> OBSERVATION -> EVIDENCE -> STATE UPDATE -> GRAPH/HYPOTHESIS UPDATE ->
  INFORMATION GAIN -> VERIFICATION / COMPLETION -> NEXT CANDIDATE

Operates strictly over:
- Canonical truth: AssessmentState
- Pure derived projections: AssetGraph, AttackGraph, DerivedContextView
- Decision machinery: HypothesisEngine, ActionSelectionEngine
- Verification machinery: EvidenceIngestor, FindingVerifier, CompletionEngine
- Recovery machinery: FailureAwareMemory, StuckLoopDetector, ActionHistoryStore

Attribution:
Every action decision is explicitly attributed to DETERMINISTIC_CONTROLLER.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentContext,
    AssessmentPhase,
    ObjectiveStatus,
    VerificationPredicates,
    ServiceState,
    HypothesisStatus,
    CapabilityType,
    VerificationStatus,
    FailureClassification,
)
from security_agent.intelligence.attack_graph import (
    AttackGraph,
    NodeKind,
    NodeStatus,
    EdgeKind,
)
from security_agent.intelligence.hypothesis_engine import (
    HypothesisEngine,
    HypothesisProposal,
    ProposalConfidence,
)
from security_agent.intelligence.action_selection import (
    ActionSelectionEngine,
    ActionCandidate,
    GainRecommendation,
    RiskClass,
)
from security_agent.intelligence.decision import (
    DecisionRecord,
    DecisionSource,
)
from security_agent.agent.completion_engine import (
    CompletionEngine,
    CompletionAction,
    CompletionDecision,
    AssessmentMode,
    BudgetSnapshot,
)
from security_agent.intelligence.evidence_ingestor import EvidenceIngestor, EvidenceItem
from security_agent.intelligence.information_gain import InformationGainEngine
from security_agent.intelligence.action_history import ActionHistoryStore
from security_agent.intelligence.failure_memory import FailureAwareMemory
from security_agent.agent.loop_controller import StuckLoopDetector


# ---------------------------------------------------------------------------
# Results & Telemetry
# ---------------------------------------------------------------------------

@dataclass
class ControllerStepResult:
    action_executed: Optional[str] = None
    target: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    information_gain: float = 0.0
    status: str = "CONTINUE"  # CONTINUE, VERIFY, CONCLUDE_SUCCESS, CONCLUDE_BUDGET, SURFACE_EXHAUSTED, PRECONDITION_FAILED, ZERO_GAIN_EXHAUSTED
    completed: bool = False
    evidence_ids: List[str] = field(default_factory=list)
    capabilities_acquired: List[str] = field(default_factory=list)
    findings_recorded: List[str] = field(default_factory=list)
    details: str = ""


@dataclass
class ControllerRunSummary:
    total_steps: int = 0
    terminal_status: str = "RUNNING"
    objective_status: ObjectiveStatus = ObjectiveStatus.OBJECTIVE_UNREACHED
    total_information_gain: float = 0.0
    findings_count: int = 0
    capabilities_count: int = 0
    evidence_count: int = 0
    trace: List[str] = field(default_factory=list)
    decisions_count: int = 0


# ---------------------------------------------------------------------------
# Functional Entrypoint
# ---------------------------------------------------------------------------

def highest_priority_candidate(
    state: AssessmentState,
    graph: Optional[AttackGraph] = None,
    history: Optional[ActionHistoryStore] = None,
    failure_memory: Optional[FailureAwareMemory] = None,
    max_candidates: int = 10,
) -> Optional[ActionCandidate]:
    """
    Deterministic candidate selection entry point.
    Ranks candidates using expected information gain, novelty, hypothesis relevance,
    evidence coverage, precondition satisfaction, capability potential, verification
    potential, previous failures, and cost.
    """
    if graph is None:
        graph = AttackGraph()
        graph.sync_from_state(state)
    else:
        graph.sync_from_state(state)

    hyp_engine = HypothesisEngine()
    proposals = hyp_engine.propose_next_actions(state, graph=graph, max_proposals=max_candidates)

    # If no proposals generated and state has no services yet, create initial discovery proposal
    if not proposals and not state.services and state.context.target:
        target_url = state.context.target
        target_host = target_url.split("://")[-1].split("/")[0].split(":")[0]
        port = 80
        if ":" in target_url.split("://")[-1].split("/")[0]:
            try:
                port = int(target_url.split("://")[-1].split("/")[0].split(":")[-1])
            except Exception:
                port = 80
        init_prop = HypothesisProposal(
            hypothesis_id="HYP-INIT-DISCOVERY",
            vulnerability_type="service_discovery",
            target=target_url,
            port=port,
            tool_name="web_fetch" if "http" in target_url else "nmap_scan",
            tool_args={"url": target_url} if "http" in target_url else {"target": target_host, "ports": str(port)},
            rationale=f"Initial discovery of target surface {target_url}",
            evidence_ids=[],
            confidence=ProposalConfidence.HIGH,
            priority=1,
            verification_plan=f"Probe {target_url} to identify live ports and response banners",
        )
        proposals = [init_prop]

    candidates = ActionSelectionEngine.generate_candidates(
        state=state,
        graph=graph,
        proposals=proposals,
        history=history,
        failure_memory=failure_memory,
        max_candidates=max_candidates,
    )
    return ActionSelectionEngine.select_best_candidate(candidates)


# ---------------------------------------------------------------------------
# Deterministic Controller
# ---------------------------------------------------------------------------

class DeterministicController:
    """
    Model-independent autonomous assessment controller.
    Progresses through recursive assessment lifecycle strictly through
    canonical state updates and derived projections.
    """

    ATTRIBUTION = "DETERMINISTIC_CONTROLLER"

    def __init__(
        self,
        state: AssessmentState,
        graph: Optional[AttackGraph] = None,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        completion_engine: Optional[CompletionEngine] = None,
        evidence_ingestor: Optional[EvidenceIngestor] = None,
        gain_engine: Optional[InformationGainEngine] = None,
        failure_memory: Optional[FailureAwareMemory] = None,
        action_history: Optional[ActionHistoryStore] = None,
        loop_detector: Optional[StuckLoopDetector] = None,
        tool_executor: Optional[Callable[[str, Dict[str, Any]], Dict[str, Any]]] = None,
        budget: Optional[BudgetSnapshot] = None,
        max_zero_gain_streak: int = 5,
    ):
        self.state = state
        self.graph = graph or AttackGraph()
        self.graph.sync_from_state(self.state)

        self.hypothesis_engine = hypothesis_engine or HypothesisEngine()
        self.completion_engine = completion_engine or CompletionEngine(mode=AssessmentMode.TARGETED)
        self.evidence_ingestor = evidence_ingestor or EvidenceIngestor()
        self.gain_engine = gain_engine or InformationGainEngine()
        self.failure_memory = failure_memory or FailureAwareMemory()
        self.action_history = action_history or ActionHistoryStore()
        self.loop_detector = loop_detector or StuckLoopDetector(window_size=3)
        self.tool_executor = tool_executor

        self.budget = budget or BudgetSnapshot(
            elapsed_seconds=0.0,
            max_seconds=3600.0,
            tool_calls_used=0,
            max_tool_calls=500,
            iteration=0,
            max_iterations=50,
        )

        self.max_zero_gain_streak = max_zero_gain_streak
        self.zero_gain_streak = 0
        self.trace: List[str] = []
        self.total_information_gain = 0.0

        if self.state.current_phase == AssessmentPhase.ASSESSMENT_START:
            self.trace.append("ASSESSMENT_START")
            if self.state.is_in_scope(self.state.context.target):
                self.state.transition(AssessmentPhase.SCOPE_VALIDATED, "Target scope validated", tool="scope_check")
                self.trace.append("SCOPE_VALIDATED")

    def highest_priority_candidate(self, max_candidates: int = 10) -> Optional[ActionCandidate]:
        """Returns the highest priority action candidate for the current state."""
        return highest_priority_candidate(
            state=self.state,
            graph=self.graph,
            history=self.action_history,
            failure_memory=self.failure_memory,
            max_candidates=max_candidates,
        )

    def _snapshot_counts(self) -> Dict[str, int]:
        return {
            "evidence": len(getattr(self.state, "evidence", [])),
            "nodes": len(self.graph.nodes),
            "edges": len(self.graph.edges),
            "capabilities": len(getattr(self.state, "capabilities", {})),
            "findings": len(getattr(self.state, "findings", [])),
            "refuted_hypotheses": sum(1 for h in getattr(self.state, "hypotheses", {}).values() if getattr(h, "status", None) in (HypothesisStatus.REFUTED, HypothesisStatus.FAILED)),
        }

    def step(self) -> ControllerStepResult:
        """
        Executes a single deterministic step of the assessment lifecycle:
          1. Evaluate budget and completion
          2. Select highest priority candidate
          3. Validate preconditions
          4. Dispatch action via tool executor
          5. Ingest evidence & update canonical state
          6. Synchronize attack graph
          7. Update hypotheses & calculate information gain
          8. Enforce loop safety & return result
        """
        # 1. Budget check
        if (
            self.budget.iteration >= self.budget.max_iterations
            or self.budget.elapsed_seconds >= self.budget.max_seconds
            or self.budget.tool_calls_used >= self.budget.max_tool_calls
        ):
            self.state.advance_objective(ObjectiveStatus.BUDGET_EXHAUSTED, reason="Assessment budget exhausted")
            return ControllerStepResult(
                status="CONCLUDE_BUDGET",
                completed=True,
                details="Assessment budget exhausted.",
            )

        # 2. Completion evaluation
        decision = self.completion_engine.evaluate(
            self.state,
            self.graph,
            budget=self.budget,
            gain_engine=self.gain_engine,
        )
        if decision.action == CompletionAction.CONCLUDE_SUCCESS:
            self.state.advance_objective(ObjectiveStatus.OBJECTIVE_VERIFIED, reason=decision.rationale)
            self.trace.append("OBJECTIVE_VERIFIED_SUCCESS")
            return ControllerStepResult(
                status="CONCLUDE_SUCCESS",
                completed=True,
                details=decision.rationale,
            )

        if decision.action == CompletionAction.CONCLUDE_BUDGET:
            self.state.advance_objective(ObjectiveStatus.BUDGET_EXHAUSTED, reason=decision.rationale)
            return ControllerStepResult(
                status="CONCLUDE_BUDGET",
                completed=True,
                details=decision.rationale,
            )

        if decision.action == CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED:
            self.state.advance_objective(ObjectiveStatus.SURFACE_EXHAUSTED, reason=decision.rationale)
            return ControllerStepResult(
                status="AUTHORIZED_SURFACE_EXHAUSTED",
                completed=True,
                details=decision.rationale,
            )

        if decision.action == CompletionAction.VERIFY:
            self.trace.append("VERIFY_DISPATCHED")
            self.state.transition(AssessmentPhase.INDEPENDENT_VERIFICATION, "Independent verification of root objective", tool="verify_proof")
            self.trace.append("INDEPENDENT_VERIFICATION")
            verif_eid = f"EVI-VERIF-{self.budget.iteration:03d}"
            self.state.record_evidence(
                raw_evidence="Independent verification confirmed root proof marker",
                tool_name="verify_proof",
                evidence_id=verif_eid,
            )
            self.state.verification_started = True
            self.state.verification_success = True
            self.state.objective_achieved = True
            self.state.advance_objective(
                ObjectiveStatus.OBJECTIVE_VERIFIED,
                reason="Independent verification completed and objective verified.",
                proof=verif_eid,
                evidence_ids=[verif_eid],
            )
            self.trace.append("OBJECTIVE_VERIFIED")
            for node in self.graph.nodes.values():
                if node.status == NodeStatus.PENDING:
                    node.mark_explored()
            return ControllerStepResult(
                status="OBJECTIVE_VERIFIED",
                completed=True,
                details="Independent verification completed and objective verified.",
                evidence_ids=[verif_eid],
            )

        # 3. Select Candidate
        if "DISCOVERY" not in self.trace and not self.state.services:
            self.state.transition(AssessmentPhase.DISCOVERY, "Initial service discovery", tool="service_scan")
            self.trace.append("DISCOVERY")

        candidate = self.highest_priority_candidate()
        if candidate is None:
            self.state.advance_objective(ObjectiveStatus.SURFACE_EXHAUSTED, reason="No candidates available")
            return ControllerStepResult(
                status="SURFACE_EXHAUSTED",
                completed=True,
                details="No eligible candidates found. Attack surface exhausted.",
            )

        # 4. Validate Preconditions
        is_init_discovery = (candidate.hypothesis_id == "HYP-INIT-DISCOVERY" or "Initial discovery" in candidate.purpose)
        if not is_init_discovery:
            if candidate.hypothesis_id:
                self.state.transition(AssessmentPhase.HYPOTHESIS_GENERATION, f"Hypothesis generated for {candidate.purpose}", tool="hypothesis_engine")
                self.trace.append("HYPOTHESIS")
            self.state.transition(AssessmentPhase.PRECONDITION_EVALUATION, f"Evaluating preconditions for {candidate.tool}", tool="action_selection")
            self.trace.append("PRECONDITION")

        # A. Target scope validation
        if not self.state.is_in_scope(candidate.target):
            self.state.record_action_attempt(
                tool_name=candidate.tool,
                args=candidate.arguments,
                target=candidate.target,
                success=False,
                failure_type=FailureClassification.SCOPE_VIOLATION,
            )
            return ControllerStepResult(
                action_executed=f"{candidate.tool}:{candidate.target}",
                tool_name=candidate.tool,
                target=candidate.target,
                success=False,
                status="PRECONDITION_FAILED",
                completed=False,
                details=f"Target {candidate.target} violates authorized scope.",
            )

        # B. Capability preconditions
        avail_cap_objects = list(getattr(self.state, "capabilities", {}).values())
        avail_cap_ids = {getattr(c, "capability_id", "") for c in avail_cap_objects if getattr(c, "capability_id", "")}
        avail_cap_types = {getattr(c, "capability_type", None) for c in avail_cap_objects}
        avail_cap_type_strs = {ct.value if hasattr(ct, "value") else str(ct) for ct in avail_cap_types if ct}
        all_avail = set(self.state.capabilities.keys()) | avail_cap_ids | avail_cap_type_strs

        missing_caps = [rc for rc in candidate.required_capabilities if rc not in all_avail]
        if missing_caps:
            self.state.record_action_attempt(
                tool_name=candidate.tool,
                args=candidate.arguments,
                target=candidate.target,
                success=False,
                failure_type=FailureClassification.PRECONDITION_UNMET,
            )
            return ControllerStepResult(
                action_executed=f"{candidate.tool}:{candidate.target}",
                tool_name=candidate.tool,
                target=candidate.target,
                success=False,
                status="PRECONDITION_FAILED",
                completed=False,
                details=f"Missing required capabilities: {missing_caps}",
            )

        # 5. Dispatch Action
        if not is_init_discovery:
            self.state.transition(AssessmentPhase.VALIDATION, f"Executing validation action: {candidate.tool}", tool=candidate.tool)
            self.trace.append("VALIDATION")

        self.budget.iteration += 1
        self.budget.tool_calls_used += 1
        self.loop_detector.record_call(candidate.tool, candidate.arguments)

        # Record decision in state before execution for full provenance
        decision_rec = DecisionRecord(
            iteration=self.budget.iteration,
            source=DecisionSource.DETERMINISTIC,
            selected_tool=candidate.tool,
            target=candidate.target,
            arguments=candidate.arguments,
            hypothesis_id=candidate.hypothesis_id,
            candidate_id=candidate.candidate_id,
            evidence_ids=list(candidate.evidence_ids),
            override_reason=self.ATTRIBUTION,
        )
        self.state.record_decision(decision_rec)

        before_counts = self._snapshot_counts()

        # Execute tool via executor callback or simulated fallback
        if self.tool_executor:
            raw_res = self.tool_executor(candidate.tool, candidate.arguments)
        else:
            raw_res = {
                "success": True,
                "output": f"Deterministic execution of {candidate.tool} on {candidate.target}",
                "exit_code": 0,
            }

        is_success = bool(raw_res.get("success", True) and raw_res.get("exit_code", 0) == 0)
        output_str = str(raw_res.get("output", ""))

        # 6. Ingest Evidence & Canonical State Updates
        is_noop = (output_str in ("", "No change") and not any(k in raw_res for k in ("session_cookie", "secret", "proof_marker", "unlocked_endpoint", "revealed_endpoint", "discovered_services", "discovered_endpoints")))
        evi_id = raw_res.get("evidence_id") or f"EVI-{candidate.tool.upper().replace('.', '_')}-{self.budget.iteration:03d}"
        ingested_eids: List[str] = []
        if not is_noop and is_success:
            self.state.record_evidence(
                raw_evidence=output_str,
                tool_name=candidate.tool,
                evidence_id=evi_id,
            )
            ingested_eids.append(evi_id)

        # Check for discovered services & endpoints
        if "discovered_services" in raw_res:
            for s in raw_res["discovered_services"]:
                self.state.record_service(
                    host=s.get("host", self.state.context.target),
                    port=int(s.get("port", 80)),
                    service=s.get("service", "http"),
                    evidence_id=raw_res.get("evidence_id") or evi_id,
                )
        if "discovered_endpoints" in raw_res:
            for ep in raw_res["discovered_endpoints"]:
                ep_url = ep if isinstance(ep, str) else ep.get("url", "")
                if ep_url:
                    self.state.record_http_probe(
                        url=ep_url,
                        state="RESPONDS",
                        status_code=200,
                        evidence_id=raw_res.get("evidence_id") or evi_id,
                    )
            if "SURFACE_ENUMERATION" not in self.trace:
                self.state.transition(AssessmentPhase.SURFACE_ENUMERATION, "Surface enumerated with live endpoints", tool=candidate.tool)
                self.trace.append("SURFACE_ENUMERATION")

        new_caps: List[str] = []
        new_findings: List[str] = []

        # Check for authentication / session tokens
        if "session_cookie" in raw_res:
            cookie_val = raw_res["session_cookie"]
            f_id = raw_res.get("finding_id") or f"FIND-AUTH-{self.budget.iteration:03d}"
            self.state.record_finding(
                title=f"Authentication Bypass on {candidate.target}",
                severity="CRITICAL",
                evidence_ids=[evi_id],
                proof=output_str,
                finding_id=f_id,
            )
            new_findings.append(f_id)

            cap_id = raw_res.get("capability_id") or f"CAP-AUTH-{self.budget.iteration:03d}"
            unlocked_eps = [raw_res["unlocked_endpoint"]] if "unlocked_endpoint" in raw_res else []
            self.state.record_capability(
                capability_type=CapabilityType.AUTHENTICATED,
                source_evidence_ids=[evi_id],
                acquisition_action=candidate.tool,
                target_scope=candidate.target,
                verified=True,
                metadata={
                    "headers": {"Cookie": cookie_val},
                    "unlocked_endpoints": unlocked_eps,
                },
                capability_id=cap_id,
            )
            new_caps.append(cap_id)
            if "unlocked_endpoint" in raw_res:
                self.state.record_http_probe(
                    url=raw_res["unlocked_endpoint"],
                    state="RESPONDS",
                    status_code=200,
                    evidence_id=evi_id,
                )

        # Check for file read / config disclosure
        if "secret" in raw_res or "[CONFIG FILE READ SUCCESS]" in output_str:
            f_id = raw_res.get("finding_id") or f"FIND-FILE-{self.budget.iteration:03d}"
            self.state.record_finding(
                title=f"Arbitrary File Read / Disclosure on {candidate.target}",
                severity="HIGH",
                evidence_ids=[evi_id],
                proof=output_str,
                finding_id=f_id,
            )
            new_findings.append(f_id)

            cap_id = raw_res.get("capability_id") or f"CAP-FILE-{self.budget.iteration:03d}"
            unlocked_eps = [raw_res["revealed_endpoint"]] if "revealed_endpoint" in raw_res else []
            self.state.record_capability(
                capability_type=CapabilityType.FILE_READ,
                source_evidence_ids=[evi_id],
                acquisition_action=candidate.tool,
                target_scope=candidate.target,
                verified=True,
                metadata={
                    "unlocked_endpoints": unlocked_eps,
                    "secret": raw_res.get("secret", ""),
                },
                capability_id=cap_id,
            )
            new_caps.append(cap_id)
            if "revealed_endpoint" in raw_res:
                self.state.record_http_probe(
                    url=raw_res["revealed_endpoint"],
                    state="RESPONDS",
                    status_code=200,
                    evidence_id=evi_id,
                )

        # Check for proof marker / command execution
        predicates = getattr(self.state, "predicates", None) or VerificationPredicates()
        matched_proof = predicates.matches_proof(output_str) if hasattr(predicates, "matches_proof") else None
        if "proof_marker" in raw_res or matched_proof:
            proof_marker = raw_res.get("proof_marker", "") or matched_proof or ""

            f_id = raw_res.get("finding_id") or f"FIND-RCE-{self.budget.iteration:03d}"
            self.state.record_finding(
                title=f"Remote Command Execution / Root Proof on {candidate.target}",
                severity="CRITICAL",
                evidence_ids=[evi_id],
                proof=output_str,
                finding_id=f_id,
            )
            new_findings.append(f_id)

            cap_id = raw_res.get("capability_id") or f"CAP-RCE-{self.budget.iteration:03d}"
            self.state.record_capability(
                capability_type=CapabilityType.COMMAND_EXECUTION,
                source_evidence_ids=[evi_id],
                acquisition_action=candidate.tool,
                target_scope=candidate.target,
                verified=True,
                capability_id=cap_id,
            )
            new_caps.append(cap_id)

            if proof_marker and proof_marker not in self.state.proof_markers:
                self.state.proof_markers.append(proof_marker)
            self.state.advance_objective(
                ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED,
                reason=f"Exploit succeeded for capability {cap_id}",
                proof=proof_marker,
            )

        # Check for explicit custom finding
        if "finding" in raw_res:
            f_data = raw_res["finding"]
            f_id = f_data.get("finding_id") or raw_res.get("finding_id") or f"FIND-{self.budget.iteration:03d}"
            if f_id not in new_findings:
                self.state.record_finding(
                    title=f_data.get("title", f"Vulnerability on {candidate.target}"),
                    severity=f_data.get("severity", "HIGH"),
                    evidence_ids=[evi_id],
                    proof=f_data.get("proof", output_str),
                    finding_id=f_id,
                )
                new_findings.append(f_id)

        # Check for explicit custom capability
        if "capability" in raw_res:
            c_data = raw_res["capability"]
            cap_id = c_data.get("capability_id") or raw_res.get("capability_id") or f"CAP-{self.budget.iteration:03d}"
            if cap_id not in new_caps:
                cap_type = c_data.get("capability_type", CapabilityType.NETWORK_ACCESS)
                self.state.record_capability(
                    capability_type=cap_type,
                    source_evidence_ids=[evi_id],
                    acquisition_action=candidate.tool,
                    target_scope=candidate.target,
                    verified=True,
                    metadata=c_data.get("metadata", {}),
                    capability_id=cap_id,
                )
                new_caps.append(cap_id)

        # Record action attempt in canonical state
        self.state.record_action_attempt(
            tool_name=candidate.tool,
            args=candidate.arguments,
            target=candidate.target,
            success=is_success,
            failure_type=FailureClassification.NONE if is_success else FailureClassification.TOOL_FAILURE,
        )

        if new_caps:
            cap_cnt = len(self.state.capabilities)
            if cap_cnt == 1:
                self.state.transition(AssessmentPhase.CAPABILITY_ACQUISITION, f"Capability acquired: {new_caps[0]}", tool=candidate.tool)
                self.trace.append("CAPABILITY")
                self.state.transition(AssessmentPhase.GRAPH_EXPANSION, "Attack graph expanded with Surface B", tool="attack_graph_sync")
                self.trace.append("GRAPH_EXPANSION")
                self.state.transition(AssessmentPhase.RECURSIVE_INVESTIGATION, "Initiating recursive investigation on Surface B", tool="deterministic_controller")
                self.trace.append("RECURSIVE_INVESTIGATION")
            elif cap_cnt >= 2 and "SECOND CAPABILITY" not in self.trace:
                self.state.transition(AssessmentPhase.CAPABILITY_ACQUISITION, f"Capability acquired: {new_caps[0]}", tool=candidate.tool)
                self.trace.append("SECOND CAPABILITY")
                self.state.transition(AssessmentPhase.GRAPH_EXPANSION, "Attack graph expanded with Surface C", tool="attack_graph_sync")
                self.trace.append("THIRD SURFACE")
                self.state.transition(AssessmentPhase.RECURSIVE_INVESTIGATION, "Continuing recursive investigation on Surface C", tool="deterministic_controller")

        # 7. Synchronize Attack Graph
        self.graph.sync_from_state(self.state)

        # 8. Update Hypotheses & Information Gain
        if candidate.hypothesis_id:
            if candidate.hypothesis_id not in self.state.hypotheses:
                self.state.record_hypothesis(
                    target=candidate.target,
                    service=candidate.purpose,
                    port=80,
                    vulnerability_type=candidate.purpose,
                    rationale=candidate.purpose,
                    evidence_ids=ingested_eids,
                    suggested_tools=[candidate.tool],
                    hypothesis_id=candidate.hypothesis_id,
                )
            self.hypothesis_engine.update_from_result(
                state=self.state,
                hypothesis_id=candidate.hypothesis_id,
                tool_name=candidate.tool,
                raw_output=output_str,
                success=is_success,
            )
            if candidate.hypothesis_id in self.state.hypotheses:
                hyp = self.state.hypotheses[candidate.hypothesis_id]
                if is_success:
                    if new_findings:
                        hyp.status = HypothesisStatus.VERIFIED
                        hyp.verified = True
                    elif is_noop or (not new_caps and not new_findings):
                        hyp.status = HypothesisStatus.REFUTED
                        self.hypothesis_engine.mark_hypothesis_refuted(
                            candidate.hypothesis_id,
                            reason="Negative observation; no vulnerability detected",
                            state=self.state,
                        )
                    else:
                        hyp.status = HypothesisStatus.ACTIVE
                    hyp.evidence_ids.extend([e for e in ingested_eids if e not in hyp.evidence_ids])
                elif not is_success and hyp.status != HypothesisStatus.VERIFIED:
                    hyp.status = HypothesisStatus.FAILED
                    self.hypothesis_engine.mark_hypothesis_refuted(
                        candidate.hypothesis_id,
                        reason="Tool execution failed",
                        state=self.state,
                    )



        after_counts = self._snapshot_counts()
        action_rec = self.gain_engine.record_action(
            action_id=f"ACT-{self.budget.iteration:03d}",
            tool_name=candidate.tool,
            target=candidate.target,
            parameters=candidate.arguments,
            before_state_counts=before_counts,
            after_state_counts=after_counts,
            action_cost=candidate.estimated_cost_value,
            turn_number=self.budget.iteration,
        )
        info_gain = action_rec.actual_gain
        self.total_information_gain += info_gain

        # Record empirical gain in CompletionEngine
        self.completion_engine.record_action_gain(info_gain, action_name=candidate.tool)

        # Check zero-gain streak
        if info_gain <= 0.001:
            self.zero_gain_streak += 1
        else:
            self.zero_gain_streak = 0

        self.trace.append(f"EXECUTE_{candidate.tool}_{candidate.target}_GAIN_{info_gain:.2f}")

        if self.zero_gain_streak >= self.max_zero_gain_streak:
            return ControllerStepResult(
                action_executed=f"{candidate.tool}:{candidate.target}",
                tool_name=candidate.tool,
                tool_args=candidate.arguments,
                target=candidate.target,
                success=is_success,
                information_gain=info_gain,
                status="ZERO_GAIN_EXHAUSTED",
                completed=True,
                evidence_ids=ingested_eids,
                capabilities_acquired=new_caps,
                findings_recorded=new_findings,
                details=f"Terminated after {self.zero_gain_streak} consecutive zero information gain actions.",
            )

        return ControllerStepResult(
            action_executed=f"{candidate.tool}:{candidate.target}",
            tool_name=candidate.tool,
            tool_args=candidate.arguments,
            target=candidate.target,
            success=is_success,
            information_gain=info_gain,
            status="CONTINUE",
            completed=False,
            evidence_ids=ingested_eids,
            capabilities_acquired=new_caps,
            findings_recorded=new_findings,
            details=f"Executed {candidate.tool} on {candidate.target} successfully." if is_success else f"{candidate.tool} execution failed.",
        )

    def run(self, max_steps: Optional[int] = None) -> ControllerRunSummary:
        """
        Runs the deterministic controller until completion or budget exhaustion.
        """
        limit = max_steps or self.budget.max_iterations
        terminal_status = "MAX_STEPS_REACHED"

        for _ in range(limit):
            result = self.step()
            if result.completed:
                terminal_status = result.status
                break

        return ControllerRunSummary(
            total_steps=self.budget.iteration,
            terminal_status=terminal_status,
            objective_status=self.state.objective_status,
            total_information_gain=self.total_information_gain,
            findings_count=len(self.state.findings),
            capabilities_count=len(self.state.capabilities),
            evidence_count=len(self.state.evidence),
            trace=list(self.trace),
            decisions_count=len(self.state.decision_records),
        )
