"""
Completion Engine — Evidence-driven, budget-aware assessment lifecycle controller.

Authority: The ONLY component that may authorize assessment termination.

Design rules (per architectural directive):
  1. The LLM NEVER decides when the assessment is complete.
  2. LoopRecoveryController detects repetitive/stagnant strategies and recommends
     alternatives. CompletionEngine determines whether the lifecycle may terminate.
     They cooperate but do NOT duplicate.
  3. Stagnation -> strategy recovery (PIVOT), not termination.
     Termination requires proof that no authorized work remains or budget is truly exhausted.
  4. A finding MUST NOT terminate the assessment -- it creates new work.
  5. AssessmentMode controls termination policy:
       TARGETED:   objective verified -> may terminate (after graph exhaustion check)
       EXHAUSTIVE: objective verified -> continue until full authorized surface covered

CompletionDecision.action values:
  CONTINUE                  -> Assessment must continue; engine provides a corrective prompt
  VERIFY                    -> Exploitation succeeded; independent verification required
  PIVOT                     -> Stagnation detected; diversify strategy before continuing
  CONCLUDE_SUCCESS          -> All objectives met, graph exhausted, mode allows termination
  CONCLUDE_BUDGET           -> Budget genuinely exhausted; terminate with current findings
  AUTHORIZED_SURFACE_EXHAUSTED -> EXHAUSTIVE mode: all authorized surface fully covered
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    ObjectiveStatus,
    ServiceState,
    HypothesisStatus,
    VerificationPredicates,
)
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import (
    HypothesisEngine,
    HypothesisProposal,
    ProposalConfidence,
)


# ---------------------------------------------------------------------------
# Assessment mode
# ---------------------------------------------------------------------------

class AssessmentMode(str, Enum):
    TARGETED   = "TARGETED"    # Stop after primary objective verified
    EXHAUSTIVE = "EXHAUSTIVE"  # Continue until all authorized surface covered


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------

class CompletionAction(str, Enum):
    CONTINUE                     = "CONTINUE"
    VERIFY                       = "VERIFY"
    PIVOT                        = "PIVOT"
    CONCLUDE_SUCCESS             = "CONCLUDE_SUCCESS"
    CONCLUDE_BUDGET              = "CONCLUDE_BUDGET"
    AUTHORIZED_SURFACE_EXHAUSTED = "AUTHORIZED_SURFACE_EXHAUSTED"


@dataclass
class CompletionDecision:
    """
    Typed decision returned by CompletionEngine.evaluate().
    The AgentLoop must respect this unconditionally.
    """
    action: CompletionAction
    rationale: str
    continuation_prompt: Optional[str] = None
    next_proposal: Optional[HypothesisProposal] = None
    graph_summary: str = ""
    pivot_strategies: List[str] = field(default_factory=list)
    evaluated_at: float = field(default_factory=time.time)

    @property
    def should_continue(self) -> bool:
        return self.action in (CompletionAction.CONTINUE, CompletionAction.PIVOT)

    @property
    def requires_verification(self) -> bool:
        return self.action == CompletionAction.VERIFY

    @property
    def should_conclude(self) -> bool:
        return self.action in (
            CompletionAction.CONCLUDE_SUCCESS,
            CompletionAction.CONCLUDE_BUDGET,
            CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "rationale": self.rationale,
            "continuation_prompt": self.continuation_prompt,
            "next_proposal": self.next_proposal.to_dict() if self.next_proposal else None,
            "pivot_strategies": self.pivot_strategies,
            "evaluated_at": self.evaluated_at,
        }


# ---------------------------------------------------------------------------
# Budget snapshot
# ---------------------------------------------------------------------------

@dataclass
class BudgetSnapshot:
    """Lightweight snapshot of current budget state."""
    elapsed_seconds: float = 0.0
    max_seconds: float = 3600.0
    tool_calls_used: int = 0
    max_tool_calls: int = 500
    iteration: int = 0
    max_iterations: int = 40

    @property
    def time_pct(self) -> float:
        return (self.elapsed_seconds / self.max_seconds * 100) if self.max_seconds else 0.0

    @property
    def tool_call_pct(self) -> float:
        return (self.tool_calls_used / self.max_tool_calls * 100) if self.max_tool_calls else 0.0

    @property
    def iteration_pct(self) -> float:
        return (self.iteration / self.max_iterations * 100) if self.max_iterations else 0.0

    @property
    def is_budget_critical(self) -> bool:
        return any([self.time_pct >= 90, self.tool_call_pct >= 90, self.iteration_pct >= 90])

    @property
    def is_budget_exhausted(self) -> bool:
        return any([
            self.elapsed_seconds >= self.max_seconds,
            self.tool_calls_used >= self.max_tool_calls,
            self.iteration >= self.max_iterations,
        ])


# ---------------------------------------------------------------------------
# Completion Engine
# ---------------------------------------------------------------------------

class CompletionEngine:
    """
    Evidence-driven assessment lifecycle controller.

    Cooperates with LoopRecoveryController:
      - LoopRecoveryController: detects repetitive tool use, recommends strategy pivots
      - CompletionEngine:       decides whether the assessment lifecycle may END

    Neither component duplicates the other's responsibility.
    """

    STAGNATION_PIVOT_THRESHOLD = 4
    MAX_PIVOT_CYCLES = 3

    def __init__(
        self,
        hypothesis_engine: Optional[HypothesisEngine] = None,
        mode: AssessmentMode = AssessmentMode.TARGETED,
        zero_gain_threshold: int = 4,
        min_progress_gain: float = 0.05,
        rolling_window_size: int = 5,
        gain_engine: Optional[Any] = None,
    ) -> None:
        self.hypothesis_engine = hypothesis_engine or HypothesisEngine()
        self.mode = mode
        self.zero_gain_threshold = zero_gain_threshold
        self.min_progress_gain = min_progress_gain
        self.rolling_window_size = rolling_window_size
        self.gain_engine = gain_engine

        self.zero_gain_streak: int = 0
        self.useful_action_count: int = 0
        self.total_actions_evaluated: int = 0
        self.recent_gains: List[float] = []

        self._stagnation_counter: int = 0
        self._pivot_counter: int = 0
        self._last_state_version: int = -1
        self._last_graph_pending: int = -1

    def record_action_gain(self, gain: float, action_name: str = "") -> None:
        """
        Records the empirical information gain of an action and updates
        rolling metrics and zero_gain_streak.
        """
        self.total_actions_evaluated += 1
        self.recent_gains.append(gain)
        if len(self.recent_gains) > self.rolling_window_size:
            self.recent_gains.pop(0)

        if gain > self.min_progress_gain:
            self.zero_gain_streak = 0
            self.useful_action_count += 1
            self._stagnation_counter = 0
        else:
            self.zero_gain_streak += 1

    @property
    def rolling_information_gain(self) -> float:
        """Returns the rolling mean information gain across the recent window."""
        if not self.recent_gains:
            return 0.0
        return sum(self.recent_gains) / len(self.recent_gains)

    @property
    def useful_action_rate(self) -> float:
        """Proportion of evaluated actions that yielded useful information gain."""
        if self.total_actions_evaluated == 0:
            return 0.0
        return self.useful_action_count / self.total_actions_evaluated

    def sync_information_gain(
        self,
        state: Optional[AssessmentState] = None,
        gain_engine: Optional[Any] = None,
    ) -> None:
        """
        Synchronizes information gain signals from an InformationGainEngine
        or canonical state.information_gain_history.
        """
        engine = gain_engine or self.gain_engine
        if engine is not None and hasattr(engine, "action_history") and engine.action_history:
            self.recent_gains = [a.actual_gain for a in engine.action_history[-self.rolling_window_size:]]
            self.total_actions_evaluated = len(engine.action_history)
            self.useful_action_count = sum(1 for a in engine.action_history if a.actual_gain > self.min_progress_gain)

            streak = 0
            for a in reversed(engine.action_history):
                if a.actual_gain <= self.min_progress_gain:
                    streak += 1
                else:
                    break
            self.zero_gain_streak = streak
            return

        if state is not None and getattr(state, "information_gain_history", None):
            history = state.information_gain_history
            self.recent_gains = [item.get("gain", 0.0) for item in history[-self.rolling_window_size:]]
            self.total_actions_evaluated = len(history)
            self.useful_action_count = sum(1 for item in history if item.get("gain", 0.0) > self.min_progress_gain)

            streak = 0
            for item in reversed(history):
                if item.get("gain", 0.0) <= self.min_progress_gain:
                    streak += 1
                else:
                    break
            self.zero_gain_streak = streak

    # ------------------------------------------------------------------
    # Primary evaluation interface
    # ------------------------------------------------------------------

    def evaluate(
        self,
        state: AssessmentState,
        graph: AttackGraph,
        budget: BudgetSnapshot,
        content: str = "",
        observations: Optional[List[str]] = None,
        task_goal: str = "",
        target: str = "",
        gain_engine: Optional[Any] = None,
        current_gain: Optional[float] = None,
    ) -> CompletionDecision:
        """
        Evaluates the assessment lifecycle. Returns a CompletionDecision.
        Gate priority order:
          1. Budget exhausted       -> CONCLUDE_BUDGET
          2. Verification required  -> VERIFY
          3. Cold start             -> CONTINUE
          4. Objective verified     -> mode-dependent
          5. Uninvestigated svcs    -> CONTINUE
          6. High-conf proposals    -> CONTINUE
          7. Offensive goal no proof-> CONTINUE
          8. Graph pending nodes    -> CONTINUE
          9. Stagnation / Zero Gain -> PIVOT / CONCLUDE / SURFACE_EXHAUSTED
          10. Budget critical       -> CONCLUDE_BUDGET
          11. Default               -> CONTINUE / AUTHORIZED_SURFACE_EXHAUSTED / CONCLUDE_SUCCESS
        """
        observations = observations or []
        goal_lower = task_goal.lower()
        graph_summary = graph.to_summary() if graph else ""

        if current_gain is not None:
            self.record_action_gain(current_gain)
        else:
            self.sync_information_gain(state=state, gain_engine=gain_engine)

        current_state_version = getattr(state, "state_version", 0)
        current_graph_pending = graph.total_unexplored() if graph else 0

        if (current_state_version == self._last_state_version and
                current_graph_pending == self._last_graph_pending):
            self._stagnation_counter += 1
        else:
            self._stagnation_counter = 0
            self._pivot_counter = 0
            self._last_state_version = current_state_version
            self._last_graph_pending = current_graph_pending

        # Gate 1
        if budget.is_budget_exhausted:
            return CompletionDecision(
                action=CompletionAction.CONCLUDE_BUDGET,
                rationale=(
                    f"Budget exhausted: time={budget.elapsed_seconds:.0f}s/"
                    f"{budget.max_seconds:.0f}s, tools={budget.tool_calls_used}/"
                    f"{budget.max_tool_calls}, iter={budget.iteration}/{budget.max_iterations}."
                ),
                graph_summary=graph_summary,
            )

        # Gate 2
        if state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED:
            if not state.verification_started or not state.verification_success:
                if not state.verification_candidates:
                    state.generate_verification_candidates()
                top_ver = state.verification_candidates[0] if state.verification_candidates else None
                prompt = self._build_verification_prompt(state, top_ver, target)
                return CompletionDecision(
                    action=CompletionAction.VERIFY,
                    rationale="Exploitation validated but independent verification not yet performed.",
                    continuation_prompt=prompt,
                    graph_summary=graph_summary,
                )

        # Gate 3
        if len(observations) == 0 and budget.iteration <= 3:
            return CompletionDecision(
                action=CompletionAction.CONTINUE,
                rationale="No observations recorded. Assessment just started.",
                continuation_prompt=(
                    f"Assessment not yet started. Execute service discovery: "
                    f"nmap_scan(host='{target}', ports='1-10000')."
                ),
                graph_summary=graph_summary,
            )

        # Gate 4
        if state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED:
            if self.mode == AssessmentMode.TARGETED:
                # In TARGETED mode: verified objective overrides exploration when
                # no unexplored work remains OR information gain has ceased (zero_gain_streak >= 1)
                # OR budget is critical.
                if not graph.has_unexplored_work() or self.zero_gain_streak >= 1 or budget.is_budget_critical:
                    return CompletionDecision(
                        action=CompletionAction.CONCLUDE_SUCCESS,
                        rationale=(
                            "TARGETED mode: objective verified. Search concluded without redundant exploration. "
                            f"Findings: {len(state.findings)}."
                        ),
                        graph_summary=graph_summary,
                    )
                proposals = self.hypothesis_engine.propose_next_actions(state, graph, max_proposals=3)
                top = proposals[0] if proposals else None
                prompt = self._build_continuation_prompt(state, top, task_goal, target, "post-exploitation")
                return CompletionDecision(
                    action=CompletionAction.CONTINUE,
                    rationale=(
                        f"TARGETED mode: objective verified but {graph.total_unexplored()} "
                        "unexplored node(s) remain."
                    ),
                    continuation_prompt=prompt,
                    next_proposal=top,
                    graph_summary=graph_summary,
                )
            else:
                # EXHAUSTIVE
                if not graph.has_unexplored_work():
                    uninvestigated = [
                        s for s in state.services.values()
                        if s.state == ServiceState.OPEN and not s.investigated
                    ]
                    if not uninvestigated:
                        return CompletionDecision(
                            action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                            rationale=(
                                "EXHAUSTIVE mode: objective verified and all authorized "
                                f"surface fully covered. Findings: {len(state.findings)}."
                            ),
                            graph_summary=graph_summary,
                        )
                if self.zero_gain_streak >= self.zero_gain_threshold and not graph.has_unexplored_work():
                    return CompletionDecision(
                        action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                        rationale=(
                            f"EXHAUSTIVE mode: zero information gain streak ({self.zero_gain_streak}) "
                            "reached threshold and graph work exhausted."
                        ),
                        graph_summary=graph_summary,
                    )
                proposals = self.hypothesis_engine.propose_next_actions(state, graph, max_proposals=3)
                top = proposals[0] if proposals else None
                prompt = self._build_continuation_prompt(state, top, task_goal, target, "exhaustive surface coverage")
                return CompletionDecision(
                    action=CompletionAction.CONTINUE,
                    rationale=(
                        "EXHAUSTIVE mode: objective verified but authorized surface not fully "
                        f"covered. Remaining: {graph.total_unexplored()} node(s)."
                    ),
                    continuation_prompt=prompt,
                    next_proposal=top,
                    graph_summary=graph_summary,
                )

        # Gate 5
        uninvestigated = [
            s for s in state.services.values()
            if s.state == ServiceState.OPEN and not s.investigated
        ]
        if uninvestigated and budget.iteration < budget.max_iterations - 2:
            proposals = self.hypothesis_engine.propose_next_actions(state, graph, max_proposals=3)
            top = proposals[0] if proposals else None
            prompt = self._build_uninvestigated_prompt(uninvestigated, target, top)
            return CompletionDecision(
                action=CompletionAction.CONTINUE,
                rationale=(
                    f"{len(uninvestigated)} open service(s) not yet investigated: "
                    f"{', '.join(f'{s.port}/{s.protocol}' for s in uninvestigated[:4])}."
                ),
                continuation_prompt=prompt,
                next_proposal=top,
                graph_summary=graph_summary,
            )

        # Gate 6
        proposals = self.hypothesis_engine.propose_next_actions(state, graph, max_proposals=5)
        high_conf = [p for p in proposals if p.confidence == ProposalConfidence.HIGH]
        if high_conf and budget.iteration < budget.max_iterations - 2 and self.zero_gain_streak < self.zero_gain_threshold:
            top = high_conf[0]
            prompt = self._build_continuation_prompt(state, top, task_goal, target, "exploitation")
            return CompletionDecision(
                action=CompletionAction.CONTINUE,
                rationale=(
                    f"High-confidence hypothesis {top.hypothesis_id} "
                    f"({top.vulnerability_type}) has satisfied preconditions."
                ),
                continuation_prompt=prompt,
                next_proposal=top,
                graph_summary=graph_summary,
            )

        # Gate 7
        is_offensive = any(kw in goal_lower for kw in [
            "attack", "compromise", "penetrat", "gain access", "capture flag",
            "exploit", "break auth", "rce", "remote code", "hack",
        ])
        if is_offensive and state.objective_status == ObjectiveStatus.OBJECTIVE_UNREACHED and self.zero_gain_streak < self.zero_gain_threshold:
            all_obs_str = " ".join(observations)
            predicates = getattr(state, "predicates", None)
            proof_markers = getattr(predicates, "proof_markers", None) or getattr(state, "proof_markers", None) or VerificationPredicates().proof_markers
            has_proof = any(
                m in all_obs_str or m in content
                for m in proof_markers
            )
            if not has_proof and budget.iteration < budget.max_iterations - 2:
                medium = [p for p in proposals if p.confidence in (
                    ProposalConfidence.MEDIUM, ProposalConfidence.HIGH
                )]
                top = medium[0] if medium else (proposals[0] if proposals else None)
                prompt = self._build_offensive_continuation_prompt(state, top, target)
                return CompletionDecision(
                    action=CompletionAction.CONTINUE,
                    rationale="Offensive objective not achieved; no proof of compromise.",
                    continuation_prompt=prompt,
                    next_proposal=top,
                    graph_summary=graph_summary,
                )

        # Gate 8
        if graph.has_unexplored_work() and budget.iteration < budget.max_iterations - 2 and self.zero_gain_streak < self.zero_gain_threshold:
            if proposals:
                top = proposals[0]
                prompt = self._build_continuation_prompt(state, top, task_goal, target, "graph exploration")
                return CompletionDecision(
                    action=CompletionAction.CONTINUE,
                    rationale=f"Attack graph has {graph.total_unexplored()} unexplored node(s).",
                    continuation_prompt=prompt,
                    next_proposal=top,
                    graph_summary=graph_summary,
                )

        # Gate 9: Stagnation / Repeated Zero-Gain Actions -> PIVOT or CONCLUDE
        stagnation_or_zero_gain = (
            self._stagnation_counter >= self.STAGNATION_PIVOT_THRESHOLD
            or self.zero_gain_streak >= self.zero_gain_threshold
        )
        if stagnation_or_zero_gain:
            if state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED and self.mode == AssessmentMode.TARGETED:
                return CompletionDecision(
                    action=CompletionAction.CONCLUDE_SUCCESS,
                    rationale=(
                        f"Objective verified and {self.zero_gain_streak} consecutive actions produced "
                        "no new information. Concluding successfully."
                    ),
                    graph_summary=graph_summary,
                )

            surface_exhausted = (
                not graph.has_unexplored_work()
                and not any(s for s in state.services.values() if s.state == ServiceState.OPEN and not s.investigated)
            )

            if surface_exhausted and (self._pivot_counter > 0 or self.zero_gain_streak >= self.zero_gain_threshold):
                return CompletionDecision(
                    action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                    rationale=(
                        f"Authorized surface exhausted: {self.zero_gain_streak} consecutive zero-gain actions "
                        "with no remaining unexplored nodes or uninvestigated services."
                    ),
                    graph_summary=graph_summary,
                )

            self._stagnation_counter = 0
            self._pivot_counter += 1
            strategies = self._generate_pivot_strategies(state, graph, proposals, target)

            if self._pivot_counter > self.MAX_PIVOT_CYCLES or (self.zero_gain_streak >= self.zero_gain_threshold * 2):
                if state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED:
                    return CompletionDecision(
                        action=CompletionAction.CONCLUDE_SUCCESS,
                        rationale=(
                            f"Objective verified and {self.zero_gain_streak} consecutive zero-gain actions. "
                            "Assessment complete."
                        ),
                        graph_summary=graph_summary,
                    )
                return CompletionDecision(
                    action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                    rationale=(
                        f"Repeated zero-gain streak ({self.zero_gain_streak}) persisted across "
                        f"{self._pivot_counter} pivot cycles. Search space exhausted."
                    ),
                    graph_summary=graph_summary,
                )

            pivot_prompt = self._build_pivot_prompt(state, strategies, target, task_goal)
            return CompletionDecision(
                action=CompletionAction.PIVOT,
                rationale=(
                    f"No information gain for {max(self._stagnation_counter, self.zero_gain_streak, self.STAGNATION_PIVOT_THRESHOLD)} "
                    f"iterations (pivot #{self._pivot_counter}). Diversifying strategy."
                ),
                continuation_prompt=pivot_prompt,
                pivot_strategies=strategies,
                graph_summary=graph_summary,
            )

        # Gate 10
        if budget.is_budget_critical and not high_conf:
            return CompletionDecision(
                action=CompletionAction.CONCLUDE_BUDGET,
                rationale=(
                    f"Budget at {budget.time_pct:.0f}%t/{budget.tool_call_pct:.0f}%tc. "
                    "No high-confidence hypotheses remain."
                ),
                graph_summary=graph_summary,
            )

        # Gate 11: default
        if proposals:
            top = proposals[0]
            prompt = self._build_continuation_prompt(state, top, task_goal, target, "assessment continuation")
            return CompletionDecision(
                action=CompletionAction.CONTINUE,
                rationale=f"Medium-confidence proposal available: {top.vulnerability_type}.",
                continuation_prompt=prompt,
                next_proposal=top,
                graph_summary=graph_summary,
            )

        uninvestigated_services = state.get_uninvestigated_services() if hasattr(state, "get_uninvestigated_services") else []
        if not uninvestigated_services and (not graph.has_unexplored_work() or not state.services):
            if self.mode == AssessmentMode.TARGETED:
                if state.objective_status == ObjectiveStatus.OBJECTIVE_VERIFIED:
                    return CompletionDecision(
                        action=CompletionAction.CONCLUDE_SUCCESS,
                        rationale="No unexplored nodes or pending proposals remain. Assessment completed.",
                        graph_summary=graph_summary,
                    )
                else:
                    return CompletionDecision(
                        action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                        rationale="Authorized attack surface exhausted without achieving verified objective.",
                        graph_summary=graph_summary,
                    )
            else:
                return CompletionDecision(
                    action=CompletionAction.AUTHORIZED_SURFACE_EXHAUSTED,
                    rationale="All authorized attack surface fully covered and exhausted.",
                    graph_summary=graph_summary,
                )

        strategies = self._generate_pivot_strategies(state, graph, [], target)
        if strategies:
            pivot_prompt = self._build_pivot_prompt(state, strategies, target, task_goal)
            return CompletionDecision(
                action=CompletionAction.PIVOT,
                rationale="No proposals derivable from current state. Pivoting strategy.",
                continuation_prompt=pivot_prompt,
                pivot_strategies=strategies,
                graph_summary=graph_summary,
            )


        return CompletionDecision(
            action=CompletionAction.CONTINUE,
            rationale="Final attempt before surface-exhaustion check on next iteration.",
            continuation_prompt=(
                f"Continue assessment of {target}. Run additional enumeration to confirm "
                "all services and endpoints have been fully investigated."
            ),
            graph_summary=graph_summary,
        )

    # ------------------------------------------------------------------
    # Surface exhaustion proof (all three conditions must hold)
    # ------------------------------------------------------------------

    def _surface_proven_empty(self, state: AssessmentState, graph: AttackGraph) -> bool:
        no_pending_nodes = not graph.has_unexplored_work()
        no_uninvestigated = not any(
            s for s in state.services.values()
            if s.state == ServiceState.OPEN and not s.investigated
        )
        no_active_hyps = len(state.get_active_hypotheses()) == 0
        return no_pending_nodes and no_uninvestigated and no_active_hyps

    # ------------------------------------------------------------------
    # Pivot strategy generator
    # ------------------------------------------------------------------

    def _generate_pivot_strategies(
        self,
        state: AssessmentState,
        graph: AttackGraph,
        current_proposals: List[HypothesisProposal],
        target: str,
    ) -> List[str]:
        strategies: List[str] = []
        target_host = target.split("://")[-1].split("/")[0].split(":")[0]
        open_ports = state.get_open_ports()

        pending = graph.pending_nodes()
        if pending:
            n = pending[0]
            strategies.append(
                f"Reconsider unresolved graph node [{n.kind.value}] '{n.label}' "
                f"(priority={n.priority}) -- investigate with a direct probe."
            )

        attempted_types = {h.vulnerability_type for h in state.hypotheses.values()}
        all_types = {
            "xss", "lfi", "ssrf", "idor", "command_injection",
            "path_traversal", "open_redirect", "directory_traversal",
            "information_disclosure",
        }
        untried = all_types - attempted_types
        if untried and open_ports:
            vtype = next(iter(untried))
            port = open_ports[0]
            strategies.append(
                f"Alternative hypothesis not yet explored: '{vtype}' on port {port}. "
                f"Probe with a targeted tool."
            )

        http_ports = [
            s.port for s in state.services.values()
            if s.is_http_compatible() and s.state == ServiceState.OPEN
        ]
        if http_ports:
            strategies.append(
                f"Run directory bruteforce on port {http_ports[0]}: "
                f"ffuf_fuzz(url='http://{target_host}:{http_ports[0]}/FUZZ')."
            )

        non_http = [
            s for s in state.services.values()
            if not s.is_http_compatible() and s.state == ServiceState.OPEN and not s.investigated
        ]
        if non_http:
            s = non_http[0]
            strategies.append(
                f"Uninvestigated non-HTTP service: {s.service} on port {s.port}. "
                f"Grab banner: grab_banner(host='{target_host}', port={s.port})."
            )

        strategies.append(
            "Run scan_source_secrets or audit_configurations to identify "
            "credential exposure or misconfiguration."
        )
        return strategies[:4]

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _build_verification_prompt(self, state: AssessmentState, top_ver: Optional[Dict], target: str) -> str:
        val_snippet = state.last_validation_output.strip()[:200] if state.last_validation_output else ""
        ver_block = ""
        if top_ver:
            ver_block = (
                f"\nRequired verification action:\n"
                f"  Tool: {top_ver['tool']}\n"
                f"  Arguments: {top_ver.get('args', {})}\n"
                f"  Expected proof: {top_ver.get('expected_proof', 'ADMIN_STATE / FLAG')}\n"
            )
        return (
            "=== VERIFICATION REQUIRED ===\n"
            f"Validation output:\n  {val_snippet}\n\n"
            f"Objective Status: {state.objective_status.value}\n\n"
            f"You MUST perform independent verification before concluding.\n{ver_block}"
            "============================="
        )

    def _build_uninvestigated_prompt(self, uninvestigated: List, target: str, top: Optional[HypothesisProposal]) -> str:
        target_host = target.split("://")[-1].split("/")[0].split(":")[0]
        lines = [f"ASSESSMENT CONTINUATION REQUIRED: Open services not yet investigated on {target}:"]
        for s in uninvestigated[:6]:
            lines.append(f"  * Port {s.port}/{s.protocol} ({s.service}) [Version: {s.version}]")
        if top:
            lines.append(f"\nNext action:\n  Tool: {top.tool_name}\n  Args: {top.tool_args}\n  Rationale: {top.rationale}")
        else:
            first = uninvestigated[0]
            scheme = "https" if first.port == 443 else "http"
            if hasattr(first, "is_http_compatible") and first.is_http_compatible():
                lines.append(f"\nAction: whatweb_scan(url='{scheme}://{target_host}:{first.port}/')")
            else:
                lines.append(f"\nAction: grab_banner(host='{target_host}', port={first.port})")
        return "\n".join(lines)

    def _build_continuation_prompt(self, state: AssessmentState, proposal: Optional[HypothesisProposal], task_goal: str, target: str, context_label: str = "assessment continuation") -> str:
        open_ports = state.get_open_ports()
        if not proposal:
            return (
                f"Continue assessment of {target}. "
                f"Open ports: {', '.join(map(str, open_ports)) or 'Unknown'}. "
                "Run additional enumeration."
            )
        return (
            f"=== {context_label.upper()} REQUIRED ===\n"
            f"Task: {task_goal}\nTarget: {target}\n\n"
            f"Open ports: {', '.join(map(str, open_ports)) or 'None discovered'}\n"
            f"Verified findings: {len(state.findings)}\n\n"
            f"Next action ({proposal.confidence.value} confidence):\n"
            f"  Hypothesis: {proposal.hypothesis_id} ({proposal.vulnerability_type})\n"
            f"  Tool: {proposal.tool_name}\n"
            f"  Args: {proposal.tool_args}\n"
            f"  Rationale: {proposal.rationale}\n"
            f"  Evidence: {', '.join(proposal.evidence_ids) or 'service discovery'}\n"
            "Execute this action. Do NOT conclude without completing this investigation."
            "\n========================================="
        )

    def _build_offensive_continuation_prompt(self, state: AssessmentState, top: Optional[HypothesisProposal], target: str) -> str:
        open_ports = state.get_open_ports()
        if top:
            next_block = f"\nNext attack action:\n  Tool: {top.tool_name}\n  Args: {top.tool_args}\n  Rationale: {top.rationale}"
        else:
            next_block = f"\nAvailable tools: ffuf_fuzz, sqlmap_attack, brute_force_http, nuclei_scan.\nOpen ports: {', '.join(map(str, open_ports)) or 'Unknown'}"
        return (
            f"TASK NOT COMPLETE. No proof of compromise obtained against {target}.\n"
            f"You are the attacker. Execute an attack tool call now.\n{next_block}"
        )

    def _build_pivot_prompt(self, state: AssessmentState, strategies: List[str], target: str, task_goal: str) -> str:
        strat_lines = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(strategies))
        open_ports = state.get_open_ports()
        unresolved_hyps = [h for h in state.hypotheses.values() if h.status.value not in ("VERIFIED", "REJECTED", "FAILED")]
        return (
            "=== STRATEGY PIVOT REQUIRED ===\n"
            "No information gain in recent iterations. Current approach is exhausted.\n\n"
            f"Target: {target}\nTask: {task_goal}\n"
            f"Open ports: {', '.join(map(str, open_ports)) or 'None confirmed'}\n"
            f"Unresolved hypotheses: {len(unresolved_hyps)}\n"
            f"Verified findings: {len(state.findings)}\n\n"
            "Alternative strategies to explore (select one and execute):\n"
            f"{strat_lines}\n\n"
            "Pick the most promising strategy and execute a concrete tool call now. "
            "Do NOT repeat previous actions."
            "\n==============================="
        )

    # ------------------------------------------------------------------
    # Mode control + metrics
    # ------------------------------------------------------------------

    def set_mode(self, mode: AssessmentMode) -> None:
        self.mode = mode

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "stagnation_counter": self._stagnation_counter,
            "pivot_counter": self._pivot_counter,
            "last_state_version": self._last_state_version,
            "last_graph_pending": self._last_graph_pending,
            "proposals_generated": self.hypothesis_engine._proposals_generated,
            "proposals_executed": self.hypothesis_engine._proposals_executed,
        }

    # ------------------------------------------------------------------
    # Guard: tool-level completion / verification enforcement
    # ------------------------------------------------------------------

    def evaluate_tool_completion(
        self,
        state: Optional[AssessmentState],
        target: str,
        iteration: int,
        max_iterations: int,
        observations: List[str],
        tool_args: Dict[str, Any],
    ) -> "GuardDecision":
        """
        Decides whether a ``complete`` / ``finish_task`` tool call should be
        honoured.  Returns a GuardDecision that tells the loop whether to
        ALLOW the exit, or REJECT it with a continuation prompt.

        Three rejection scenarios:
          1. OBJECTIVE_ACHIEVED_UNVERIFIED → force independent verification.
          2. Open ports + no validation attempted + early iteration → persistence gate.
          3. Otherwise → ALLOW the completion.
        """
        if state is None:
            return GuardDecision(action=GuardAction.ALLOW)

        # Gate 1: Verification required
        if (
            state.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED
            and iteration < max_iterations - 1
        ):
            state.verification_attempts += 1
            candidates = (
                state.verification_candidates
                or state.generate_verification_candidates()
            )
            predicates = getattr(state, "predicates", None) or VerificationPredicates()
            top = candidates[0] if candidates else {
                "tool": "http.request",
                "args": {"method": "GET", "url": f"{target}/admin",
                         "headers": {"Cookie": predicates.default_session_cookie}},
                "expected_proof": " / ".join(predicates.proof_markers[:2]) if predicates.proof_markers else "Proof marker",
            }
            import json as _json
            return GuardDecision(
                action=GuardAction.REJECT_VERIFICATION,
                prompt=(
                    "=== VERIFICATION REQUIRED ===\n"
                    "Completion was REJECTED: VERIFICATION_REQUIRED.\n"
                    "Validation has already succeeded (Objective Status: OBJECTIVE_ACHIEVED_UNVERIFIED).\n"
                    "You must execute independent verification using the authenticated session "
                    "before concluding or generating the final report.\n\n"
                    f"Highest-Priority Verification Action:\n"
                    f"Tool: {top['tool']}\n"
                    f"Arguments: {_json.dumps(top['args'])}\n"
                    f"Expected Proof: {top.get('expected_proof', 'ADMIN_STATE / FLAG')}\n"
                    "============================="
                ),
            )

        # Gate 2: Persistence gate — open ports not yet validated
        open_ports = state.get_open_ports()
        validation_attempted = (
            len(state.exploitation_records) > 0
            or any("FLAG" in obs or "PROOF" in obs for obs in observations)
        )
        if open_ports and not validation_attempted and iteration < 6:
            return GuardDecision(
                action=GuardAction.REJECT_PERSISTENCE,
                prompt=(
                    f"Do not conclude the assessment yet. You have discovered active services "
                    f"on port(s) {open_ports}. Form a vulnerability hypothesis and execute "
                    f"validation actions (e.g. web_fetch on endpoints, http.request, sqlmap_attack) "
                    f"to verify potential vulnerabilities and extract proof of compromise before "
                    f"generating the final report."
                ),
            )

        # No gate triggered
        return GuardDecision(action=GuardAction.ALLOW)

    def evaluate_verification_gate(
        self,
        state: Optional[AssessmentState],
        tool_name: str,
        tool_args: Dict[str, Any],
        target: str,
        iteration: int,
        max_iterations: int,
    ) -> "GuardDecision":
        """
        Phase 6F: Verification Action Enforcement.

        When the objective is OBJECTIVE_ACHIEVED_UNVERIFIED, only genuine
        verification actions (e.g. authenticated admin endpoint probes) are
        allowed through.  All other tool calls are rejected with a guidance
        prompt.
        """
        if state is None:
            return GuardDecision(action=GuardAction.ALLOW)
        if state.objective_status != ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED:
            return GuardDecision(action=GuardAction.ALLOW)

        # Check if this tool call IS a verification action
        is_ver_action = False
        if tool_name in ("http.request", "curl_probe", "web_fetch", "http_probe"):
            url_val = str(tool_args.get("url", ""))
            headers_val = tool_args.get("headers", {})
            if (
                any(ep in url_val for ep in ("/admin", "/flag", "/dashboard"))
                or "session=" in str(headers_val)
                or "session" in str(tool_args)
            ):
                is_ver_action = True

        if not is_ver_action and iteration < max_iterations - 1:
            state.verification_attempts += 1
            candidates = (
                state.verification_candidates
                or state.generate_verification_candidates()
            )
            predicates = getattr(state, "predicates", None) or VerificationPredicates()
            top = candidates[0] if candidates else {
                "tool": "http.request",
                "args": {"method": "GET", "url": f"{target}/admin",
                         "headers": {"Cookie": predicates.default_session_cookie}},
                "expected_proof": " / ".join(predicates.proof_markers[:2]) if predicates.proof_markers else "Proof marker",
            }
            import json as _json
            return GuardDecision(
                action=GuardAction.REJECT_VERIFICATION,
                prompt=(
                    "=== VERIFICATION REQUIRED ===\n"
                    f"Action '{tool_name}' was REJECTED: VERIFICATION_REQUIRED.\n"
                    "Validation has already succeeded (Objective Status: OBJECTIVE_ACHIEVED_UNVERIFIED).\n"
                    "You must execute independent verification using the authenticated session "
                    "before performing other actions or concluding the assessment.\n\n"
                    f"Highest-Priority Verification Action:\n"
                    f"Tool: {top['tool']}\n"
                    f"Arguments: {_json.dumps(top['args'])}\n"
                    f"Expected Proof: {top.get('expected_proof', 'ADMIN_STATE / FLAG')}\n"
                    "============================="
                ),
            )

        # Accepted as verification action
        state.verification_selected += 1
        state.verification_attempts += 1
        state.verification_started = True
        return GuardDecision(action=GuardAction.ALLOW)


# ---------------------------------------------------------------------------
# Guard decision types
# ---------------------------------------------------------------------------

class GuardAction(str, Enum):
    """Outcome of a completion / verification gate check."""
    ALLOW                = "ALLOW"
    REJECT_VERIFICATION  = "REJECT_VERIFICATION"
    REJECT_PERSISTENCE   = "REJECT_PERSISTENCE"


@dataclass
class GuardDecision:
    """Typed result from CompletionEngine guard methods."""
    action: GuardAction
    prompt: str = ""

    @property
    def allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def rejected(self) -> bool:
        return not self.allowed
