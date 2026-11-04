"""
Loop Recovery Controller and Stuck-Loop Detector for Buzzard Code.

Provides deterministic recovery, stagnation detection, and evidence-grounded offensive lifecycle:
Lifecycle:
DISCOVERY -> IDENTIFICATION -> ENUMERATION -> HYPOTHESIS -> EXPLOITATION -> VERIFICATION -> POST_EXPLOITATION -> REPORT

When the agent is stuck:
1. Inspect current AssessmentState.
2. Determine whether useful attack-surface evidence exists.
3. Determine whether a concrete vulnerability hypothesis exists.
4. If no hypothesis exists: return to DISCOVERY / IDENTIFICATION / ENUMERATION.
5. If a credible hypothesis exists: transition to EXPLOITATION and select relevant capabilities.
6. Execute only tools whose target, scope, and evidence requirements are satisfied.
7. Require VERIFICATION after exploitation.
8. If exploitation fails: classify failure and try alternative justified strategy.
9. If no useful action remains: terminate cleanly.
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple

from security_agent.agent.assessment_state import (
    AssessmentState,
    AssessmentPhase,
    ServiceState,
    HypothesisStatus,
    ExploitStatus,
    VulnerabilityHypothesis,
    ObjectiveStatus,
    FailureClassification,
    classify_failure,
    VerificationPredicates,
)


class StuckLoopDetector:
    """
    Tracks recent tool calls and failures to detect stagnation and repetitive loops.
    """

    def __init__(self, window_size: int = 3):
        self.window_size = window_size
        self._recent_calls: List[str] = []
        self._recent_failures: List[str] = []

    def record_call(self, tool_name: str, arguments: Dict[str, Any]) -> None:
        """Records a tool execution attempt signature."""
        clean_args = {k: str(v) for k, v in (arguments or {}).items()}
        sig = f"{tool_name}:{json.dumps(clean_args, sort_keys=True)}"
        self._recent_calls.append(sig)
        if len(self._recent_calls) > self.window_size:
            self._recent_calls = self._recent_calls[-self.window_size:]

    def record_failure(self, tool_name: str, error_type: str, exit_code: int) -> None:
        """Records a tool failure signature."""
        sig = f"{tool_name}:{error_type}:{exit_code}"
        self._recent_failures.append(sig)
        if len(self._recent_failures) > self.window_size:
            self._recent_failures = self._recent_failures[-self.window_size:]

    def is_loop_detected(self) -> Tuple[bool, Optional[str]]:
        """
        Returns (True, tool_name) if the last window_size tool calls are identical.
        """
        if len(self._recent_calls) >= self.window_size:
            if len(set(self._recent_calls)) == 1:
                tool_name = self._recent_calls[0].split(":")[0]
                return True, tool_name
        return False, None

    def is_failure_loop_detected(self) -> Tuple[bool, Optional[str]]:
        """
        Returns (True, signature) if the last window_size failures are identical.
        """
        if len(self._recent_failures) >= self.window_size:
            if len(set(self._recent_failures)) == 1:
                return True, self._recent_failures[0]
        return False, None

    def reset(self) -> None:
        """Resets the rolling signature history after a recovery action is taken."""
        self._recent_calls.clear()
        self._recent_failures.clear()


class LoopRecoveryController:
    """
    Manages deterministic recovery strategies, evidence-grounded offensive exploitation transitions,
    failure classification, and completion guardrails.
    """

    def __init__(self, max_redirects: int = 3):
        self.detector = StuckLoopDetector(window_size=3)
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def record_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        success: bool = True,
        error_type: str = "",
        exit_code: int = 0
    ) -> None:
        self.detector.record_call(tool_name, arguments)
        if not success:
            self.detector.record_failure(tool_name, error_type, exit_code)

    def check_stuck_loop(self) -> Tuple[bool, Optional[str]]:
        return self.detector.is_loop_detected()

    def max_redirects_exceeded(self) -> bool:
        return self.redirect_count >= self.max_redirects

    def handle_stuck_state(
        self,
        state: Optional[AssessmentState],
        target: str,
        last_tool: str
    ) -> Tuple[AssessmentPhase, str, Optional[Dict[str, Any]]]:
        """
        Reassesses canonical state when a loop is detected and transitions to the appropriate lifecycle phase:
        - If no attack surface discovered -> DISCOVERY
        - If open services uninvestigated -> ENUMERATION / IDENTIFICATION
        - If verified hypothesis exists -> EXPLOITATION
        - If no hypothesis justified -> ENUMERATION / REPORT
        """
        self.redirect_count += 1
        self.detector.reset()
        clean_target = (target or "").rstrip("/")

        if state is None:
            prompt = (
                f"STUCK-LOOP INTERRUPT ({self.redirect_count}): Tool '{last_tool}' was called repeatedly. "
                f"Reassessing state: Target is {clean_target}. Execute service discovery (nmap_scan) to identify active services."
            )
            return AssessmentPhase.DISCOVERY, prompt, {"tool": "nmap_scan", "args": {"host": clean_target, "ports": "1-10000"}}

        open_services = [s for s in state.services.values() if s.state == ServiceState.OPEN]

        # 1. No attack surface verified -> Return to DISCOVERY
        if not open_services and not state.has_discovered_ports():
            state.transition(AssessmentPhase.DISCOVERY, "Stuck-loop recovery: discovering attack surface")
            prompt = (
                f"STUCK-LOOP RECOVERY ({self.redirect_count}): No verified open services or attack surface exist on target {clean_target}. "
                f"Arbitrary exploitation is FORBIDDEN without technical evidence.\n"
                f"Transitioning to DISCOVERY phase: Run network port scan (nmap_scan) on canonical target {clean_target}."
            )
            return AssessmentPhase.DISCOVERY, prompt, {"tool": "nmap_scan", "args": {"host": clean_target, "ports": "1-10000"}}

        # 2. Uninvestigated services exist -> Return to ENUMERATION / IDENTIFICATION
        uninvestigated = [s for s in open_services if not s.investigated]
        if uninvestigated:
            s_target = uninvestigated[0]
            target_host = clean_target.split("://")[-1].split("/")[0].split(":")[0] or "127.0.0.1"
            state.transition(AssessmentPhase.ENUMERATION, f"Stuck-loop recovery: enumerating port {s_target.port}")

            if s_target.is_http_compatible():
                scheme = "https" if s_target.port == 443 else "http"
                suggested_tool = "whatweb_scan"
                suggested_args = {"url": f"{scheme}://{target_host}:{s_target.port}"}
                action_text = f"whatweb_scan(url='{scheme}://{target_host}:{s_target.port}')"
            else:
                suggested_tool = "grab_banner"
                suggested_args = {"host": target_host, "port": s_target.port}
                action_text = f"grab_banner(host='{target_host}', port={s_target.port})"

            prompt = (
                f"STUCK-LOOP RECOVERY ({self.redirect_count}): Open service port {s_target.port}/{s_target.protocol} ({s_target.service}) "
                f"on {target_host} has not yet been fingerprinted or investigated.\n"
                f"Transitioning to ENUMERATION phase: Run {action_text} to collect technical evidence and service banners."
            )
            return AssessmentPhase.ENUMERATION, prompt, {"tool": suggested_tool, "args": suggested_args}

        # 3. Check for credible vulnerability hypothesis with satisfied preconditions -> Transition to EXPLOITATION
        can_exploit, rationale, candidate = state.can_transition_to_exploitation()
        if can_exploit and candidate is not None:
            hyp = candidate.vulnerability_hypothesis
            state.transition(AssessmentPhase.EXPLOITATION, f"Stuck-loop recovery: executing exploitation for {hyp.id}")
            hyp.status = HypothesisStatus.EXPLOITING

            evidence_str = ", ".join(candidate.evidence_ids) if candidate.evidence_ids else "Discovered service evidence"
            prompt = (
                f"STUCK-LOOP RECOVERY ({self.redirect_count}) — EXPLOITATION PHASE:\n"
                f"Candidate exploitation capability '{candidate.allowed_tool}' satisfies all preconditions for hypothesis '{hyp.id}' ({hyp.vulnerability_type}) on port {candidate.port}.\n"
                f"Grounding Evidence: {evidence_str}\n"
                f"Allowed Capability: {candidate.allowed_tool}\n"
                f"Verification Plan: {candidate.verification_plan}\n\n"
                f"Execute the targeted exploitation action. After execution, you MUST verify proof of compromise (FLAG{{...}}, credentials, or RCE output) in the VERIFICATION phase."
            )
            return AssessmentPhase.EXPLOITATION, prompt, {"tool": candidate.allowed_tool, "args": candidate.tool_arguments}

        # 4. No hypothesis / preconditions justified -> Return to ENUMERATION or REPORT
        state.transition(AssessmentPhase.ENUMERATION, "Stuck-loop recovery: gathering endpoint evidence")
        prompt = (
            f"STUCK-LOOP RECOVERY ({self.redirect_count}): All open services are identified, but no specific vulnerability hypothesis satisfies preconditions yet.\n"
            f"Do NOT execute arbitrary exploitation without evidence. Execute endpoint fuzzing (ffuf_fuzz) or check headers (check_headers) to identify potential injection points, or conclude with a verified security report."
        )
        return AssessmentPhase.ENUMERATION, prompt, None

    def get_offensive_redirect_prompt(self, target: str, tool_name: str, state: Optional[AssessmentState] = None) -> str:
        """
        Backwards-compatible wrapper that invokes handle_stuck_state.
        """
        _, prompt, _ = self.handle_stuck_state(state=state, target=target, last_tool=tool_name)
        return prompt

    def classify_exploit_failure(
        self,
        state: AssessmentState,
        hypothesis_id: str,
        tool_name: str,
        raw_output: str,
        exit_code: int = 0
    ) -> str:
        """
        Classifies an exploit failure, records the attempt, updates hypothesis lifecycle,
        and checks if a justified alternative candidate with satisfied preconditions exists.
        If not, gracefully transitions to ENUMERATION instead of blindly looping exploit attempts.
        """
        ftype = classify_failure(raw_output, exit_code)
        target = state.context.target
        port = 80
        if hypothesis_id in state.hypotheses:
            port = state.hypotheses[hypothesis_id].port
            target = state.hypotheses[hypothesis_id].target

        state.record_exploit_attempt(
            hypothesis_id=hypothesis_id,
            tool_name=tool_name,
            target=target,
            port=port,
            arguments={},
            status=ExploitStatus.FAILED,
            failure_reason=ftype.value
        )

        # Check alternative candidates with satisfied preconditions
        alt_cand = state.get_eligible_exploit_candidate(exclude_hypothesis_id=hypothesis_id)
        if alt_cand:
            alt_hyp = alt_cand.vulnerability_hypothesis
            return (
                f"EXPLOITATION ATTEMPT FAILED ({ftype.value}): Tool '{tool_name}' failed against hypothesis '{hypothesis_id}'.\n"
                f"Alternative credible hypothesis available: '{alt_hyp.id}' ({alt_hyp.vulnerability_type}) on port {alt_cand.port} via tool '{alt_cand.allowed_tool}'.\n"
                f"Preconditions satisfied. Verification plan: {alt_cand.verification_plan}"
            )

        # Graceful fallback: Revert to ENUMERATION rather than aggressive ungrounded loops
        state.transition(AssessmentPhase.ENUMERATION, f"Exploitation failed ({ftype.value}): gathering fresh evidence")
        return (
            f"EXPLOITATION ATTEMPT FAILED ({ftype.value}): Tool '{tool_name}' failed against hypothesis '{hypothesis_id}'.\n"
            f"No other active hypothesis currently satisfies exploit preconditions. "
            f"Transitioning to ENUMERATION to gather fresh technical evidence before attempting further exploitation."
        )

    def check_premature_completion(
        self,
        content: str,
        observations: List[str],
        iteration: int,
        max_iterations: int,
        state: Optional[AssessmentState],
        task_goal: str,
        target: str,
        has_findings: bool = False
    ) -> Optional[str]:
        """
        Evaluates whether an agent attempt to stop without tool calls is premature,
        returning a corrective user prompt instruction or None if completion is valid.
        """
        goal_lower = task_goal.lower()

        # 1. Guard against premature termination when the agent only opened the URL on a broad security task
        only_opened_browser = (
            len(observations) == 1 and
            "browser.open" in observations[0] and
            any(kw in goal_lower for kw in ["attack", "gain access", "audit", "pentest", "vulnerabilit", "assess"])
        )
        if len(observations) == 0 or (only_opened_browser and iteration <= 3):
            return (
                "Assessment incomplete: You have only opened the URL and have not gathered technical evidence. "
                "You MUST execute relevant tools (e.g. browser.get_forms(), evaluate_security_headers(), "
                "check_cors_configuration(), or browser.get_html()) to inspect endpoints, forms, and defensive boundaries before concluding."
            )

        # 1b. Phase 6F Verification Guard: If validation succeeded, must independently verify before completion
        if state is not None and getattr(state, "objective_status", None) == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED and iteration < max_iterations - 1:
            candidates = state.verification_candidates if getattr(state, "verification_candidates", None) else state.generate_verification_candidates()
            predicates = getattr(state, "predicates", None) or VerificationPredicates()
            ver_action = candidates[0] if candidates else {
                "tool": "http.request",
                "args": {"method": "GET", "url": f"{target}/admin", "headers": {"Cookie": predicates.default_session_cookie}},
                "expected_proof": " / ".join(predicates.proof_markers[:2]) if predicates.proof_markers else "Proof marker",
            }
            return (
                "=== VERIFICATION REQUIRED ===\n"
                "Validation succeeded (Objective Status: OBJECTIVE_ACHIEVED_UNVERIFIED).\n"
                "You must perform independent verification before concluding or generating the final report.\n\n"
                f"Required verification action:\n"
                f"Tool: {ver_action['tool']}\n"
                f"Arguments: {json.dumps(ver_action['args'])}\n"
                f"Target: {ver_action.get('target', '')}\n"
                f"Expected proof: {ver_action.get('expected_proof', 'ADMIN_STATE')}\n"
                "============================="
            )

        # 2. Exploitation Verification Guard: If exploitation was attempted, require verification before completion
        if state is not None and state.exploitation_records:
            unverified_exploits = [e for e in state.exploitation_records if not e.verified and e.status == ExploitStatus.PENDING]
            if unverified_exploits and iteration < max_iterations - 1:
                state.transition(AssessmentPhase.VERIFICATION, "Verifying exploitation outcome")
                return (
                    "EXPLOITATION VERIFICATION REQUIRED: An exploitation capability was executed. "
                    "You MUST verify the technical outcome in the VERIFICATION phase. "
                    "Inspect output for concrete proof of compromise (e.g. FLAG{...}, database tables, valid session token, or command execution response) before generating the final report."
                )

        # 3. Guard against premature termination when open services were discovered but uninvestigated
        is_audit_task = any(kw in goal_lower for kw in [
            "assess", "audit", "pentest", "vulnerabilit", "inspect", "service", "report", "scan", "laborator", "docker"
        ])
        if state is not None and is_audit_task and iteration < max_iterations - 2:
            uninvestigated = [
                s for s in state.services.values()
                if s.state == ServiceState.OPEN and not s.investigated
            ]
            if uninvestigated:
                untested_lines = "\n".join([
                    f"  • Port {s.port}/{s.protocol} ({s.service}) on {s.host} [Version: {s.version}]"
                    for s in uninvestigated[:6]
                ])
                target_host = target.split("://")[-1].split("/")[0].split(":")[0] or "127.0.0.1"

                http_srvs = [s for s in uninvestigated if s.service in ("http", "https", "http-alt", "http-proxy") or s.port in (80, 443, 8080, 8000, 5000, 3000)]
                if http_srvs:
                    s_target = http_srvs[0]
                    next_action = f"Suggested next action: Call whatweb_scan(url='http://{target_host}:{s_target.port}') or check_headers(url='http://{target_host}:{s_target.port}') to inspect this service."
                else:
                    s_target = uninvestigated[0]
                    next_action = f"Suggested next action: Call grab_banner(host='{target_host}', port={s_target.port}) or terminal.execute to inspect port {s_target.port}."

                return (
                    f"ASSESSMENT CONTINUATION REQUIRED: You identified open service(s) on target {target}:\n"
                    f"The following active services have NOT yet been probed or fingerprinted:\n"
                    f"{untested_lines}\n\n"
                    f"Do NOT conclude or write a final report yet. Continue the multi-step assessment by investigating these exposed services.\n"
                    f"{next_action}"
                )

        # 4. OFFENSIVE GOAL GUARD: an attack task may NOT complete without evidence of compromise
        offensive_goal = any(kw in goal_lower for kw in [
            "attack", "compromise", "penetrat", "gain access", "capture flag",
            "exploit", "break authent", "rce", "remote code", "hack"
        ])
        if offensive_goal:
            all_obs = " ".join(observations)
            predicates = getattr(state, "predicates", None) if state else None
            proof_markers = getattr(predicates, "proof_markers", None) or getattr(state, "proof_markers", None) or VerificationPredicates().proof_markers
            has_flag = any(m in all_obs or m in content for m in proof_markers)
            if not (has_flag or has_findings) and iteration < max_iterations - 2:
                return (
                    "TASK NOT COMPLETE. You have NOT achieved the offensive objective - no flag captured, "
                    "no data extracted, no authentication bypassed, no code execution gained. You are the "
                    "ATTACKER, not an advisor: stop writing reports and continue attacking until you obtain "
                    "concrete proof of compromise (a FLAG{...}, dumped credentials, admin access, or RCE).\n"
                    "Attack tools available: ffuf_fuzz, sqlmap_attack, brute_force_http, nuclei_scan, "
                    "nikto_scan, nmap_scan, whatweb_scan, web_fetch, tcp_connectivity_check.\n"
                    "Suggested next moves for this target: formulate a specific vulnerability hypothesis, enumerate endpoints with ffuf_fuzz, then test "
                    "/login and /search for SQL injection (sqlmap_attack), /view?file= for path traversal, "
                    "and /ping for command injection. Extract the flags."
                )

        return None
