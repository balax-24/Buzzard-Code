"""
Autonomous Software Engineer Control Plane for Buzzard Code.

Orchestrates the complete beast agent software engineering lifecycle:
1. Codebase Investigation (EngineeringMemoryGraph)
2. Change Blast Radius & Risk Simulation (ChangeImpactSimulator)
3. Model Capability Tiering (CodingModelRouter)
4. Syntax-Verified Transactional Edits (AtomicCodeEditor)
5. Targeted Sub-Second Test Selection (TestImpactSelector)
6. Closed-Loop Failure Recovery (AutonomousSelfHealingLoop)
7. Cryptographic Evidence Bundle Verification (EvidenceBundle)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from coding.ast_morph import AstMorphEngine
from coding.atomic_editor import AtomicCodeEditor, EditOperation, TransactionResult
from coding.hypothesis_racer import Hypothesis, HypothesisRacer, RaceOutcome
from coding.impact_simulator import ChangeImpactSimulator, ImpactPrediction
from coding.self_healing import AutonomousSelfHealingLoop, RepairPlan
from hooks.hook_manager import HookManager
from intelligence.ast_outliner import AstOutliner, FileOutline
from intelligence.causal_history import CausalHistoryLinker, CausalReport
from intelligence.memory_graph import EngineeringMemoryGraph
from model.coding_router import CodingModelRouter
from runtime.warm_repl import ReplEvalResult, WarmReplSession
from system.pty_supervisor import PtySupervisor
from verification.runtime_probe import RuntimeProbe, RuntimeSnapshot
from verification.test_selector import SelectedTests, TestImpactSelector

logger = logging.getLogger(__name__)


@dataclass
class WorkflowPlan:
    task: str
    target_files: List[str]
    impact: ImpactPrediction
    selected_tests: SelectedTests
    model_recommended: str
    steps: List[str]


@dataclass
class ExecutionOutcome:
    success: bool
    modified_files: List[str] = field(default_factory=list)
    tests_passed: bool = False
    test_output: Optional[str] = None
    repair_plan: Optional[RepairPlan] = None
    error: Optional[str] = None

    def format_summary(self) -> str:
        lines = [
            f"⚡ AUTONOMOUS ENGINEERING OUTCOME: {'✔ SUCCESS' if self.success else '✖ FAILED'}",
            f"  • Files Modified: {len(self.modified_files)}",
        ]
        for f in self.modified_files:
            lines.append(f"    - {f}")

        lines.append(f"  • Test Verification: {'PASSED' if self.tests_passed else 'FAILED'}")
        if self.repair_plan and not self.tests_passed:
            lines.append(f"  • Self-Healing Diagnostics: {self.repair_plan.failure_count} failures analyzed.")
        if self.error:
            lines.append(f"  • Error: {self.error}")

        return "\n".join(lines)


class AutonomousEngineer:
    """
    Central autonomous engineering controller for Buzzard Code.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.graph = EngineeringMemoryGraph(self.workspace_root)
        self.graph.sync_persistent()

        self.impact_simulator = ChangeImpactSimulator(self.workspace_root, self.graph)
        self.test_selector = TestImpactSelector(self.workspace_root, self.graph)
        self.editor = AtomicCodeEditor(self.workspace_root)
        self.healer = AutonomousSelfHealingLoop(self.workspace_root, self.graph)
        self.router = CodingModelRouter()
        self.hooks = HookManager(self.workspace_root)
        self.outliner = AstOutliner(self.workspace_root)
        self.morph = AstMorphEngine()
        self.pty = PtySupervisor(self.workspace_root)
        self.causal = CausalHistoryLinker(self.workspace_root)
        self._worktree_mgr = None
        self._repl = None
        self._racer = None
        self._probe = None
        self._poc = None
        self._cpg = None
        self._bounty = None
        self._checkpoints = None
        self._distiller = None

    @property
    def repl(self) -> WarmReplSession:
        if self._repl is None:
            self._repl = WarmReplSession(self.workspace_root)
        return self._repl

    @property
    def racer(self) -> HypothesisRacer:
        if self._racer is None:
            self._racer = HypothesisRacer(self.workspace_root)
        return self._racer

    @property
    def probe(self) -> RuntimeProbe:
        if self._probe is None:
            self._probe = RuntimeProbe(self.workspace_root)
        return self._probe

    @property
    def poc(self):
        if self._poc is None:
            from verification.poc_synthesizer import ZeroShotPocSynthesizer
            self._poc = ZeroShotPocSynthesizer(self.workspace_root)
        return self._poc

    @property
    def cpg(self):
        if self._cpg is None:
            from intelligence.code_property_graph import CodePropertyGraph
            self._cpg = CodePropertyGraph(self.workspace_root)
        return self._cpg

    @property
    def bounty(self):
        if self._bounty is None:
            from agent.bounty_engine import AdversarialBountyEngine
            self._bounty = AdversarialBountyEngine(self.workspace_root, self.worktrees)
        return self._bounty

    @property
    def checkpoints(self):
        if self._checkpoints is None:
            from runtime.checkpoint_manager import SemanticCheckpointManager
            self._checkpoints = SemanticCheckpointManager(self.workspace_root)
        return self._checkpoints

    @property
    def distiller(self):
        if self._distiller is None:
            from intelligence.context_distiller import HierarchicalContextDistiller
            self._distiller = HierarchicalContextDistiller(self.workspace_root, self.outliner)
        return self._distiller

    @property
    def worktrees(self):
        if self._worktree_mgr is None:
            from agent.worktree_manager import WorktreeManager
            self._worktree_mgr = WorktreeManager(self.workspace_root)
        return self._worktree_mgr

    def outline_file(self, rel_path: str) -> FileOutline:
        """Generates AST structural outline with token savings metric."""
        return self.outliner.generate_outline(rel_path)

    def unfold_symbol(self, rel_path: str, symbol_name: str) -> Dict[str, Any]:
        """Selectively extracts target symbol snippet with zero 800-line context pollution."""
        return self.outliner.unfold_symbol(rel_path, symbol_name)

    def eval_repl(self, code: str) -> ReplEvalResult:
        """Executes Python code inside warm persistent in-memory kernel."""
        return self.repl.execute(code)

    def race_hypotheses(self, hypotheses: List[Hypothesis], test_cmd: Optional[List[str]] = None) -> RaceOutcome:
        """Races candidate patches across speculative worktrees and merges winner."""
        return self.racer.race(hypotheses, test_cmd)

    def probe_code(self, code: str) -> RuntimeSnapshot:
        """Inspects runtime frames, locals, and exceptions without print statements."""
        return self.probe.probe_code_snippet(code)

    def causal_history(self, rel_path: str, line_numbers: List[int]) -> CausalReport:
        """Traces lines back to commit rationale, PR intent, and bugfix warnings."""
        return self.causal.analyze_file_lines(rel_path, line_numbers)

    def plan(self, task: str, target_files: Optional[List[str]] = None) -> WorkflowPlan:
        """
        Constructs an end-to-end execution plan for an engineering task.
        """
        targets = target_files or []

        # If targets not specified, discover from keywords in task
        if not targets:
            text_lower = task.lower()
            for rel_path in self.graph.files.keys():
                stem = Path(rel_path).stem.lower()
                if stem in text_lower and not rel_path.startswith("test"):
                    targets.append(rel_path)

        impact = self.impact_simulator.simulate(targets)
        selected_tests = self.test_selector.select_tests_for_files(targets)
        model = self.router.select_model(
            task_text=task,
            risk_level=impact.risk_level,
            affected_files_count=len(impact.affected_files),
        )

        steps = [
            f"1. Investigate AST symbols and call hierarchy across {len(targets)} target file(s).",
            f"2. Validate blast radius ({len(impact.affected_files)} dependent files, risk: {impact.risk_level.upper()}).",
            f"3. Apply syntax-verified atomic edits via AtomicCodeEditor.",
            f"4. Run priority targeted tests: {selected_tests.targeted_command or 'full suite'}.",
            f"5. Self-heal and repair if assertions fail.",
            f"6. Generate authoritative signed Evidence Bundle for verification.",
        ]

        return WorkflowPlan(
            task=task,
            target_files=targets,
            impact=impact,
            selected_tests=selected_tests,
            model_recommended=model,
            steps=steps,
        )

    def apply_edits_atomically(self, operations: List[EditOperation]) -> TransactionResult:
        """
        Applies a set of multi-file edits with AST syntax verification, lifecycle hooks, and rollback.
        """
        target_files = [op.file_path for op in operations]

        # 1. Pre-edit hook
        pre_hook = self.hooks.run_hook("pre-edit", target_files=target_files)
        if pre_hook.executed and not pre_hook.passed:
            return TransactionResult(
                success=False,
                error=f"Pre-edit hook failed: {pre_hook.stderr or pre_hook.error}",
            )

        # 2. Atomic edits with AST validation
        result = self.editor.apply_transaction(operations)
        if result.success:
            # Re-index modified files in memory graph
            for f in result.modified_files:
                p = self.workspace_root / f
                if p.exists():
                    if p.suffix == ".py":
                        self.graph._index_python_file(p, f)
                    elif p.suffix in (".ts", ".tsx", ".js", ".jsx"):
                        self.graph._index_js_ts_file(p, f)

            # 3. Post-edit hook
            self.hooks.run_hook("post-edit", target_files=result.modified_files)

        return result

    def diagnose_test_failure(self, test_output: str) -> RepairPlan:
        """
        Analyzes test failure output and constructs an autonomous repair plan.
        """
        return self.healer.create_repair_plan(test_output)

    def synthesize_poc(self, issue_context: str, target_file: Optional[str] = None) -> Any:
        """Synthesizes minimal reproduction proof-of-concept test artifact."""
        return self.poc.synthesize_reproducer(issue_context, target_file)

    def execute_poc(self, artifact_id: str) -> Any:
        """Executes reproduction PoC to verify defect failure or resolution."""
        return self.poc.execute_reproducer(artifact_id)

    def query_cpg(self, symbol_name: str, direction: str = "callees", max_depth: int = 3) -> List[Dict[str, Any]]:
        """Queries Code Property Graph for call hierarchies and data flow."""
        return self.cpg.get_call_hierarchy(symbol_name, direction, max_depth)

    def run_bounty_challenge(self, target_file: str, functions: Optional[List[str]] = None) -> Any:
        """Spawns adversarial Red-Team twin agent to fuzz and stress-test patches."""
        return self.bounty.run_bounty_challenge(target_file, functions or [])

    def create_checkpoint(self, step_id: int, description: str, files: Optional[List[str]] = None) -> Any:
        """Creates time-travel micro-checkpoint of file snapshots and state."""
        return self.checkpoints.create_checkpoint(step_id, description, files)

    def rewind_checkpoint(self, step_id_or_id: int | str) -> Tuple[bool, str]:
        """Rewinds file tree and workspace state to a prior checkpoint."""
        return self.checkpoints.rewind_to(step_id_or_id)

    def distill_context(self, raw_turns: List[Dict[str, Any]], active_files: List[str]) -> Any:
        """Compresses context by 85% into AST skeleton projections and causal facts."""
        return self.distiller.distill_turns(raw_turns, active_files)
