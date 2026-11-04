"""
Layered Context Memory (L0-L8) Panel for Qwythos TUI.
Visualizes structured layered memory and learned constraints.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from agent.assessment_state import AssessmentState
from intelligence.memory import LayeredMemoryManager
from intelligence.attack_graph import AttackGraph
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.branches import BranchManager


class MemoryPanel(VerticalScroll):
    DEFAULT_CSS = """
    MemoryPanel {
        height: 100%;
        background: #181825;
        padding: 1;
    }
    """

    def __init__(
        self,
        state: AssessmentState | None = None,
        memory_mgr: LayeredMemoryManager | None = None,
        graph: AttackGraph | None = None,
        hyp_engine: HypothesisEngine | None = None,
        branch_mgr: BranchManager | None = None,
        id: str | None = None,
    ):
        super().__init__(id=id)
        self.state = state or AssessmentState()
        self.memory_mgr = memory_mgr or LayeredMemoryManager()
        self.graph = graph or AttackGraph()
        self.hyp_engine = hyp_engine or HypothesisEngine()
        self.branch_mgr = branch_mgr or BranchManager()
        self.raw_text: str = ""

    def compose(self) -> ComposeResult:
        yield Static("### 🧠 Layered Memory (L0 - L8)", id="mem_title")
        self.content_static = Static("", id="mem_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        rehydrated = self.memory_mgr.build_rehydration_context(
            self.state, self.graph, self.hyp_engine, self.branch_mgr
        )
        self.raw_text = rehydrated
        self.content_static.update(f"```\n{rehydrated}\n```")
