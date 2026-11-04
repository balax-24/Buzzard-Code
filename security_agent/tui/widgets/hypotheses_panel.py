"""
Hypotheses Panel Widget for Qwythos TUI.
Displays Active vs Refuted Hypotheses with evidence links.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static
from rich.panel import Panel

from security_agent.intelligence.hypothesis_engine import HypothesisEngine
from security_agent.agent.assessment_state import AssessmentState


class HypothesesPanel(VerticalScroll):
    DEFAULT_CSS = """
    HypothesesPanel {
        height: 100%;
        background: #181825;
        padding: 1;
    }
    """

    def __init__(self, state: AssessmentState | None = None, id: str | None = None):
        super().__init__(id=id)
        self.state = state or AssessmentState()
        self.raw_text: str = ""

    def compose(self) -> ComposeResult:
        yield Static("### 💡 Vulnerability Hypotheses", id="hyp_title")
        self.content_static = Static("", id="hyp_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = []
        if not self.state.hypotheses:
            lines.append("*No hypotheses currently formulated.*")
        else:
            for h_id, hyp in self.state.hypotheses.items():
                status_color = "green" if hyp.status.value == "VERIFIED" else ("red" if hyp.status.value == "REFUTED" else "yellow")
                lines.append(
                    f"**[{hyp.vulnerability_type}]** `{h_id}`\n"
                    f"- Target: `{hyp.target}:{hyp.port}`\n"
                    f"- Status: [{status_color}]{hyp.status.value}[/{status_color}]\n"
                    f"- Evidence: `{', '.join(hyp.evidence_ids) if hyp.evidence_ids else 'None'}`\n"
                )
        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
