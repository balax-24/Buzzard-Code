"""
Verified Findings Panel Widget for Qwythos TUI.
Visualizes confirmed, verified vulnerabilities separately from unverified hypotheses.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from security_agent.agent.assessment_state import AssessmentState


class FindingsPanel(VerticalScroll):
    DEFAULT_CSS = """
    FindingsPanel {
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
        yield Static("### 🚨 Verified Findings", id="find_title")
        self.content_static = Static("", id="find_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = []
        if not self.state.findings:
            lines.append("*No verified vulnerabilities confirmed yet.*")
        else:
            for f in self.state.findings:
                title = f.get("title", str(f)) if isinstance(f, dict) else getattr(f, "title", str(f))
                sev = f.get("severity", "HIGH") if isinstance(f, dict) else getattr(f, "severity", "HIGH")
                lines.append(
                    f"**[{sev}]** {title}\n"
                    f"- Verified: **YES**\n"
                )
        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
