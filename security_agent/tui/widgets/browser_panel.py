"""
Live Browser & DOM Inspection Panel for Qwythos TUI.
Visualizes active URL, reduced DOM tree, forms, and discovered endpoints.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from security_agent.agent.assessment_state import AssessmentState


class BrowserPanel(VerticalScroll):
    DEFAULT_CSS = """
    BrowserPanel {
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
        yield Static("### 🌐 Live Browser & DOM Surface", id="browser_title")
        self.content_static = Static("", id="browser_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = []
        if not self.state.http_endpoints and not self.state.forms:
            lines.append("*No active browser sessions or discovered DOM elements.*")
        else:
            if self.state.http_endpoints:
                lines.append("**Discovered HTTP Endpoints:**")
                for ep in self.state.http_endpoints.values():
                    lines.append(f"- `{ep.url}` (Status: {ep.status_code or 'Unknown'})")
            if self.state.forms:
                lines.append("\n**Interactive Forms:**")
                for f_id, form in self.state.forms.items():
                    action = getattr(form, "action", "")
                    method = getattr(form, "method", "POST")
                    lines.append(f"- Form `{f_id}`: `{method} {action}`")
        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
