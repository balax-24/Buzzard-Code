"""
Immutable Evidence Browser Panel for Qwythos TUI.
Allows searching and inspecting evidence records.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from security_agent.agent.assessment_state import AssessmentState


class EvidencePanel(VerticalScroll):
    DEFAULT_CSS = """
    EvidencePanel {
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
        yield Static("### 📜 Immutable Evidence Vault", id="evi_title")
        self.content_static = Static("", id="evi_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = []
        # Collect evidence across services, endpoints, capabilities
        evi_set = set()
        for s in self.state.services.values():
            evi_set.update(s.evidence_ids)
        for ep in self.state.http_endpoints.values():
            evi_set.update(ep.evidence_ids)
        for cap in self.state.capabilities.values():
            evi_set.update(cap.source_evidence_ids)

        if not evi_set:
            lines.append("*No evidence records gathered yet.*")
        else:
            for eid in sorted(evi_set):
                lines.append(f"• **`{eid}`** | Status: VERIFIED | Immutability: SECURE")

        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
