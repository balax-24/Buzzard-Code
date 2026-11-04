"""
Capabilities Panel Widget for Qwythos TUI.
Visualizes capability progression transitions (UNAUTHENTICATED -> AUTHENTICATED -> ADMIN_ACCESS).
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from security_agent.agent.assessment_state import AssessmentState, CapabilityType


class CapabilitiesPanel(VerticalScroll):
    DEFAULT_CSS = """
    CapabilitiesPanel {
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
        yield Static("### 🔑 Operational Capabilities", id="cap_title")
        self.content_static = Static("", id="cap_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = [
            "**Capability Progression Hierarchy:**",
            "  `UNAUTHENTICATED`",
            "        ↓",
            f"  `AUTHENTICATED` {'✓' if any(c.capability_type == CapabilityType.AUTHENTICATED for c in self.state.capabilities.values()) else '○'}",
            "        ↓",
            f"  `ADMIN_ACCESS` {'✓' if any(c.capability_type == CapabilityType.ADMIN_ACCESS for c in self.state.capabilities.values()) else '○'}",
            "        ↓",
            f"  `COMMAND_EXECUTION` {'✓' if any(c.capability_type == CapabilityType.COMMAND_EXECUTION for c in self.state.capabilities.values()) else '○'}",
            "\n**Acquired Capability Records:**"
        ]

        if not self.state.capabilities:
            lines.append("• *Baseline: UNAUTHENTICATED*")
        else:
            for c_id, cap in self.state.capabilities.items():
                lines.append(f"• **[{cap.capability_type.value}]** `{c_id}` | Scope: `{cap.target_scope}`")

        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
