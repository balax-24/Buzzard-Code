"""
Multi-Path Investigation Branches Panel Widget for Qwythos TUI.
Visualizes active, paused, and completed investigation branches.
"""

from __future__ import annotations

from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Static

from security_agent.intelligence.branches import BranchManager


class BranchesPanel(VerticalScroll):
    DEFAULT_CSS = """
    BranchesPanel {
        height: 100%;
        background: #181825;
        padding: 1;
    }
    """

    def __init__(self, branch_mgr: BranchManager | None = None, id: str | None = None):
        super().__init__(id=id)
        self.branch_mgr = branch_mgr or BranchManager()
        self.raw_text: str = ""

    def compose(self) -> ComposeResult:
        yield Static("### 🌿 Investigation Branches", id="branch_title")
        self.content_static = Static("", id="branch_content")
        yield self.content_static
        self.refresh_panel()

    def refresh_panel(self) -> None:
        if not hasattr(self, "content_static"):
            return
        lines = []
        if not self.branch_mgr.branches:
            lines.append("*No secondary branches spawned yet (Single-line execution).*")
        else:
            for b in self.branch_mgr.branches.values():
                is_active = b.branch_id == self.branch_mgr.active_branch_id
                prefix = "★ [ACTIVE]" if is_active else f"• [{b.status.value}]"
                lines.append(
                    f"{prefix} **{b.name}** (`{b.branch_id}`)\n"
                    f"  Target: `{b.target}` | Priority: {b.priority.value}\n"
                    f"  Budget: {b.tool_calls_used}/{b.tool_calls_allocated} tools\n"
                )
        self.raw_text = "\n".join(lines)
        self.content_static.update(self.raw_text)
