"""
Conversation Stream and Message Widgets for Buzzard Code TUI.
Provides terminal-native, compact, information-dense rendering of:
- Minimalist centered empty state
- Role-based conversation messages (You / Buzzard) without bloated boxes
- Compact inline system events and security checks
- Smooth in-place token streaming into a single persistent bubble
"""

from __future__ import annotations

from typing import Optional, List, Any
from textual.widget import Widget
from textual.app import ComposeResult
from textual.containers import VerticalScroll, Vertical
from textual.widgets import Static
from rich.text import Text
from rich.markdown import Markdown

from cli.banner import render_banner
from tui.models import ChatMessage, MessageRole, ToolCallCardData
from tui.widgets.tool_card import ToolCallCard, ToolActivityCard


class EmptyStateWidget(Widget):
    """
    Minimalist centered splash shown when conversation is empty.
    Per specification:
    Welcome line, working directory, example coding requests and key commands.
    """

    DEFAULT_CSS = """
    EmptyStateWidget {
        height: auto;
        padding: 2 1;
        margin: 1 0;
        background: transparent;
    }
    """

    def render(self) -> Text:
        t = Text("\n")
        t.append_text(render_banner(self.size.width or 80, indent=2))
        t.append(f"\n  cwd: {self._workspace()}\n\n", style="#94a3b8")
        t.append("  Try:\n", style="#94a3b8")
        for example in ("Explain this codebase", "Fix the failing tests", "Add validation to @src/api.py"):
            t.append(f"    > {example}\n", style="#e2e8f0")
        t.append("\n  /help", style="#a78bfa")
        t.append(" commands  ", style="#64748b")
        t.append("/model", style="#a78bfa")
        t.append(" switch model  ", style="#64748b")
        t.append("/mcp", style="#a78bfa")
        t.append(" tools\n", style="#64748b")
        return t

    @staticmethod
    def _workspace() -> str:
        from tools.filesystem import get_active_workspace
        return get_active_workspace()


class MessageBubble(Widget):
    """
    Renders an individual conversation message or inline status row.
    NO giant bordered boxes or heavy background fills.
    """

    DEFAULT_CSS = """
    MessageBubble {
        margin: 0 0 1 0;
        padding: 0;
        background: transparent;
        height: auto;
    }
    MessageBubble Vertical {
        height: auto;
    }
    .message-content {
        padding: 0 0 0 2;
        height: auto;
    }
    """

    def __init__(self, message: ChatMessage, id: str | None = None):
        super().__init__(id=id)
        self.message = message
        self.content_widget: Optional[Static] = None

    def compose(self) -> ComposeResult:
        # Check if message is a short system status/check row
        if self.message.role == MessageRole.SYSTEM and self._is_inline_status(self.message.content):
            self.content_widget = Static(self._render_inline_status(), classes="message-content")
            yield self.content_widget
            return

        with Vertical():
            # Role label
            if self.message.role == MessageRole.USER:
                role_label = Text("> You", style="bold #94a3b8")
            elif self.message.role == MessageRole.ASSISTANT:
                role_label = Text("● Buzzard", style="bold #c084fc")
            elif self.message.role == MessageRole.ERROR:
                role_label = Text("  ✕ Error", style="bold #ef4444")
            else:
                role_label = Text("  System", style="bold #64748b")

            yield Static(role_label)

            # Optional reasoning summary
            if self.message.reasoning_summary:
                reason_text = Text(f"  · Reasoning: {self.message.reasoning_summary}", style="italic #64748b")
                yield Static(reason_text)

            # Content body
            if getattr(self.message, "renderable", None) is not None:
                self.content_widget = Static(self.message.renderable, classes="message-content")
            else:
                self.content_widget = Static(self._format_body(self.message.content or " "), classes="message-content")
            yield self.content_widget

            # Tool call cards if attached
            for card_data in self.message.tool_cards:
                yield ToolCallCard(card_data)

    def _is_inline_status(self, text: str) -> bool:
        """Determines if a system message is a short single-event status row."""
        stripped = text.strip()
        if not stripped or "\n" in stripped:
            return False
        first_char = stripped[0]
        return first_char in ("✓", "✕", "⚠", "●", "⚡") or len(stripped) < 80

    def _render_inline_status(self) -> Text:
        t = Text()
        stripped = self.message.content.strip()
        t.append("  ")
        if stripped.startswith("✓"):
            t.append("✓ ", style="bold #10b981")
            t.append(stripped[1:].strip(), style="#94a3b8")
        elif stripped.startswith("✕") or stripped.startswith("✗"):
            t.append("✕ ", style="bold #ef4444")
            t.append(stripped[1:].strip(), style="#f87171")
        elif stripped.startswith("⚠"):
            t.append("⚠ ", style="bold #f59e0b")
            t.append(stripped[1:].strip(), style="#fbbf24")
        elif stripped.startswith("●"):
            t.append("● ", style="bold #06b6d4")
            t.append(stripped[1:].strip(), style="#e2e8f0")
        else:
            t.append("· ", style="#64748b")
            t.append(stripped, style="#94a3b8")
        return t

    def _format_body(self, text: str) -> Any:
        """Format message body using Markdown for rich rendering without raw delimiters."""
        clean = (text or "").strip()
        if not clean:
            return Text("")

        if self.message.role == MessageRole.ERROR:
            return Text(clean, style="#f87171")
        elif self.message.role == MessageRole.USER:
            return Text(clean, style="#e2e8f0")

        # Assistant and System messages: render through Rich Markdown
        return Markdown(clean)

    def update_content(self, new_content: str, renderable: Optional[Any] = None) -> None:
        self.message.content = new_content
        if renderable is not None:
            self.message.renderable = renderable
        if self.content_widget:
            if getattr(self.message, "renderable", None) is not None:
                self.content_widget.update(self.message.renderable)
            elif self.message.role == MessageRole.SYSTEM and self._is_inline_status(new_content):
                self.content_widget.update(self._render_inline_status())
            elif getattr(self.message, "is_streaming", False):
                self.content_widget.update(Text(new_content, style="#e2e8f0"))
            else:
                self.content_widget.update(self._format_body(new_content or " "))


class ChatView(VerticalScroll):
    """
    Main conversation viewport.
    Houses the message stream, inline statuses, tool cards, and empty state.
    """

    DEFAULT_CSS = """
    ChatView {
        height: 1fr;
        background: #0d0e15;
        padding: 0 1;
        scrollbar-size-vertical: 1;
    }
    """

    def __init__(self, id: str | None = None):
        super().__init__(id=id)
        self.current_streaming_bubble: MessageBubble | None = None
        self._empty_state: Optional[EmptyStateWidget] = None
        self._has_activity: bool = False

    def on_mount(self) -> None:
        # Show elegant empty state on initial mount
        if not self._has_activity:
            self._empty_state = EmptyStateWidget()
            self.mount(self._empty_state)

    def _remove_empty_state_if_needed(self) -> None:
        if self._empty_state is not None:
            try:
                self._empty_state.remove()
            except Exception:
                pass
            self._empty_state = None
        self._has_activity = True

    def add_message(self, message: ChatMessage) -> MessageBubble:
        self._remove_empty_state_if_needed()
        bubble = MessageBubble(message)
        self.mount(bubble)
        if message.is_streaming:
            self.current_streaming_bubble = bubble
        else:
            self.current_streaming_bubble = None
        self.call_after_refresh(self.scroll_end, animate=False)
        return bubble

    def append_streaming_token(self, token: str) -> None:
        if self.current_streaming_bubble:
            new_text = self.current_streaming_bubble.message.content + token
            self.current_streaming_bubble.update_content(new_text)
            self.call_after_refresh(self.scroll_end, animate=False)

    def finish_streaming(self) -> None:
        if self.current_streaming_bubble:
            self.current_streaming_bubble.message.is_streaming = False
            self.current_streaming_bubble.update_content(self.current_streaming_bubble.message.content)
            self.current_streaming_bubble = None

    def has_streamed_since_last_tool(self) -> bool:
        """True when the newest transcript entry is an assistant reply that is already visible."""
        children = list(self.children)
        if not children or not isinstance(children[-1], MessageBubble):
            return False
        message = children[-1].message
        return message.role == MessageRole.ASSISTANT and bool(message.content.strip())

    def add_tool_card(self, card_data: ToolCallCardData) -> None:
        self._remove_empty_state_if_needed()
        card = ToolCallCard(card_data)
        self.mount(card)
        self.call_after_refresh(self.scroll_end, animate=False)

    def add_tool_activity(self, card: ToolActivityCard) -> None:
        self._remove_empty_state_if_needed()
        self.mount(card)
        self.call_after_refresh(self.scroll_end, animate=False)

    @property
    def message_bubbles(self) -> List[MessageBubble]:
        return list(self.query(MessageBubble))

    def clear_chat(self) -> None:
        """Removes all mounted message bubbles and tool cards, restoring empty state."""
        self.remove_children()
        self.current_streaming_bubble = None
        self._has_activity = False
        self._empty_state = EmptyStateWidget()
        self.mount(self._empty_state)
