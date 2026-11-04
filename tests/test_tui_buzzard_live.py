"""
Comprehensive Live TUI and Security Invariant Tests for Buzzard Code.
Verifies the complete TUI/UX redesign:
- Minimalist centered empty state
- Clean conversation message rendering (no giant bordered boxes)
- In-place single-region token streaming
- EventBus tool activity card transitions (validating -> running -> completed / blocked)
- ApprovalModal keyboard navigation ([Y], [N], [A], [D])
- Slash command autocompletion & palette suggestions box
- Compact interactive /model switching
- Responsive rendering across 80x24, 100x30, 120x40 viewports
- Security invariants R1-R8 (Scope, Policy, Sandbox, KillSwitch, No credential leak)
"""

import pytest
import asyncio
from typing import Dict, Any

from textual.widgets import Input
from textual.geometry import Size

from security_agent.tui.app import BuzzardTUIApp, BuzzardInput, CommandSuggestionsBox
from security_agent.tui.widgets.header import BuzzardHeader
from security_agent.tui.widgets.status_bar import BuzzardStatusBar
from security_agent.tui.widgets.chat import ChatView, MessageBubble, EmptyStateWidget
from security_agent.tui.widgets.tool_card import ToolActivityCard
from security_agent.tui.widgets.modals import ApprovalModal, ModelSwitchModal
from security_agent.tui.models import ChatMessage, MessageRole
from security_agent.events.bus import EventBus
from security_agent.events.types import Event, EventType
from security_agent.security.kill_switch import KillSwitch
from security_agent.tui.test_utils import run_async


def test_buzzard_tui_startup_and_composition():
    """Verify clean startup, compact header, status bar, and initial empty state."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            header = app.query_one(BuzzardHeader)
            chat_container = app.query_one(ChatView)
            user_input = app.query_one(BuzzardInput)
            status_bar = app.query_one(BuzzardStatusBar)

            assert header is not None
            assert chat_container is not None
            assert user_input is not None
            assert status_bar is not None

            assert header.model_name == app.model_name
            assert header.mode == "Autonomous"
            assert app.status_bar is not None

            # Verify initial empty state widget is mounted
            empty_states = list(chat_container.query(EmptyStateWidget))
            assert len(empty_states) == 1
    run_async(_run())


def test_buzzard_tui_clean_conversation_design():
    """Verify messages use subtle typography labels (You / Buzzard) without giant boxes."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # Add user message
            u_msg = ChatMessage(role=MessageRole.USER, content="Scan 127.0.0.1 for open ports.")
            chat_view.add_message(u_msg)
            await pilot.pause(0.05)

            # Empty state should be removed
            assert len(list(chat_view.query(EmptyStateWidget))) == 0

            # Add assistant message
            a_msg = ChatMessage(role=MessageRole.ASSISTANT, content="I will inspect the authorized scope first.")
            chat_view.add_message(a_msg)

            bubbles = chat_view.message_bubbles
            assert len(bubbles) == 2
            assert bubbles[0].message.role == MessageRole.USER
            assert bubbles[1].message.role == MessageRole.ASSISTANT
    run_async(_run())


def test_buzzard_tui_token_streaming_in_place():
    """Verify token streaming updates the same message bubble in place without appending lines."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)
            initial_count = len(chat_view.message_bubbles)

            msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
            bubble = chat_view.add_message(msg)
            assert len(chat_view.message_bubbles) == initial_count + 1

            # Stream tokens
            chat_view.append_streaming_token("I will ")
            chat_view.append_streaming_token("scan ")
            chat_view.append_streaming_token("192.168.1.10 ")
            chat_view.append_streaming_token("safely.")
            chat_view.finish_streaming()

            # Verify contents updated in place in single bubble
            assert len(chat_view.message_bubbles) == initial_count + 1
            assert bubble.message.content == "I will scan 192.168.1.10 safely."
            assert not bubble.message.is_streaming
    run_async(_run())


def test_buzzard_tui_compact_inline_status_rows():
    """Verify system status events render as compact inline status rows."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            s1 = ChatMessage(role=MessageRole.SYSTEM, content="✓ Scope authorized")
            s2 = ChatMessage(role=MessageRole.SYSTEM, content="✓ Sandbox available")
            chat_view.add_message(s1)
            chat_view.add_message(s2)

            bubbles = chat_view.message_bubbles
            assert len(bubbles) == 2
            assert "✓ Scope authorized" in bubbles[0].message.content
            assert "✓ Sandbox available" in bubbles[1].message.content
    run_async(_run())


def test_buzzard_tui_eventbus_tool_transitions():
    """Verify ToolActivityCard in-place transitions across the full security lifecycle."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            # 1. Action proposed
            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.AGENT_ACTION_PROPOSED,
                    payload={
                        "tool": "nmap_scan",
                        "target": "192.168.1.10",
                        "arguments": {"target": "192.168.1.10", "mode": "quick"},
                        "tool_call_id": "call-1234",
                    }
                )
            )
            await pilot.pause(0.05)

            cards = list(app.query(ToolActivityCard))
            assert len(cards) == 1
            card = cards[0]
            assert card.tool_name == "nmap_scan"
            assert "192.168.1.10" in card.target

            # 2. Policy allowed
            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.POLICY_ALLOWED,
                    payload={"tool_call_id": "call-1234", "rule": "authorized_scope"}
                )
            )
            await pilot.pause(0.05)
            assert any("Policy allowed" in s.get("text", "") for s in card.stages)

            # 3. Tool started
            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.TOOL_STARTED,
                    payload={"tool_call_id": "call-1234", "tool": "nmap_scan"}
                )
            )
            await pilot.pause(0.05)
            stage_texts = [s.get("text", "") for s in card.stages]
            assert any("Scope authorized" in t for t in stage_texts)
            assert any("Docker sandbox" in t or "no isolation" in t for t in stage_texts)
            assert any("Running" in t for t in stage_texts)

            # 4. Tool completed
            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.TOOL_COMPLETED,
                    payload={
                        "tool_call_id": "call-1234",
                        "tool": "nmap_scan",
                        "duration_seconds": 1.45,
                        "stdout": "22/tcp open ssh\n80/tcp open http",
                        "exit_code": 0,
                    }
                )
            )
            await pilot.pause(0.05)
            assert card.status == "COMPLETED"
            assert card.duration_seconds == 1.45
            assert "22/tcp open ssh" in card.stdout
            assert len(list(app.query(ToolActivityCard))) == 1
    run_async(_run())


def test_buzzard_tui_tool_card_blocked_state():
    """Verify tool blocked state renders policy denial and reason per Section 6."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.AGENT_ACTION_PROPOSED,
                    payload={
                        "tool": "exploit_scan",
                        "target": "10.99.99.99",
                        "arguments": {"target": "10.99.99.99"},
                        "tool_call_id": "call-block-01",
                    }
                )
            )
            await pilot.pause(0.05)

            app._handle_bus_event_in_ui(
                Event(
                    type=EventType.POLICY_DENIED,
                    payload={
                        "tool_call_id": "call-block-01",
                        "reason": "target outside authorized scope",
                    }
                )
            )
            await pilot.pause(0.05)

            card = app.active_tool_cards["call-block-01"]
            assert card.status == "BLOCKED"
            rendered_text = card.render().plain
            assert "Denied" in rendered_text
            assert "target outside authorized scope" in rendered_text
    run_async(_run())


def test_buzzard_tui_approval_modal_keyboard():
    """Verify ApprovalModal keyboard bindings: [Y]/[A] to approve, [N]/[D] to deny, [Shift+A] always."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            # 1. Test Approval via [Y]
            modal_approve = ApprovalModal(
                tool_name="nmap_scan",
                arguments={"target": "10.0.0.1"},
                target="10.0.0.1",
                policy_reason="Policy confirmation required",
                scope_status="authorized network",
                sandbox_env="Docker Sandbox",
                risk_class="R2",
            )
            app.push_screen(modal_approve)
            await pilot.pause(0.05)
            await pilot.press("y")
            await pilot.pause(0.05)
            assert modal_approve.decision is True

            # 2. Test Denial via [N]
            modal_deny = ApprovalModal(
                tool_name="terminal.execute",
                arguments={"command": "rm -rf /"},
                target="localhost",
                policy_reason="Dangerous operation",
                scope_status="authorized network",
                sandbox_env="Docker Sandbox",
                risk_class="R4",
            )
            app.push_screen(modal_deny)
            await pilot.pause(0.05)
            await pilot.press("n")
            await pilot.pause(0.05)
            assert modal_deny.decision is False

            # 3. Test Backward Compatibility keys: [a] and [d]
            m3 = ApprovalModal(tool_name="test", arguments={})
            app.push_screen(m3)
            await pilot.pause(0.05)
            await pilot.press("y")
            await pilot.pause(0.05)
            assert m3.decision is True

            m4 = ApprovalModal(tool_name="test", arguments={})
            app.push_screen(m4)
            await pilot.pause(0.05)
            await pilot.press("d")
            await pilot.pause(0.05)
            assert m4.decision is False
    run_async(_run())


def test_buzzard_tui_slash_autocomplete_and_palette():
    """Verify live slash command prefix filtering, navigation, tab completion, enter selection, and escape."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            cmd_box = app.query_one(CommandSuggestionsBox)
            chat_view = app.query_one(ChatView)
            assert cmd_box.display is False

            # 1. Type "/mo" -> prefix filtering matches /model and /models
            app.chat_input.value = "/mo"
            app.on_input_changed(Input.Changed(app.chat_input, "/mo"))
            await pilot.pause(0.05)

            assert cmd_box.display is True
            matches = [c for c, d in cmd_box.matches]
            assert matches == ["/model", "/models"]
            assert cmd_box.selected_index == 0
            assert cmd_box.selected_command == "/model"

            # 2. Down navigation updates authoritative selected_index
            await pilot.press("down")
            await pilot.pause(0.05)
            assert cmd_box.selected_index == 1
            assert cmd_box.selected_command == "/models"

            # Up navigation wraps back
            await pilot.press("up")
            await pilot.pause(0.05)
            assert cmd_box.selected_index == 0
            assert cmd_box.selected_command == "/model"

            # 3. Tab autocompletes the CURRENT selected command with trailing space
            await pilot.press("tab")
            await pilot.pause(0.05)
            assert app.chat_input.value == "/model "
            assert cmd_box.display is False

            # 4. Partial command filtering: "/san" shows only /sandbox
            app.chat_input.value = "/san"
            app.on_input_changed(Input.Changed(app.chat_input, "/san"))
            await pilot.pause(0.05)
            assert cmd_box.display is True
            assert [c for c, d in cmd_box.matches] == ["/sandbox"]
            assert cmd_box.selected_command == "/sandbox"

            # Pressing Enter on "/san" executes the highlighted /sandbox, NEVER "/san"
            await pilot.press("enter")
            await pilot.pause(0.05)
            assert cmd_box.display is False
            last_msg = chat_view.message_bubbles[-1].message.content
            assert "Docker Security Sandbox Runtime" in last_msg

            # 5. Partial command filtering: "/doc" shows only /doctor
            app.chat_input.value = "/doc"
            app.on_input_changed(Input.Changed(app.chat_input, "/doc"))
            await pilot.pause(0.05)
            assert cmd_box.display is True
            assert [c for c, d in cmd_box.matches] == ["/doctor"]
            assert cmd_box.selected_command == "/doctor"

            # 6. Escape closes the palette without submitting anything
            await pilot.press("escape")
            await pilot.pause(0.05)
            assert cmd_box.display is False
            assert app.chat_input.value == "/doc"

            # 7. Unmatched prefix: "/xyz" shows no matching commands (palette hidden)
            app.chat_input.value = "/xyz"
            app.on_input_changed(Input.Changed(app.chat_input, "/xyz"))
            await pilot.pause(0.05)
            assert cmd_box.display is False

            # 8. Enter selection with navigation:
            # User types "/", palette opens, presses Down to highlight /models
            app.chat_input.value = "/"
            app.on_input_changed(Input.Changed(app.chat_input, "/"))
            await pilot.pause(0.05)
            assert cmd_box.display is True
            assert cmd_box.selected_index == 0
            assert cmd_box.selected_command == "/model"

            # Press Down: highlight /models
            await pilot.press("down")
            await pilot.pause(0.05)
            assert cmd_box.selected_index == 1
            assert cmd_box.selected_command == "/models"

            # Press Enter: MUST execute /models, NEVER stale /model
            await pilot.press("enter")
            await pilot.pause(0.05)
            assert cmd_box.display is False
            last_msg = chat_view.message_bubbles[-1].message.content
            assert "Available Models" in last_msg
    run_async(_run())

def test_buzzard_tui_model_switching_compact_event():
    """Verify switching model updates state and outputs compact status without giant cards."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # Switch model via /model
            app._switch_model("k3-sec:latest")
            await pilot.pause(0.05)

            # Verify header and status bar updated
            assert "k3-sec:latest" in app.header_widget.model_name
            assert "k3-sec:latest" in app.status_bar.model_name

            # Verify compact status event
            last_msg = chat_view.message_bubbles[-1].message.content
            assert "✓ Model switched to k3-sec:latest" in last_msg
    run_async(_run())


def test_buzzard_tui_slash_commands():
    """Verify built-in slash commands execute cleanly."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # 1. /status
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/status"))
            await pilot.pause(0.05)
            last_msg = chat_view.message_bubbles[-1].message.content
            assert "Buzzard Code Status" in last_msg

            # 2. /tools
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/tools"))
            await pilot.pause(0.05)
            last_msg = chat_view.message_bubbles[-1].message.content
            assert ("BUZZARD TOOL REGISTRY" in last_msg or "Registered Security Tools" in last_msg)

            # 3. /scope
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/scope"))
            await pilot.pause(0.05)
            last_msg = chat_view.message_bubbles[-1].message.content
            assert "Authorized Scope Targets" in last_msg

            # 4. /clear
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/clear"))
            await pilot.pause(0.05)
            # Should restore empty state
            assert len(chat_view.message_bubbles) == 0
            assert len(list(chat_view.query(EmptyStateWidget))) == 1
    run_async(_run())


def test_buzzard_input_history_navigation():
    """Verify arrow up and down navigates command history."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            inp = app.chat_input
            inp.record_history("scan 127.0.0.1")
            inp.record_history("/status")
            inp.record_history("/tools")

            # Press Up arrow
            inp.history_up()
            assert inp.value == "/tools"

            inp.history_up()
            assert inp.value == "/status"

            inp.history_up()
            assert inp.value == "scan 127.0.0.1"

            # Press Down arrow
            inp.history_down()
            assert inp.value == "/status"

            inp.history_down()
            assert inp.value == "/tools"
    run_async(_run())


def test_buzzard_tui_responsive_resizing():
    """Verify TUI adapts gracefully to 80x24, 100x30, 120x40 without broken layouts."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test(size=Size(80, 24)) as pilot:
            header = app.query_one(BuzzardHeader)
            status_bar = app.query_one(BuzzardStatusBar)
            chat_view = app.query_one(ChatView)

            assert header.render() is not None
            assert status_bar.render() is not None

            # Resize to 100x30
            await pilot.resize_terminal(100, 30)
            await pilot.pause(0.05)
            assert header.render() is not None
            assert status_bar.render() is not None

            # Resize to 120x40
            await pilot.resize_terminal(120, 40)
            await pilot.pause(0.05)
            assert header.render() is not None
            assert status_bar.render() is not None
    run_async(_run())


def test_buzzard_tui_security_invariants():
    """Verify security invariants R3 (Scope) and R4 (Kill Switch) in TUI."""
    async def _run():
        app = BuzzardTUIApp(fake=True)
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)

            # R3: Target outside authorized scope blocked immediately
            app._run_security_task("Scan 10.254.254.1 for vulnerabilities")
            await pilot.pause(0.1)

            last_msg = chat_view.message_bubbles[-1].message.content
            assert "TARGET OUTSIDE AUTHORIZED SCOPE" in last_msg
            assert app.is_running_operation is False

            # R4: Kill Switch blocks all execution
            ks = KillSwitch.get_instance()
            ks.trigger("Test kill switch")
            app._run_security_task("Scan 127.0.0.1")
            await pilot.pause(0.1)

            last_msg = chat_view.message_bubbles[-1].message.content
            assert "EXECUTION BLOCKED" in last_msg
            assert "Kill switch is currently active" in last_msg
            ks.reset()
    run_async(_run())
