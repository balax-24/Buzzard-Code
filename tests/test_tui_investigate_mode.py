from tui.test_utils import run_async
"""
Tests for Qwythos TUI Investigate Mode.
Verifies:
1. Candidate generation, planner prompt hierarchy, and tool execution.
2. Tool call card creation and graph synchronization.
"""

import pytest
from textual.widgets import Input
from tui.app import QwythosTUIApp
from tui.models import AppMode, MessageRole
from tui.config import TUIConfig


def test_investigate_mode_tool_execution():
    async def _run():
        config = TUIConfig(default_model="qwythos:latest", default_mode="INVESTIGATE")
        app = QwythosTUIApp(config=config, use_fake_model=True)
    
        async with app.run_test() as pilot:
            assert app.controller.mode == AppMode.INVESTIGATE
    
            # Submit investigation action
            await app.on_input_submitted(Input.Submitted(app.chat_input, "scan the target host"))
            await app.workers.wait_for_complete()
            await pilot.pause(0.1)
    
            # Verify assistant executed tool and generated tool card
            assert len(app.controller.chat_history) >= 2
            assistant_msg = app.controller.chat_history[1]
    
            assert assistant_msg.role == MessageRole.ASSISTANT
            assert len(assistant_msg.tool_cards) >= 1
            card = assistant_msg.tool_cards[0]
            assert card.tool_name == "http.request"
            assert card.status == "SUCCESS"
    run_async(_run())
