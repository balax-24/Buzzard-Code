from security_agent.tui.test_utils import run_async
"""
Tests for Qwythos TUI Chat Mode.
Verifies:
1. Normal conversational queries (JWT, coding questions).
2. Fast response without tool invocations or heavy security agent loops.
"""

import pytest
from textual.widgets import Input
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.models import AppMode, MessageRole
from security_agent.tui.config import TUIConfig


def test_chat_mode_conversational_turn():
    async def _run():
        config = TUIConfig(default_model="qwythos:latest", default_mode="CHAT")
        app = QwythosTUIApp(config=config, use_fake_model=True)
    
        async with app.run_test() as pilot:
            # Submit conversational query
            await app.on_input_submitted(Input.Submitted(app.chat_input, "explain how JWT authentication works"))
            await app.workers.wait_for_complete()
            await pilot.pause(0.1)
    
            # Verify chat history contains user message and assistant answer
            assert len(app.controller.chat_history) >= 2
            user_msg = app.controller.chat_history[0]
            assistant_msg = app.controller.chat_history[1]
    
            assert user_msg.role == MessageRole.USER
            assert "JWT" in user_msg.content
    
            assert assistant_msg.role == MessageRole.ASSISTANT
            assert "JSON Web Token" in assistant_msg.content
            assert len(assistant_msg.tool_cards) == 0  # Zero tools invoked in CHAT mode
    run_async(_run())
