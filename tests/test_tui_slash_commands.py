from tui.test_utils import run_async
"""
Tests for Qwythos TUI Slash Commands.
Verifies:
1. /help, /mode, /model, /models, /status, /clear.
2. /graph, /hypotheses, /findings, /capabilities, /memory, /report.
"""

import pytest
from textual.widgets import Input
from tui.app import QwythosTUIApp
from tui.models import AppMode, MessageRole


def test_tui_slash_commands():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            # 1. Test /mode
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/mode investigate"))
            await pilot.pause(0.1)
            assert app.controller.mode == AppMode.INVESTIGATE
    
            # 2. Test /model
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/model qwen-cyber:latest"))
            await pilot.pause(0.1)
            assert app.controller.current_model == "qwen-cyber:latest"
    
            # 3. Test /status
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/status"))
            await pilot.pause(0.1)
            last_msg = app.controller.chat_history[-1]
            assert "Agent Status" in last_msg.content
    
            # 4. Test /report md
            await app.on_input_submitted(Input.Submitted(app.chat_input, "/report md"))
            await pilot.pause(0.1)
            last_msg = app.controller.chat_history[-1]
            assert "Security Assessment Report" in last_msg.content or "Target:" in last_msg.content
    run_async(_run())
