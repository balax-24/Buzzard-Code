from security_agent.tui.test_utils import run_async
"""
Tests for Qwythos TUI Startup and Widget Composition.
Verifies:
1. Clean TUI initialization without errors.
2. Default mode is CHAT.
3. Proper widget hierarchy (Header, Sidebar tabs, ChatView, Input, StatusBar).
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.models import AppMode
from security_agent.tui.config import TUIConfig


def test_tui_startup_and_composition():
    async def _run():
        config = TUIConfig(default_model="qwythos:latest", default_mode="CHAT")
        app = QwythosTUIApp(config=config, use_fake_model=True)
    
        async with app.run_test() as pilot:
            assert app.controller.mode == AppMode.CHAT
            assert app.controller.current_model == "qwythos:latest"
    
            # Check widgets exist
            assert app.query_one("#app_header") is not None
            assert app.query_one("#left_sidebar") is not None
            assert app.query_one("#chat_container") is not None
            assert app.query_one("#user_input") is not None
            assert app.query_one("#app_status_bar") is not None
    run_async(_run())
