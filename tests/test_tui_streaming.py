from security_agent.tui.test_utils import run_async
"""
Tests for Qwythos TUI Streaming Output.
Verifies:
1. Token-by-token streaming accumulation in ChatView.
2. Completion state handling.
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.models import ChatMessage, MessageRole
from security_agent.tui.widgets.chat import ChatView


def test_chat_view_streaming():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            chat_view = app.query_one(ChatView)
    
            msg = ChatMessage(role=MessageRole.ASSISTANT, content="", is_streaming=True)
            bubble = chat_view.add_message(msg)
    
            # Stream chunks
            chat_view.append_streaming_token("Hello ")
            chat_view.append_streaming_token("world ")
            chat_view.append_streaming_token("from ")
            chat_view.append_streaming_token("Qwythos!")
            chat_view.finish_streaming()
    
            assert bubble.message.content == "Hello world from Qwythos!"
            assert not bubble.message.is_streaming
    run_async(_run())
