from security_agent.tui.test_utils import run_async
"""
Tests for Browser Panel Widget.
Verifies:
1. Browser DOM element, form, and endpoint rendering.
"""

import pytest
from security_agent.tui.app import QwythosTUIApp
from security_agent.tui.widgets.browser_panel import BrowserPanel
from security_agent.agent.assessment_state import HTTPEndpointRecord, HTTPState


def test_browser_panel():
    async def _run():
        app = QwythosTUIApp(use_fake_model=True)
    
        async with app.run_test() as pilot:
            panel = app.query_one(BrowserPanel)
    
            # Add endpoint
            app.controller.state.http_endpoints["http://127.0.0.1:8080/dashboard"] = HTTPEndpointRecord(
                url="http://127.0.0.1:8080/dashboard",
                host="127.0.0.1",
                port=8080,
                path="/dashboard",
                state=HTTPState.RESPONDS,
                status_code=200
            )
            panel.refresh_panel()
    
            assert "/dashboard" in panel.raw_text
    run_async(_run())
