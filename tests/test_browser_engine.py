"""
Tests for BrowserEngine initialization, context creation, and graceful fallback.
"""

import pytest
from security_agent.browser import BrowserEngine, BrowserContext, BrowserPage


def test_browser_engine_launch_and_context_creation():
    engine = BrowserEngine(headless=True)
    engine.launch()
    assert engine._is_launched is True

    ctx = engine.new_context(role="admin", target_origin="http://localhost:8080")
    assert isinstance(ctx, BrowserContext)
    assert ctx.role == "admin"
    assert ctx.target_origin == "http://localhost:8080"
    assert ctx in engine.contexts

    page = ctx.new_page()
    assert isinstance(page, BrowserPage)
    assert page in ctx.pages
    assert ctx.get_active_page() == page

    engine.close()
    assert len(engine.contexts) == 0


def test_browser_engine_multi_context_isolation():
    engine = BrowserEngine(headless=True)
    engine.launch()

    ctx1 = engine.new_context(role="anonymous")
    ctx2 = engine.new_context(role="admin")

    p1 = ctx1.new_page()
    p2 = ctx2.new_page()

    assert p1.page_id != p2.page_id
    assert ctx1.context_id != ctx2.context_id

    ctx1.close()
    assert ctx1._is_closed is True
    assert ctx2._is_closed is False

    engine.close()
