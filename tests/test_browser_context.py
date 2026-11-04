"""
Tests for BrowserContext lifecycle, page creation, and state management.
"""

import pytest
from security_agent.browser import BrowserContext, BrowserPage
from security_agent.browser.errors import ContextClosedError


def test_browser_context_page_lifecycle():
    ctx = BrowserContext(role="user", target_origin="http://target.local")
    assert ctx.role == "user"
    assert len(ctx.pages) == 0

    p1 = ctx.new_page()
    assert isinstance(p1, BrowserPage)
    assert len(ctx.pages) == 1
    assert ctx.get_active_page() == p1

    p2 = ctx.new_page()
    assert len(ctx.pages) == 2
    assert ctx.get_active_page() == p2

    ctx.close()
    assert ctx._is_closed is True
    assert p1._is_closed is True
    assert p2._is_closed is True

    with pytest.raises(ContextClosedError):
        ctx.new_page()

    with pytest.raises(ContextClosedError):
        ctx.get_active_page()
