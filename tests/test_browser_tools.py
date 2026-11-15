"""Tests for browser checks (roadmap D4): a stubbed Playwright page, SSRF, plan mode, cleanup."""

import pytest

from tools import browser_tools, web_tools
from tools.browser_tools import (
    page_click, page_console, page_open, page_read, page_screenshot, page_type,
    cleanup_session_browsers,
)
from tools.web_tools import WebSettings


class _Console:
    def __init__(self, level, text):
        self._level, self._text = level, text

    @property
    def type(self):
        return self._level

    def text(self):  # Playwright exposes text() as a method; the recorder handles both
        return self._text


class FakePage:
    def __init__(self):
        self.url = "about:blank"
        self._title = ""
        self._body = ""
        self._handlers = {}
        self.clicks = []
        self.fills = []
        self.screenshots = []
        self.closed = False

    def on(self, event, handler):
        self._handlers[event] = handler

    def emit_console(self, level, text):
        self._handlers["console"](_Console(level, text))

    def goto(self, url, timeout=None, wait_until=None):
        if "boom" in url:
            raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")
        self.url = url
        self._title = "Example Domain"
        self._body = "Example Domain\nMore information..."
        return type("Resp", (), {"status": 200})()

    def title(self):
        return self._title

    def inner_text(self, selector):
        assert selector == "body"
        return self._body

    def content(self):
        return f"<html><body>{self._body}</body></html>"

    def click(self, selector, timeout=None):
        if selector == "#missing":
            raise RuntimeError("Timeout: selector not found")
        self.clicks.append(selector)
        self.url = "https://example.com/clicked"

    def fill(self, selector, value, timeout=None):
        if selector == "#missing":
            raise RuntimeError("selector not found")
        self.fills.append((selector, value))

    def screenshot(self, path=None, full_page=None):
        with open(path, "wb") as handle:
            handle.write(b"\x89PNG\r\n")
        self.screenshots.append(path)

    def close(self):
        self.closed = True


@pytest.fixture
def fake(monkeypatch, tmp_path):
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(browser_tools, "_load_browser_settings", lambda: WebSettings())
    page = FakePage()
    monkeypatch.setattr(browser_tools, "_launch_page", lambda: (page, page.close))
    browser_tools._SESSIONS.clear()
    yield page
    browser_tools._SESSIONS.clear()


def test_open_read_click_type_flow(fake):
    out = page_open("https://example.com/", session_id="s1")
    assert "Opened https://example.com/" in out and "Status: 200" in out and "Example Domain" in out
    assert "Example Domain" in page_read(session_id="s1")
    assert "clicked" in page_click("a#more", session_id="s1")
    assert fake.clicks == ["a#more"]
    assert page_type("input#q", "hello", session_id="s1").startswith("Typed")
    assert fake.fills == [("input#q", "hello")]


def test_actions_before_open_are_refused(fake):
    for call in (lambda: page_read("s9"), lambda: page_click("a", "s9"),
                 lambda: page_type("a", "b", "s9"), lambda: page_screenshot("s9"),
                 lambda: page_console("s9")):
        assert "no page is open" in call()


def test_navigation_error_is_reported(fake):
    out = page_open("https://boom.example.com/", session_id="s1")
    assert out.startswith("Error") and "could not open" in out


def test_missing_selector_errors(fake):
    page_open("https://example.com/", session_id="s1")
    assert page_click("#missing", session_id="s1").startswith("Error")
    assert page_type("#missing", "x", session_id="s1").startswith("Error")
    assert page_click("  ", session_id="s1").startswith("Error")


def test_screenshot_written_under_buzzard_home(fake, tmp_path):
    page_open("https://example.com/", session_id="s1")
    out = page_screenshot(session_id="s1")
    path = out.split("Saved screenshot to ", 1)[1].strip()
    assert path.endswith("shot-001.png")
    assert str(tmp_path / "home") in path
    with open(path, "rb") as handle:
        assert handle.read().startswith(b"\x89PNG")
    assert "shot-002.png" in page_screenshot(session_id="s1")


def test_console_messages_errors_first(fake):
    page_open("https://example.com/", session_id="s1")
    fake.emit_console("log", "hi")
    fake.emit_console("error", "boom failed")
    fake.emit_console("warning", "careful")
    out = page_console(session_id="s1")
    lines = out.splitlines()
    assert "1 error(s)" in lines[0]
    assert lines[1].startswith("[error]") and lines[2].startswith("[warning]")


def test_ssrf_and_bad_url_refused(fake, monkeypatch):
    assert page_open("ftp://example.com", session_id="s1").startswith("Error")
    assert page_open("   ", session_id="s1").startswith("Error")
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["127.0.0.1"])
    out = page_open("http://localhost/admin", session_id="s1")
    assert out.startswith("Error") and "non-public" in out


def test_deny_list(fake, monkeypatch):
    monkeypatch.setattr(browser_tools, "_load_browser_settings", lambda: WebSettings(deny=("example.com",)))
    assert "deny list" in page_open("https://sub.example.com/", session_id="s1")


def test_sessions_are_isolated_and_cleaned_up(fake, monkeypatch):
    pages = {}

    def factory():
        page = FakePage()
        pages[len(pages)] = page
        return page, page.close

    monkeypatch.setattr(browser_tools, "_launch_page", factory)
    page_open("https://example.com/a", session_id="s1")
    page_open("https://example.com/b", session_id="s2")
    assert len(pages) == 2
    assert cleanup_session_browsers("s1") == 1
    assert pages[0].closed is True and pages[1].closed is False
    assert cleanup_session_browsers("s1") == 0  # already gone
    assert cleanup_session_browsers("s2") == 1


def test_settings_validation(monkeypatch):
    import core.config as config_mod

    monkeypatch.setattr(config_mod, "load_merged_config", lambda: {})
    assert browser_tools._load_browser_settings() == WebSettings()
    monkeypatch.setattr(config_mod, "load_merged_config",
                        lambda: {"browser": {"deny": ["Bad.COM", ".internal"], "allow_private": True}})
    settings = browser_tools._load_browser_settings()
    assert settings.deny == ("bad.com", "internal") and settings.allow_private is True
    for bad in ({"browser": []}, {"browser": {"allow": "nope"}}, {"browser": {"deny": [1]}}):
        monkeypatch.setattr(config_mod, "load_merged_config", lambda bad=bad: bad)
        with pytest.raises(ValueError):
            browser_tools._load_browser_settings()


def test_registered_needs_approval_and_network():
    from agent.loop import CODING_TOOL_NAMES
    from tools.registry import create_authoritative_registry

    registry = create_authoritative_registry()
    for name in ("page_open", "page_read", "page_click", "page_type",
                 "page_screenshot", "page_console"):
        definition = registry.definitions[name]
        assert definition.approval_required and definition.network_required
        assert not definition.scope_required
        assert name in CODING_TOOL_NAMES


def test_plan_mode_refuses_browser_tools():
    from agent.run_session import RunSession

    session = RunSession(None, None, None, {}, ask_approval=lambda request: "allow")
    session.plan_mode = True
    assert session.approve("page_open", {"url": "https://example.com"}, None) is False
    session.plan_mode = False
    assert session.approve("page_open", {"url": "https://example.com"}, None) is True


def test_scope_does_not_block_browser_tools():
    from security.policy import PolicyEngine

    engine = PolicyEngine(["localhost"])
    assert engine._check_scope("page_open", {"url": "https://example.com/doc"})[0] is True
