"""
Browser checks for Buzzard Code (roadmap D4).

Approval-gated tools that drive a headless Chromium browser (Playwright) so the coding agent can
verify a UI change: open a page, read its text, click, type, screenshot it and read its console
errors. One browser session is kept per task and closed when the task ends, like managed processes.

- ``page_open(url)``: navigate; returns the final URL, title and HTTP status.
- ``page_read()``: the readable text of the current page.
- ``page_click(selector)``: click a CSS selector.
- ``page_type(selector, text)``: type into a CSS selector.
- ``page_screenshot()``: save a PNG under ``BUZZARD_HOME/browser/<task>/`` and return its path.
- ``page_console()``: the console messages collected since the page opened (errors first).

Safety (AGENTS.md §19 and §24):

- Every tool needs operator approval and is refused in plan mode, like every network tool.
- ``page_open`` validates the URL with the same guard as the web tools: only http(s); the host
  must resolve to a public address (loopback, private, link-local and reserved ranges are refused
  unless ``browser.allow_private``); and the ``browser.allow`` / ``browser.deny`` domain lists apply.
- Screenshots are written under ``BUZZARD_HOME``, never into the repository, so a verification
  artifact never changes the working tree.

Automatic inclusion of a browser step in the completion gate is not built yet; these tools let the
agent (or a user) run and record the check by hand.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from tools.web_tools import WebSettings, WebError, _to_text, _validate_url

NAVIGATION_TIMEOUT_MS = 30_000
ACTION_TIMEOUT_MS = 10_000
MAX_TEXT_CHARS = 8_000
MAX_CONSOLE_MESSAGES = 200
VIEWPORT = {"width": 1280, "height": 800}
USER_AGENT = "BuzzardCode/1.0 (+https://github.com/balax-24/Buzzard-Code)"


def _load_browser_settings() -> WebSettings:
    """Reads the ``browser`` config section into the shared allow/deny/allow_private shape."""
    from core.config import load_merged_config

    raw = load_merged_config().get("browser")
    raw = {} if raw is None else raw
    if not isinstance(raw, dict):
        raise ValueError("browser must be an object.")

    def _domains(key: str) -> Tuple[str, ...]:
        value = raw.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            raise ValueError(f"browser.{key} must be a list of domain strings.")
        return tuple(v.strip().lower().lstrip(".") for v in value)

    return WebSettings(_domains("allow"), _domains("deny"), bool(raw.get("allow_private", False)))


def _launch_page() -> Tuple[Any, Callable[[], None]]:
    """Launches headless Chromium and returns (page, close). Overridden in tests."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:  # pragma: no cover - exercised only without Playwright installed
        raise WebError("Playwright is not installed; run `playwright install chromium`.") from error

    playwright = sync_playwright().start()
    try:
        browser = playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        context = browser.new_context(user_agent=USER_AGENT, viewport=VIEWPORT, ignore_https_errors=False)
        page = context.new_page()
    except Exception as error:
        playwright.stop()
        raise WebError(f"Could not start the browser: {error}") from error

    def close() -> None:
        for step in (page.close, context.close, browser.close, playwright.stop):
            try:
                step()
            except Exception:
                pass

    return page, close


class _BrowserSession:
    """One task's browser page, created on first use and closed at task end."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._page: Optional[Any] = None
        self._close: Optional[Callable[[], None]] = None
        self._console: List[Dict[str, str]] = []
        self._shots = 0

    def page(self) -> Any:
        if self._page is None:
            page, close = _launch_page()
            page.on("console", self._record_console)
            self._page, self._close = page, close
        return self._page

    def _record_console(self, message: Any) -> None:
        try:
            level = getattr(message, "type", None)
            level = level() if callable(level) else level
            text = getattr(message, "text", None)
            text = text() if callable(text) else text
        except Exception:
            return
        if len(self._console) < MAX_CONSOLE_MESSAGES:
            self._console.append({"level": str(level or "log"), "text": str(text or "")})

    def console(self) -> List[Dict[str, str]]:
        return list(self._console)

    def next_screenshot_path(self) -> Path:
        base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "browser"
        key = hashlib.sha1((self.session_id or "default").encode()).hexdigest()[:12]
        folder = base / key
        folder.mkdir(parents=True, exist_ok=True)
        self._shots += 1
        return folder / f"shot-{self._shots:03d}.png"

    def close(self) -> None:
        if self._close is not None:
            self._close()
        self._page, self._close, self._console = None, None, []


_SESSIONS: Dict[str, _BrowserSession] = {}
_LOCK = threading.Lock()


def _session(session_id: str) -> _BrowserSession:
    with _LOCK:
        return _SESSIONS.setdefault(session_id or "default", _BrowserSession(session_id or "default"))


def cleanup_session_browsers(session_id: str) -> int:
    """Close and forget the browser owned by a completed or cancelled run."""
    key = session_id or "default"
    with _LOCK:
        session = _SESSIONS.pop(key, None)
    if session is None:
        return 0
    session.close()
    return 1


def page_open(url: str, session_id: str = "") -> str:
    """
    Opens a web page in the task's headless browser.
    Arguments:
        url: An http(s) URL. Only public hosts are reached.
    """
    url = str(url or "").strip()
    if not url:
        return "Error: url must not be empty."
    try:
        _validate_url(url, _load_browser_settings())
    except (WebError, ValueError) as error:
        return f"Error: {error}"
    try:
        page = _session(session_id).page()
        response = page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")
    except WebError as error:
        return f"Error: {error}"
    except Exception as error:
        return f"Error: could not open {url}: {type(error).__name__}: {error}"
    status = getattr(response, "status", None)
    status = status() if callable(status) else status
    try:
        title = page.title()
    except Exception:
        title = ""
    return f"Opened {page.url}\nTitle: {title or '(none)'}\nStatus: {status if status is not None else 'unknown'}"


def _require_page(session_id: str) -> Tuple[Optional[Any], str]:
    session = _session(session_id)
    if session._page is None:
        return None, "Error: no page is open; call page_open first."
    return session._page, ""


def page_read(session_id: str = "") -> str:
    """Returns the readable text of the current page."""
    page, problem = _require_page(session_id)
    if page is None:
        return problem
    try:
        text = page.inner_text("body")
    except Exception:
        try:
            text = _to_text(page.content())
        except Exception as error:
            return f"Error: could not read the page: {type(error).__name__}: {error}"
    text = (text or "").strip()
    if not text:
        return f"(The page at {page.url} has no readable text.)"
    truncated = "" if len(text) <= MAX_TEXT_CHARS else f"\n\n[... truncated at {MAX_TEXT_CHARS} characters]"
    return f"{page.url}\n\n{text[:MAX_TEXT_CHARS]}{truncated}"


def page_click(selector: str, session_id: str = "") -> str:
    """
    Clicks the first element matching a CSS selector.
    Arguments:
        selector: A CSS selector, e.g. 'button#save'.
    """
    selector = str(selector or "").strip()
    if not selector:
        return "Error: selector must not be empty."
    page, problem = _require_page(session_id)
    if page is None:
        return problem
    try:
        page.click(selector, timeout=ACTION_TIMEOUT_MS)
    except Exception as error:
        return f"Error: could not click '{selector}': {type(error).__name__}: {error}"
    return f"Clicked '{selector}'. Now at {page.url}."


def page_type(selector: str, text: str, session_id: str = "") -> str:
    """
    Types text into the first element matching a CSS selector.
    Arguments:
        selector: A CSS selector for an input or textarea.
        text: The text to type.
    """
    selector = str(selector or "").strip()
    if not selector:
        return "Error: selector must not be empty."
    page, problem = _require_page(session_id)
    if page is None:
        return problem
    try:
        page.fill(selector, str(text), timeout=ACTION_TIMEOUT_MS)
    except Exception as error:
        return f"Error: could not type into '{selector}': {type(error).__name__}: {error}"
    return f"Typed into '{selector}'."


def page_screenshot(session_id: str = "") -> str:
    """Saves a PNG screenshot of the current page and returns its file path."""
    session = _session(session_id)
    if session._page is None:
        return "Error: no page is open; call page_open first."
    path = session.next_screenshot_path()
    try:
        session._page.screenshot(path=str(path), full_page=True)
    except Exception as error:
        return f"Error: could not take a screenshot: {type(error).__name__}: {error}"
    return f"Saved screenshot to {path}"


def page_console(session_id: str = "") -> str:
    """Returns the console messages collected since the page opened, errors first."""
    session = _session(session_id)
    if session._page is None:
        return "Error: no page is open; call page_open first."
    messages = session.console()
    if not messages:
        return "No console messages."
    order = {"error": 0, "warning": 1}
    messages.sort(key=lambda m: order.get(m["level"], 2))
    errors = sum(1 for m in messages if m["level"] == "error")
    lines = [f"[{m['level']}] {m['text'][:300]}" for m in messages]
    return f"{len(messages)} console message(s), {errors} error(s):\n" + "\n".join(lines)


def register_browser_tools(registry) -> None:
    """Registers the approval-gated browser-check tools."""
    from tools.registry import ToolCategory

    network = dict(
        category=ToolCategory.WEB, risk_level="MEDIUM", read_only=True, destructive=False,
        network_required=True, sandbox_required=False, scope_required=False,
        approval_required=True, timeout=90,
    )
    registry.register(
        name="page_open",
        description="Opens an http(s) page in a headless browser (public hosts only). Needs approval and network access. Arguments: url (str).",
        func=page_open, **network,
    )
    registry.register(
        name="page_read",
        description="Returns the readable text of the current browser page. Needs approval. Arguments: none.",
        func=page_read, **network,
    )
    registry.register(
        name="page_click",
        description="Clicks the first element matching a CSS selector in the current page. Needs approval. Arguments: selector (str).",
        func=page_click, **network,
    )
    registry.register(
        name="page_type",
        description="Types text into a CSS selector in the current page. Needs approval. Arguments: selector (str), text (str).",
        func=page_type, **network,
    )
    registry.register(
        name="page_screenshot",
        description="Saves a PNG screenshot of the current page under BUZZARD_HOME and returns its path. Needs approval. Arguments: none.",
        func=page_screenshot, **network,
    )
    registry.register(
        name="page_console",
        description="Returns the console messages (errors first) collected since the page opened. Needs approval. Arguments: none.",
        func=page_console, **network,
    )
