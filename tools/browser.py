"""
Authoritative Browser Automation and Application-Surface Tools for Qwythos.

Provides tools for the Planner:
- browser.open
- browser.goto
- browser.snapshot
- browser.click
- browser.fill
- browser.press
- browser.submit
- browser.back
- browser.get_text
- browser.get_forms
- browser.get_links
- browser.get_html
- browser.get_url
- browser.network
- browser.extract_routes
- browser.screenshot
- browser.close
"""

from __future__ import annotations

import os
import base64
import uuid
import datetime
import atexit
from typing import Optional, List, Dict, Any

from model.schemas import Evidence, EvidenceType
from storage.db import StorageManager
from browser import (
    BrowserEngine,
    BrowserContext,
    BrowserPage,
    DOMSnapshot,
    DOMReducer,
    JavaScriptSurfaceExtractor,
    get_default_browser_engine,
)


class BrowserSessionManager:
    """Manages active browser context and page instances for tools."""

    def __init__(self):
        self._engine: Optional[BrowserEngine] = None
        self._active_context: Optional[BrowserContext] = None
        self._active_page: Optional[BrowserPage] = None

    def get_page(self) -> BrowserPage:
        if not self._engine:
            self._engine = get_default_browser_engine()
        if not self._active_context or self._active_context._is_closed:
            self._active_context = self._engine.new_context(role="default")
        if not self._active_page or self._active_page._is_closed:
            self._active_page = self._active_context.get_active_page()
        return self._active_page

    def get_context(self) -> BrowserContext:
        if not self._engine:
            self._engine = get_default_browser_engine()
        if not self._active_context or self._active_context._is_closed:
            self._active_context = self._engine.new_context(role="default")
        return self._active_context

    def close(self):
        if self._active_page:
            try:
                self._active_page.close()
            except Exception:
                pass
            self._active_page = None
        if self._active_context:
            try:
                self._active_context.close()
            except Exception:
                pass
            self._active_context = None


_session_mgr = BrowserSessionManager()
atexit.register(_session_mgr.close)


def _format_display(page: BrowserPage) -> str:
    return f"BROWSER\nURL: {page.url}\nTITLE: {page.title()}"


def browser_open(url: Optional[str] = None) -> str:
    """Launches the headless browser and opens a page. Optionally navigates to URL."""
    try:
        page = _session_mgr.get_page()
        if url:
            page.goto(url)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to open browser: {e}"


def browser_goto(url: str) -> str:
    """Navigates the browser to the specified URL."""
    try:
        page = _session_mgr.get_page()
        page.goto(url)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to navigate to {url}: {e}"


def browser_snapshot(url: Optional[str] = None) -> str:
    """Takes a structural DOM snapshot and returns reduced planner context."""
    try:
        page = _session_mgr.get_page()
        if url and url != page.url:
            page.goto(url)
        snapshot = page.snapshot()
        return snapshot.to_planner_context()
    except Exception as e:
        return f"TOOL ERROR: Failed to capture snapshot: {e}"


def browser_click(selector: str) -> str:
    """Clicks the element matching the specified selector."""
    try:
        page = _session_mgr.get_page()
        page.click(selector)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to click selector '{selector}': {e}"


def browser_fill(selector: str, value: str) -> str:
    """Fills the element matching the selector with the specified value."""
    try:
        page = _session_mgr.get_page()
        page.fill(selector, value)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to fill selector '{selector}' with value '{value}': {e}"


def browser_press(selector: str, key: str) -> str:
    """Presses a key on the element matching the selector."""
    try:
        page = _session_mgr.get_page()
        if page._pw_page:
            page._pw_page.press(selector, key)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to press '{key}' on selector '{selector}': {e}"


def browser_submit(selector: Optional[str] = None) -> str:
    """Submits the form matching selector or triggers the form submit control."""
    try:
        page = _session_mgr.get_page()
        page.submit(selector)
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to submit form: {e}"


def browser_back() -> str:
    """Navigates back to the previous page in history."""
    try:
        page = _session_mgr.get_page()
        page.go_back()
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to go back: {e}"


def browser_get_text(selector: Optional[str] = "body") -> str:
    """Retrieves visible text content matching selector."""
    try:
        page = _session_mgr.get_page()
        target_selector = selector if selector and selector.strip() and selector.lower() != "none" else "body"
        if page._pw_page:
            el = page._pw_page.query_selector(target_selector)
            if not el:
                return f"TOOL ERROR: Selector '{target_selector}' not found on the page."
            return el.inner_text()
        return page.snapshot().visible_text_snippet
    except Exception as e:
        return f"TOOL ERROR: Failed to retrieve text: {e}"


def browser_get_forms(url: Optional[str] = None) -> str:
    """Extracts all forms and input elements from the current page."""
    try:
        page = _session_mgr.get_page()
        if url and url != page.url:
            page.goto(url)
        snapshot = page.snapshot()
        if not snapshot.forms and not snapshot.inputs_outside_forms:
            return f"No forms or input elements found on {page.url}."

        results = [f"PAGE: {page.url} (Title: '{page.title()}')\n"]
        for idx, form in enumerate(snapshot.forms, 1):
            results.append(f"Form #{idx} [id='{form.form_id}', method='{form.method}', action='{form.action}']:")
            for inp in form.fields:
                results.append(
                    f"  - <input type='{inp.type}' name='{inp.name}' id='{inp.id}' "
                    f"placeholder='{inp.placeholder}' value='{inp.value}'"
                    f"{' [CSRF]' if inp.is_csrf else ''}>"
                )
            results.append("")

        if snapshot.inputs_outside_forms:
            results.append("Input elements outside forms:")
            for inp in snapshot.inputs_outside_forms:
                results.append(
                    f"  - <input type='{inp.type}' name='{inp.name}' id='{inp.id}' placeholder='{inp.placeholder}'>"
                )

        return "\n".join(results)
    except Exception as e:
        return f"TOOL ERROR: Failed to extract forms: {e}"


def browser_get_links(selector: Optional[str] = None) -> str:
    """Retrieves all discovered links found on the page."""
    try:
        page = _session_mgr.get_page()
        snapshot = page.snapshot()
        if not snapshot.links:
            return "No links found on this page."
        results = [f"- {l.text or '[Link]'}: {l.href}" for l in snapshot.links]
        return "\n".join(results[:50])
    except Exception as e:
        return f"TOOL ERROR: Failed to retrieve links: {e}"


def browser_get_html(selector: Optional[str] = "body", max_length: int = 4000) -> str:
    """Retrieves HTML markup of the specified selector or body."""
    try:
        page = _session_mgr.get_page()
        target_selector = selector if selector and selector.strip() and selector.lower() != "none" else "body"
        if page._pw_page:
            el = page._pw_page.query_selector(target_selector)
            if not el:
                return f"TOOL ERROR: Selector '{target_selector}' not found on page."
            html = el.inner_html()
        else:
            html = page._raw_html_cache or "<html><body></body></html>"

        if len(html) > max_length:
            html = html[:max_length] + f"\n... [Truncated {len(html) - max_length} chars.]"
        return html
    except Exception as e:
        return f"TOOL ERROR: Failed to retrieve HTML: {e}"


def browser_get_url() -> str:
    """Returns the current browser URL and title."""
    try:
        page = _session_mgr.get_page()
        return _format_display(page)
    except Exception as e:
        return f"TOOL ERROR: Failed to get URL/title: {e}"


def browser_network() -> str:
    """Dumps captured background API requests, failed calls, and WebSocket telemetry."""
    try:
        page = _session_mgr.get_page()
        events = page.get_network_events()
        if not events:
            return "No network events captured."

        lines = ["=== CAPTURED NETWORK TELEMETRY ==="]
        apis = [e for e in events if e.is_api_call]
        if apis:
            lines.append("API & BACKGROUND REQUESTS:")
            for a in apis[:15]:
                lines.append(f"  • [{a.method}] {a.url} (Status: {a.status}, Type: {a.content_type})")

        failures = [e for e in events if e.error_message or (e.status >= 400 and e.status != 404)]
        if failures:
            lines.append("FAILED / ERROR REQUESTS:")
            for f in failures[:10]:
                lines.append(f"  • [{f.method}] {f.url} (Status: {f.status}, Err: {f.error_message or 'HTTP Error'})")

        ws = page.network_recorder.get_websockets()
        if ws:
            lines.append("WEBSOCKET ACTIVITY:")
            for w in ws[:10]:
                lines.append(f"  • {w.event_type}: {w.url}")

        lines.append("===================================")
        return "\n".join(lines)
    except Exception as e:
        return f"TOOL ERROR: Failed to retrieve network telemetry: {e}"


def browser_extract_routes() -> str:
    """Extracts static and dynamic JavaScript endpoints, REST routes, and WebSocket URLs."""
    try:
        page = _session_mgr.get_page()
        routes = page.extract_javascript_routes()
        apis = routes.get("api_candidates", [])
        ws = routes.get("websockets", [])

        if not apis and not ws:
            return "No JavaScript routes or WebSockets discovered in page scripts."

        lines = ["=== JAVASCRIPT SURFACE DISCOVERY ==="]
        if apis:
            lines.append("DISCOVERED ENDPOINTS:")
            for a in apis:
                lines.append(f"  • [{a.method}] {a.url} ({a.source_context})")
        if ws:
            lines.append("DISCOVERED WEBSOCKETS:")
            for w in ws:
                lines.append(f"  • {w.url}")
        lines.append("=====================================")
        return "\n".join(lines)
    except Exception as e:
        return f"TOOL ERROR: Failed to extract routes: {e}"


def browser_screenshot(
    session_id: str,
    storage_manager: StorageManager,
    name: Optional[str] = None
) -> str:
    """Takes a screenshot of the current page and saves it in the evidence store."""
    try:
        page = _session_mgr.get_page()
        if page._pw_page:
            screenshot_bytes = page._pw_page.screenshot(type="png")
            b64_data = base64.b64encode(screenshot_bytes).decode("utf-8")
        else:
            b64_data = base64.b64encode(b"SIMULATED_SCREENSHOT_BYTES").decode("utf-8")

        evidence_id = f"EVI-{uuid.uuid4().hex[:6]}"
        timestamp = datetime.datetime.now().isoformat()

        evidence = Evidence(
            id=evidence_id,
            type=EvidenceType.SCREENSHOT,
            target=page.url,
            description=f"Screenshot of page: {name or page.title()}",
            data=b64_data,
            timestamp=timestamp
        )
        storage_manager.add_evidence(session_id, evidence)
        return f"Screenshot logged successfully with ID: {evidence_id}\n\n{_format_display(page)}"
    except Exception as e:
        return f"TOOL ERROR: Failed to take screenshot: {e}"


def browser_close() -> str:
    """Closes the active browser session."""
    try:
        _session_mgr.close()
        return "Browser closed successfully."
    except Exception as e:
        return f"TOOL ERROR: Failed to close browser: {e}"


def register_browser_tools(registry):
    """Registers the full suite of browser tools within the ToolRegistry."""
    registry.register(
        name="browser.open",
        description="Launches the headless browser and opens a page. Arguments: url (str, optional).",
        func=browser_open
    )
    registry.register(
        name="browser.goto",
        description="Navigates the browser to the specified URL. Arguments: url (str).",
        func=browser_goto
    )
    registry.register(
        name="browser.snapshot",
        description="Captures a structural DOM snapshot, extracting forms, links, scripts, and API candidates with size reduction. Arguments: url (str, optional).",
        func=browser_snapshot
    )
    registry.register(
        name="browser.click",
        description="Clicks the element matching the specified selector. Arguments: selector (str).",
        func=browser_click
    )
    registry.register(
        name="browser.fill",
        description="Fills the element matching the selector with the specified value. Arguments: selector (str), value (str).",
        func=browser_fill
    )
    registry.register(
        name="browser.press",
        description="Presses a key on the element matching the selector. Arguments: selector (str), key (str).",
        func=browser_press
    )
    registry.register(
        name="browser.submit",
        description="Submits a form matching the specified selector or triggers form submit. Arguments: selector (str, optional).",
        func=browser_submit
    )
    registry.register(
        name="browser.back",
        description="Navigates back to the previous page in history. Arguments: None.",
        func=browser_back
    )
    registry.register(
        name="browser.get_text",
        description="Retrieves the visible text content of the element matching the selector. Arguments: selector (str, default 'body').",
        func=browser_get_text
    )
    registry.register(
        name="browser.get_forms",
        description="Extracts all input forms, input names, IDs, placeholders, buttons, and action endpoints on the current page or specified URL. Arguments: url (str, optional).",
        func=browser_get_forms
    )
    registry.register(
        name="browser.get_html",
        description="Retrieves the HTML markup of the specified selector or body. Arguments: selector (str, optional, default 'body').",
        func=browser_get_html
    )
    registry.register(
        name="browser.get_links",
        description="Retrieves all links (text content and href) found on the current page. Arguments: selector (str, optional).",
        func=browser_get_links
    )
    registry.register(
        name="browser.get_url",
        description="Returns the current browser URL and title. Arguments: None.",
        func=browser_get_url
    )
    registry.register(
        name="browser.network",
        description="Retrieves captured background API calls, failed requests, and WebSocket telemetry. Arguments: None.",
        func=browser_network
    )
    registry.register(
        name="browser.extract_routes",
        description="Extracts JavaScript routes, API candidates, and WebSocket URLs from page scripts. Arguments: None.",
        func=browser_extract_routes
    )
    registry.register(
        name="browser.screenshot",
        description="Takes a screenshot of the current page and saves it in the evidence store. Arguments: name (str, optional).",
        func=browser_screenshot
    )
    registry.register(
        name="browser.close",
        description="Closes the active browser session. Arguments: None.",
        func=browser_close
    )
