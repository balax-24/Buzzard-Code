"""
BrowserPage abstraction for Qwythos Application-Surface Intelligence.

Provides a unified interface for page navigation, element interaction,
structural DOM snapshotting, network telemetry, and JavaScript route extraction.
"""

from __future__ import annotations

import time
import uuid
import urllib.parse
from typing import Optional, Dict, Any, List

from security_agent.browser.dom import DOMSnapshot, DOMReducer, JavaScriptSurfaceExtractor
from security_agent.browser.network import NetworkRecorder, NetworkEvent, WebSocketEvent
from security_agent.browser.errors import (
    BrowserError,
    NavigationTimeoutError,
    SelectorNotFoundError,
    ContextClosedError,
    FormSubmissionError,
)


class BrowserPage:
    """
    Authoritative abstraction over a browser page / tab.
    Decouples higher-level assessment logic from specific browser engine implementations.
    """

    def __init__(
        self,
        page_id: Optional[str] = None,
        playwright_page: Optional[Any] = None,
        network_recorder: Optional[NetworkRecorder] = None,
        context: Optional[Any] = None,
    ):
        self.page_id = page_id or f"PAGE-{uuid.uuid4().hex[:6].upper()}"
        self._pw_page = playwright_page
        self.network_recorder = network_recorder or NetworkRecorder()
        self.context = context
        self._current_url = "about:blank"
        self._current_title = "Blank"
        self._current_status = 200
        self._raw_html_cache: str = ""
        self._is_closed = False

        if self._pw_page:
            self._attach_network_listeners()

    def _attach_network_listeners(self) -> None:
        """Attaches request, response, and websocket telemetry hooks to Playwright page."""
        if not self._pw_page:
            return

        def on_request(req):
            try:
                self.network_recorder.record_request(
                    url=req.url,
                    method=req.method,
                    headers=req.headers,
                    initiator=req.resource_type or "other",
                    payload=req.post_data or ""
                )
            except Exception:
                pass

        def on_response(res):
            try:
                self.network_recorder.record_response(
                    url=res.url,
                    status=res.status,
                    headers=res.headers,
                    content_type=res.headers.get("content-type", "")
                )
            except Exception:
                pass

        def on_request_failed(req):
            try:
                err = req.failure
                self.network_recorder.record_failed(
                    url=req.url,
                    error_message=str(err) if err else "Request failed"
                )
            except Exception:
                pass

        def on_websocket(ws):
            try:
                self.network_recorder.record_websocket_event(
                    url=ws.url,
                    origin_page=self.url,
                    event_type="CONNECT"
                )
                ws.on("framereceived", lambda payload: self.network_recorder.record_websocket_event(
                    url=ws.url, origin_page=self.url, event_type="MESSAGE_RECEIVED", payload=str(payload)
                ))
                ws.on("framesent", lambda payload: self.network_recorder.record_websocket_event(
                    url=ws.url, origin_page=self.url, event_type="MESSAGE_SENT", payload=str(payload)
                ))
            except Exception:
                pass

        try:
            self._pw_page.on("request", on_request)
            self._pw_page.on("response", on_response)
            self._pw_page.on("requestfailed", on_request_failed)
            self._pw_page.on("websocket", on_websocket)
        except Exception:
            pass

    @property
    def url(self) -> str:
        if self._pw_page and not self._is_closed:
            try:
                return self._pw_page.url
            except Exception:
                pass
        return self._current_url

    @property
    def status_code(self) -> int:
        return self._current_status

    def title(self) -> str:
        if self._pw_page and not self._is_closed:
            try:
                return self._pw_page.title()
            except Exception:
                pass
        return self._current_title

    def goto(self, url: str, timeout: int = 30) -> Dict[str, Any]:
        """Navigates page to target URL."""
        if self._is_closed:
            raise ContextClosedError("Cannot navigate closed page.")

        start_time = time.time()
        self._current_url = url

        if self._pw_page:
            try:
                res = self._pw_page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                self._current_status = res.status if res else 200
                self._current_url = self._pw_page.url
                self._current_title = self._pw_page.title()
                try:
                    self._raw_html_cache = self._pw_page.content()
                except Exception:
                    self._raw_html_cache = ""
            except Exception as e:
                err_str = str(e)
                if "Timeout" in err_str:
                    raise NavigationTimeoutError(f"Navigation to {url} timed out after {timeout}s: {e}")
                raise BrowserError(f"Failed to navigate to {url}: {e}")
        else:
            # Synthetic navigation for offline/lab tests
            self._current_title = f"Page: {url}"
            self._current_status = 200

        elapsed = time.time() - start_time
        return {
            "page_id": self.page_id,
            "url": self.url,
            "title": self.title(),
            "status": self.status_code,
            "duration": round(elapsed, 4),
        }

    def click(self, selector: str, timeout: int = 5) -> Dict[str, Any]:
        """Clicks element matching CSS selector."""
        if self._is_closed:
            raise ContextClosedError("Cannot interact with closed page.")

        start_time = time.time()
        if self._pw_page:
            try:
                self._pw_page.click(selector, timeout=timeout * 1000)
                try:
                    self._pw_page.wait_for_load_state("domcontentloaded", timeout=2000)
                except Exception:
                    pass
                self._current_url = self._pw_page.url
                self._current_title = self._pw_page.title()
                try:
                    self._raw_html_cache = self._pw_page.content()
                except Exception:
                    pass
            except Exception as e:
                err_str = str(e)
                if "not found" in err_str.lower() or "timeout" in err_str.lower():
                    raise SelectorNotFoundError(f"Selector '{selector}' not found: {e}")
                raise BrowserError(f"Failed to click selector '{selector}': {e}")
        else:
            # Synthetic click
            pass

        return {
            "page_id": self.page_id,
            "action": "click",
            "selector": selector,
            "url": self.url,
            "duration": round(time.time() - start_time, 4)
        }

    def fill(self, selector: str, value: str, timeout: int = 5) -> Dict[str, Any]:
        """Fills element matching selector with value."""
        if self._is_closed:
            raise ContextClosedError("Cannot interact with closed page.")

        start_time = time.time()
        if self._pw_page:
            try:
                self._pw_page.fill(selector, value, timeout=timeout * 1000)
            except Exception as e:
                raise SelectorNotFoundError(f"Selector '{selector}' not found for fill: {e}")
        else:
            pass

        return {
            "page_id": self.page_id,
            "action": "fill",
            "selector": selector,
            "duration": round(time.time() - start_time, 4)
        }

    def submit(self, form_selector: Optional[str] = None) -> Dict[str, Any]:
        """Submits form by selector or triggers the first submit button."""
        if self._is_closed:
            raise ContextClosedError("Cannot submit on closed page.")

        start_time = time.time()
        if self._pw_page:
            try:
                if form_selector:
                    target = self._pw_page.query_selector(form_selector)
                    if not target:
                        raise SelectorNotFoundError(f"Form '{form_selector}' not found.")
                    btn = target.query_selector("button[type='submit'], input[type='submit'], button")
                    if btn:
                        btn.click()
                    else:
                        self._pw_page.evaluate(f"document.querySelector('{form_selector}').submit()")
                else:
                    self._pw_page.keyboard.press("Enter")

                try:
                    self._pw_page.wait_for_load_state("domcontentloaded", timeout=3000)
                except Exception:
                    pass
                self._current_url = self._pw_page.url
                self._current_title = self._pw_page.title()
                try:
                    self._raw_html_cache = self._pw_page.content()
                except Exception:
                    pass
            except Exception as e:
                raise FormSubmissionError(f"Form submission failed: {e}")

        return {
            "page_id": self.page_id,
            "action": "submit",
            "url": self.url,
            "duration": round(time.time() - start_time, 4)
        }

    def go_back(self) -> Dict[str, Any]:
        """Navigates back to the previous page in session history."""
        if self._is_closed:
            raise ContextClosedError("Cannot navigate closed page.")

        if self._pw_page:
            try:
                self._pw_page.go_back()
                self._current_url = self._pw_page.url
                self._current_title = self._pw_page.title()
            except Exception as e:
                raise BrowserError(f"go_back failed: {e}")

        return {"page_id": self.page_id, "url": self.url, "title": self.title()}

    def set_html_content(self, html: str, url: Optional[str] = None, title: Optional[str] = None) -> None:
        """Sets internal HTML content (used in testing or direct DOM reduction)."""
        self._raw_html_cache = html
        if url:
            self._current_url = url
        if title:
            self._current_title = title

    def snapshot(self, evidence_ids: Optional[List[str]] = None) -> DOMSnapshot:
        """Takes a structural DOM snapshot and reduces it for model planning."""
        html = self._raw_html_cache
        if self._pw_page and not self._is_closed:
            try:
                html = self._pw_page.content()
                self._raw_html_cache = html
            except Exception:
                html = self._raw_html_cache or "<html><body></body></html>"

        return DOMReducer.reduce(
            html_content=html,
            url=self.url,
            title=self.title(),
            status_code=self.status_code,
            evidence_ids=evidence_ids
        )

    def extract_javascript_routes(self, evidence_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Extracts dynamic JavaScript routes, APIs, and WebSockets from the current page."""
        html = self._raw_html_cache
        if self._pw_page and not self._is_closed:
            try:
                html = self._pw_page.content()
            except Exception:
                pass

        return JavaScriptSurfaceExtractor.extract_from_script(
            script_content=html or "",
            base_url=self.url,
            evidence_ids=evidence_ids
        )

    def get_network_events(self) -> List[NetworkEvent]:
        return self.network_recorder.events

    def close(self) -> None:
        if not self._is_closed:
            if self._pw_page:
                try:
                    self._pw_page.close()
                except Exception:
                    pass
            self._is_closed = True
