"""
BrowserContext abstraction for session continuity and credential bridge.

Synchronizes cookies, tokens, and credentials bi-directionally between
the authoritative SessionStore and the headless browser context.
"""

from __future__ import annotations

import uuid
import urllib.parse
from typing import Optional, Dict, Any, List

from state.session_store import SessionStore, Session, Cookie, BearerToken, CSRFToken
from browser.page import BrowserPage
from browser.network import NetworkRecorder
from browser.errors import ContextClosedError, BrowserError


class BrowserContext:
    """
    Authoritative abstraction over an isolated browser context (cookies, cache, storage).
    Maintains 1:1 synchronization with the backend SessionStore.
    """

    def __init__(
        self,
        context_id: Optional[str] = None,
        role: str = "default",
        target_origin: str = "",
        playwright_context: Optional[Any] = None,
        network_recorder: Optional[NetworkRecorder] = None,
    ):
        self.context_id = context_id or f"CTX-{uuid.uuid4().hex[:6].upper()}"
        self.role = role
        self.target_origin = target_origin
        self._pw_context = playwright_context
        self.network_recorder = network_recorder or NetworkRecorder()
        self.pages: List[BrowserPage] = []
        self._active_page: Optional[BrowserPage] = None
        self._is_closed = False

    def new_page(self) -> BrowserPage:
        """Creates and tracks a new page inside this browser context."""
        if self._is_closed:
            raise ContextClosedError("Cannot create page in closed context.")

        pw_page = None
        if self._pw_context:
            try:
                pw_page = self._pw_context.new_page()
            except Exception as e:
                raise BrowserError(f"Failed to create new Playwright page: {e}")

        page = BrowserPage(
            playwright_page=pw_page,
            network_recorder=self.network_recorder,
            context=self
        )
        self.pages.append(page)
        self._active_page = page
        return page

    def get_active_page(self) -> BrowserPage:
        """Returns the current active page or creates a new one if none exists."""
        if self._is_closed:
            raise ContextClosedError("Context is closed.")
        if self._active_page and not self._active_page._is_closed:
            return self._active_page
        return self.new_page()

    def inject_session_store(
        self,
        session_store: SessionStore,
        target_url: str,
        role: str = "default"
    ) -> None:
        """
        Injects cookies and headers from SessionStore into the browser context.
        """
        if self._is_closed:
            return

        target_role = role if role != "default" else self.role
        auth_ctx = session_store.get_request_auth_context(target_url, role=target_role)
        cookies = auth_ctx.get("cookies", {})

        if self._pw_context and cookies:
            parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
            domain = parsed.netloc.split(":")[0] or "localhost"

            pw_cookies = []
            for name, val in cookies.items():
                pw_cookies.append({
                    "name": name,
                    "value": val,
                    "domain": domain,
                    "path": "/",
                })
            try:
                self._pw_context.add_cookies(pw_cookies)
            except Exception:
                pass

        # Extra headers (e.g. Authorization Bearer token or CSRF token)
        extra_headers = {}
        for hk, hv in auth_ctx.get("headers", {}).items():
            if hk.lower() != "cookie":
                extra_headers[hk] = hv

        if self._pw_context and extra_headers:
            try:
                self._pw_context.set_extra_http_headers(extra_headers)
            except Exception:
                pass

    def export_cookies_to_session_store(
        self,
        session_store: SessionStore,
        target_url: str,
        role: str = "default",
        evidence_id: Optional[str] = None
    ) -> Session:
        """
        Extracts cookies set by the browser and updates the authoritative SessionStore.
        """
        target_role = role if role != "default" else self.role
        session = session_store.get_active_session_for_request(target_url, role=target_role)
        if not session:
            parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
            origin = parsed.netloc or "127.0.0.1"
            session = session_store.create_session(
                target_origin=origin,
                role=target_role,
                source_evidence_ids=[evidence_id] if evidence_id else []
            )

        if self._pw_context and not self._is_closed:
            try:
                cookies = self._pw_context.cookies()
                for c in cookies:
                    cookie_obj = Cookie(
                        name=c.get("name", ""),
                        value=c.get("value", ""),
                        domain=c.get("domain", "").lstrip("."),
                        path=c.get("path", "/"),
                        secure=c.get("secure", False),
                        http_only=c.get("httpOnly", False),
                        expiry=c.get("expires")
                    )
                    session.add_cookie(cookie_obj)
            except Exception:
                pass

        if evidence_id and evidence_id not in session.source_evidence_ids:
            session.source_evidence_ids.append(evidence_id)

        return session

    def close(self) -> None:
        """Closes all pages and the underlying browser context."""
        if not self._is_closed:
            for p in self.pages:
                p.close()
            if self._pw_context:
                try:
                    self._pw_context.close()
                except Exception:
                    pass
            self._is_closed = True
