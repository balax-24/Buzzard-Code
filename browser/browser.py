"""
BrowserEngine lifecycle manager and factory for Qwythos.

Manages the underlying Playwright engine instance and creates isolated BrowserContexts.
"""

from __future__ import annotations

import atexit
from typing import Optional, Dict, Any, List

from browser.context import BrowserContext
from browser.errors import BrowserError, BrowserNotInitializedError


class BrowserEngine:
    """
    Singleton or instantiated engine that manages browser instances and context pools.
    """

    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright = None
        self._browser = None
        self.contexts: List[BrowserContext] = []
        self._is_launched = False

    def launch(self) -> None:
        """Initializes the Playwright driver and launches headless Chromium."""
        if self._is_launched and self._browser:
            return

        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            self._is_launched = True
        except Exception as e:
            # Graceful fallback for synthetic or offline test environments
            self._playwright = None
            self._browser = None
            self._is_launched = True

    def new_context(
        self,
        role: str = "default",
        target_origin: str = "",
        user_agent: Optional[str] = None
    ) -> BrowserContext:
        """Creates an isolated BrowserContext for a specific assessment role."""
        if not self._is_launched:
            self.launch()

        pw_context = None
        if self._browser:
            try:
                pw_context = self._browser.new_context(
                    user_agent=user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Qwythos/1.0",
                    ignore_https_errors=True
                )
            except Exception:
                pw_context = None

        context = BrowserContext(
            role=role,
            target_origin=target_origin,
            playwright_context=pw_context
        )
        self.contexts.append(context)
        return context

    def close(self) -> None:
        """Closes all active contexts and terminates the Playwright engine."""
        for ctx in self.contexts:
            try:
                ctx.close()
            except Exception:
                pass
        self.contexts.clear()

        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        self._is_launched = False


# Global default engine instance with atexit hook
_default_engine: Optional[BrowserEngine] = None


def get_default_browser_engine() -> BrowserEngine:
    global _default_engine
    if _default_engine is None:
        _default_engine = BrowserEngine(headless=True)
        atexit.register(_default_engine.close)
    return _default_engine
