"""
Typed browser error hierarchy for Qwythos Application-Surface Intelligence.
"""

from __future__ import annotations
from typing import Optional, Dict, Any


class BrowserError(Exception):
    """Base exception for all browser engine and automation errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class BrowserNotInitializedError(BrowserError):
    """Raised when browser operations are invoked before initialization."""
    pass


class NavigationTimeoutError(BrowserError):
    """Raised when page navigation exceeds the timeout limit."""
    pass


class SelectorNotFoundError(BrowserError):
    """Raised when element query or action target cannot be found in DOM."""
    pass


class NetworkError(BrowserError):
    """Raised when network transport fails or connection is refused."""
    pass


class ContextClosedError(BrowserError):
    """Raised when interacting with an already closed browser context or page."""
    pass


class FormSubmissionError(BrowserError):
    """Raised when form interaction or submission fails."""
    pass


class JavaScriptEvaluationError(BrowserError):
    """Raised when executing in-page JavaScript produces an unhandled error."""
    pass
