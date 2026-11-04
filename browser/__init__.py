"""
Qwythos Browser & Application-Surface Intelligence Subsystem.
"""

from browser.errors import (
    BrowserError,
    BrowserNotInitializedError,
    NavigationTimeoutError,
    SelectorNotFoundError,
    NetworkError,
    ContextClosedError,
    FormSubmissionError,
    JavaScriptEvaluationError,
)
from browser.dom import (
    FormField,
    FormRecord,
    LinkRecord,
    ScriptRecord,
    APICandidate,
    WebSocketEndpoint,
    DOMSnapshot,
    DOMReducer,
    JavaScriptSurfaceExtractor,
)
from browser.network import (
    NetworkEvent,
    WebSocketEvent,
    NetworkRecorder,
    redact_sensitive_headers,
)
from browser.page import BrowserPage
from browser.context import BrowserContext
from browser.browser import BrowserEngine, get_default_browser_engine
from browser.snapshots import SnapshotRepository

__all__ = [
    "BrowserError",
    "BrowserNotInitializedError",
    "NavigationTimeoutError",
    "SelectorNotFoundError",
    "NetworkError",
    "ContextClosedError",
    "FormSubmissionError",
    "JavaScriptEvaluationError",
    "FormField",
    "FormRecord",
    "LinkRecord",
    "ScriptRecord",
    "APICandidate",
    "WebSocketEndpoint",
    "DOMSnapshot",
    "DOMReducer",
    "JavaScriptSurfaceExtractor",
    "NetworkEvent",
    "WebSocketEvent",
    "NetworkRecorder",
    "redact_sensitive_headers",
    "BrowserPage",
    "BrowserContext",
    "BrowserEngine",
    "get_default_browser_engine",
    "SnapshotRepository",
]
