"""
Qwythos Browser & Application-Surface Intelligence Subsystem.
"""

from security_agent.browser.errors import (
    BrowserError,
    BrowserNotInitializedError,
    NavigationTimeoutError,
    SelectorNotFoundError,
    NetworkError,
    ContextClosedError,
    FormSubmissionError,
    JavaScriptEvaluationError,
)
from security_agent.browser.dom import (
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
from security_agent.browser.network import (
    NetworkEvent,
    WebSocketEvent,
    NetworkRecorder,
    redact_sensitive_headers,
)
from security_agent.browser.page import BrowserPage
from security_agent.browser.context import BrowserContext
from security_agent.browser.browser import BrowserEngine, get_default_browser_engine
from security_agent.browser.snapshots import SnapshotRepository

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
