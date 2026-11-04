"""
Network-Event Intelligence & Telemetry for Browser Automation.

Captures and analyzes:
- HTTP requests, responses, and failures
- API calls (Fetch, XHR, REST)
- WebSocket connections and message traffic
- Request/Response headers with secret redaction
- Discovery of dynamic API routes and endpoints
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redacts passwords, bearer tokens, cookies, and secrets from header maps."""
    redacted = {}
    for k, v in headers.items():
        k_low = k.lower()
        if k_low == "authorization":
            if v.lower().startswith("bearer "):
                tok = v.split(" ", 1)[1]
                mask = tok[:4] + "***" + tok[-4:] if len(tok) > 8 else "***"
                redacted[k] = f"Bearer {mask}"
            else:
                redacted[k] = "***REDACTED***"
        elif k_low == "cookie":
            parts = []
            for cookie_part in v.split(";"):
                if "=" in cookie_part:
                    ck, cv = cookie_part.strip().split("=", 1)
                    if any(s in ck.lower() for s in ("sess", "token", "auth", "jwt", "pass", "secret")):
                        cv_mask = cv[:3] + "***" if len(cv) > 6 else "***"
                        parts.append(f"{ck}={cv_mask}")
                    else:
                        parts.append(f"{ck}={cv}")
                else:
                    parts.append(cookie_part)
            redacted[k] = "; ".join(parts)
        elif any(s in k_low for s in ("token", "secret", "api-key", "apikey", "csrf")):
            v_mask = v[:3] + "***" if len(v) > 6 else "***"
            redacted[k] = v_mask
        else:
            redacted[k] = v
    return redacted


@dataclass
class NetworkEvent:
    """Represents a single HTTP network request/response event observed in the browser."""
    event_id: str
    url: str
    method: str = "GET"
    status: int = 0
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    initiator: str = "navigation"  # "fetch", "xhr", "script", "navigation", "websocket", "other"
    timestamp: float = field(default_factory=time.time)
    duration: float = 0.0
    is_websocket: bool = False
    payload_snippet: str = ""
    error_message: Optional[str] = None
    evidence_id: Optional[str] = None

    @property
    def is_api_call(self) -> bool:
        """Determines if request is an API / background dynamic data request."""
        if self.initiator in ("fetch", "xhr", "axios"):
            return True
        if "application/json" in self.content_type.lower() or "application/xml" in self.content_type.lower():
            return True
        if "/api/" in self.url.lower() or "/graphql" in self.url.lower() or "/v1/" in self.url.lower():
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "content_type": self.content_type,
            "initiator": self.initiator,
            "timestamp": self.timestamp,
            "duration": round(self.duration, 4),
            "is_api_call": self.is_api_call,
            "is_websocket": self.is_websocket,
            "error": self.error_message,
            "evidence_id": self.evidence_id,
        }


@dataclass
class WebSocketEvent:
    """Represents a WebSocket lifecycle or message exchange event."""
    event_id: str
    url: str
    origin_page: str = ""
    event_type: str = "CONNECT"  # "CONNECT", "MESSAGE_SENT", "MESSAGE_RECEIVED", "CLOSE", "ERROR"
    payload_snippet: str = ""
    timestamp: float = field(default_factory=time.time)
    evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "url": self.url,
            "origin_page": self.origin_page,
            "event_type": self.event_type,
            "payload": self.payload_snippet[:200],
            "timestamp": self.timestamp,
            "evidence_id": self.evidence_id,
        }


class NetworkRecorder:
    """
    Authoritative telemetry recorder for browser network activity.
    Buffers events, redacts secrets, and extracts dynamic API and WebSocket surfaces.
    """

    def __init__(self):
        self.events: List[NetworkEvent] = []
        self.ws_events: List[WebSocketEvent] = []
        self._seen_urls: Set[str] = set()

    def record_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        initiator: str = "navigation",
        payload: str = "",
        evidence_id: Optional[str] = None,
    ) -> NetworkEvent:
        """Records an outgoing request event."""
        eid = f"NET-{uuid.uuid4().hex[:6].upper()}"
        redacted_headers = redact_sensitive_headers(headers or {})
        payload_snip = payload[:300] if payload else ""

        is_ws = url.startswith(("ws://", "wss://"))
        event = NetworkEvent(
            event_id=eid,
            url=url,
            method=method.upper(),
            request_headers=redacted_headers,
            initiator=initiator,
            is_websocket=is_ws,
            payload_snippet=payload_snip,
            evidence_id=evidence_id
        )
        self.events.append(event)
        self._seen_urls.add(url)
        return event

    def record_response(
        self,
        url: str,
        status: int,
        headers: Optional[Dict[str, str]] = None,
        content_type: str = "",
        duration: float = 0.0,
        evidence_id: Optional[str] = None,
    ) -> Optional[NetworkEvent]:
        """Finds matching active request event and records its response."""
        for ev in reversed(self.events):
            if ev.url == url and ev.status == 0:
                ev.status = status
                ev.response_headers = dict(headers or {})
                ev.content_type = content_type or ev.response_headers.get("content-type", "")
                ev.duration = duration
                if evidence_id and not ev.evidence_id:
                    ev.evidence_id = evidence_id
                return ev

        # If no matching request was buffered, create one
        eid = f"NET-{uuid.uuid4().hex[:6].upper()}"
        event = NetworkEvent(
            event_id=eid,
            url=url,
            method="GET",
            status=status,
            response_headers=dict(headers or {}),
            content_type=content_type or (headers or {}).get("content-type", ""),
            duration=duration,
            evidence_id=evidence_id
        )
        self.events.append(event)
        self._seen_urls.add(url)
        return event

    def record_failed(
        self,
        url: str,
        error_message: str,
        evidence_id: Optional[str] = None,
    ) -> NetworkEvent:
        """Records a network failure / connection refused event."""
        eid = f"NET-{uuid.uuid4().hex[:6].upper()}"
        event = NetworkEvent(
            event_id=eid,
            url=url,
            status=0,
            error_message=error_message,
            evidence_id=evidence_id
        )
        self.events.append(event)
        self._seen_urls.add(url)
        return event

    def record_websocket_event(
        self,
        url: str,
        origin_page: str = "",
        event_type: str = "CONNECT",
        payload: str = "",
        evidence_id: Optional[str] = None,
    ) -> WebSocketEvent:
        """Records a WebSocket event."""
        wid = f"WS-{uuid.uuid4().hex[:6].upper()}"
        ws_event = WebSocketEvent(
            event_id=wid,
            url=url,
            origin_page=origin_page,
            event_type=event_type,
            payload_snippet=payload[:200] if payload else "",
            evidence_id=evidence_id
        )
        self.ws_events.append(ws_event)
        return ws_event

    def get_api_requests(self) -> List[NetworkEvent]:
        """Returns all background API, Fetch, XHR, and JSON request events."""
        return [e for e in self.events if e.is_api_call]

    def get_websockets(self) -> List[WebSocketEvent]:
        """Returns all captured WebSocket events."""
        return list(self.ws_events)

    def get_failed_requests(self) -> List[NetworkEvent]:
        """Returns all failed or error request events."""
        return [e for e in self.events if e.error_message or (e.status >= 400 and e.status != 404)]

    def get_discovered_endpoints(self) -> List[Dict[str, Any]]:
        """Returns structured endpoint discovery records extracted from network traffic."""
        discovered: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        for ev in self.events:
            if ev.url and ev.url not in seen:
                seen.add(ev.url)
                discovered.append({
                    "url": ev.url,
                    "method": ev.method,
                    "status": ev.status,
                    "initiator": ev.initiator,
                    "is_api": ev.is_api_call,
                    "evidence_id": ev.evidence_id,
                })

        for ws in self.ws_events:
            if ws.url and ws.url not in seen:
                seen.add(ws.url)
                discovered.append({
                    "url": ws.url,
                    "method": "WS",
                    "status": 101,
                    "initiator": "websocket",
                    "is_api": False,
                    "is_websocket": True,
                    "evidence_id": ws.evidence_id,
                })

        return discovered

    def clear(self) -> None:
        self.events.clear()
        self.ws_events.clear()
        self._seen_urls.clear()
