"""
Tests for NetworkRecorder, telemetry capture, and secret redaction.
"""

from security_agent.browser.network import NetworkRecorder, redact_sensitive_headers


def test_network_recorder_event_tracking_and_redaction():
    recorder = NetworkRecorder()

    req_headers = {
        "Authorization": "Bearer supersecrettoken12345678",
        "Cookie": "session_id=abcdef123456; theme=dark",
        "X-API-Key": "secret_key_999",
        "User-Agent": "Qwythos/1.0",
    }

    # Record request
    ev = recorder.record_request(
        url="http://target.local/api/users",
        method="GET",
        headers=req_headers,
        initiator="fetch",
        evidence_id="EVI-REQ-01"
    )

    assert ev.url == "http://target.local/api/users"
    assert ev.is_api_call is True
    assert ev.request_headers["Authorization"].startswith("Bearer supe***5678")
    assert "abcdef" not in ev.request_headers["Cookie"]
    assert ev.request_headers["User-Agent"] == "Qwythos/1.0"

    # Record response
    resp_ev = recorder.record_response(
        url="http://target.local/api/users",
        status=200,
        headers={"Content-Type": "application/json"},
        content_type="application/json",
        duration=0.045
    )

    assert resp_ev is not None
    assert resp_ev.status == 200
    assert resp_ev.duration == 0.045

    # Check API requests filter
    apis = recorder.get_api_requests()
    assert len(apis) == 1
    assert apis[0].url == "http://target.local/api/users"

    # Record WebSocket event
    ws_ev = recorder.record_websocket_event(
        url="ws://target.local/stream",
        origin_page="http://target.local/dashboard",
        event_type="CONNECT",
        evidence_id="EVI-WS-01"
    )
    assert len(recorder.get_websockets()) == 1
    assert recorder.get_websockets()[0].url == "ws://target.local/stream"

    # Check discovered endpoints
    endpoints = recorder.get_discovered_endpoints()
    assert len(endpoints) == 2
    assert any(ep["url"] == "http://target.local/api/users" and ep["is_api"] for ep in endpoints)
    assert any(ep["url"] == "ws://target.local/stream" and ep.get("is_websocket") for ep in endpoints)
