"""
Tests for WebSocket endpoint discovery in DOM, scripts, and runtime events.
"""

from browser.dom import DOMReducer
from browser.network import NetworkRecorder


def test_websocket_discovery():
    html = """
    <html>
    <head>
        <script>
            const chatSocket = new WebSocket("ws://target.local:8080/ws/chat");
            const liveFeed = "wss://stream.target.local/feed";
        </script>
    </head>
    <body>
        <h1>Realtime Dashboard</h1>
    </body>
    </html>
    """

    snap = DOMReducer.reduce(html, url="http://target.local:8080/")

    assert len(snap.websockets) >= 2
    ws_urls = [w.url for w in snap.websockets]
    assert "ws://target.local:8080/ws/chat" in ws_urls
    assert "wss://stream.target.local/feed" in ws_urls

    recorder = NetworkRecorder()
    recorder.record_websocket_event(
        url="ws://target.local:8080/ws/chat",
        origin_page="http://target.local:8080/",
        event_type="CONNECT",
        evidence_id="EVI-WS-01"
    )
    recorder.record_websocket_event(
        url="ws://target.local:8080/ws/chat",
        origin_page="http://target.local:8080/",
        event_type="MESSAGE_RECEIVED",
        payload='{"type":"welcome","user":"admin"}',
        evidence_id="EVI-WS-02"
    )

    ws_events = recorder.get_websockets()
    assert len(ws_events) == 2
    assert ws_events[1].payload_snippet.startswith('{"type":"welcome"')
