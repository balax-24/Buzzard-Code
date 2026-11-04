"""
Tests for static JavaScript route extraction: fetch(), axios(), $.ajax(), REST strings, and WebSockets.
"""

from security_agent.browser.dom import JavaScriptSurfaceExtractor


def test_javascript_endpoint_extraction():
    js_bundle = """
    function loadData() {
        fetch('/api/v2/analytics/reports?format=json')
            .then(res => res.json());
        
        axios.post('/api/v2/auth/refresh', { token: 'xyz' });

        $.ajax({
            url: '/graphql',
            type: 'POST',
            data: { query: '{ me { id username } }' }
        });

        const socket = new WebSocket('ws://api.target.local:9000/events');
        const uploadRoute = "/upload/documents";
        const debugPath = "/debug/vars";
    }
    """

    res = JavaScriptSurfaceExtractor.extract_from_script(
        script_content=js_bundle,
        base_url="http://target.local/app",
        evidence_ids=["EVI-JS-01"]
    )

    apis = res["api_candidates"]
    ws = res["websockets"]

    api_urls = [a.url for a in apis]
    assert "http://target.local/api/v2/analytics/reports?format=json" in api_urls
    assert "http://target.local/api/v2/auth/refresh" in api_urls
    assert "http://target.local/graphql" in api_urls
    assert "http://target.local/upload/documents" in api_urls
    assert "http://target.local/debug/vars" in api_urls

    ws_urls = [w.url for w in ws]
    assert "ws://api.target.local:9000/events" in ws_urls
