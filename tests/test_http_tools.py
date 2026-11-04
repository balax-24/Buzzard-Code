import pytest
from unittest.mock import patch, MagicMock
import urllib.error
from tools.http import http_request, register_http_tools
from tools.registry import ToolRegistry

@patch("urllib.request.urlopen")
def test_http_request_success(mock_urlopen):
    # Mocking successful response
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.getheaders.return_value = [("Content-Type", "application/json"), ("X-Test", "Value")]
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    res = http_request(
        method="GET",
        url="http://localhost:8080/api",
        headers={"Authorization": "Bearer token"},
        query={"param": "1"},
        body=None
    )

    assert "STATUS: 200" in res
    assert "Content-Type: application/json" in res
    assert "X-Test: Value" in res
    assert "BODY:\n" in res
    assert '{"status": "ok"}' in res
    assert "DURATION:" in res

    # Verify mock_urlopen was called with modified URL and correct method/headers
    mock_urlopen.assert_called_once()
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.full_url == "http://localhost:8080/api?param=1"
    assert req.method == "GET"
    assert req.get_header("Authorization") == "Bearer token"

@patch("urllib.request.urlopen")
def test_http_request_http_error(mock_urlopen):
    # Mocking HTTPError (e.g., 404 Not Found)
    mock_headers = MagicMock()
    mock_headers.items.return_value = [("Content-Type", "text/plain")]
    
    # HTTPError signature: url, code, msg, hdrs, fp
    http_error = urllib.error.HTTPError(
        "http://localhost:8080/notfound",
        404,
        "Not Found",
        mock_headers,
        MagicMock(read=MagicMock(return_value=b"Page not found"))
    )
    mock_urlopen.side_effect = http_error

    res = http_request(
        method="POST",
        url="http://localhost:8080/notfound",
        body="some data"
    )

    assert "STATUS: 404" in res
    assert "BODY:\n" in res
    assert "Page not found" in res
    assert "DURATION:" in res

@patch("urllib.request.urlopen")
def test_http_request_other_error(mock_urlopen):
    # Mocking other network/connection exception
    mock_urlopen.side_effect = Exception("Connection refused")

    res = http_request(
        method="GET",
        url="http://localhost:8080/refused"
    )

    assert "TOOL ERROR: HTTP request failed: Connection refused" in res

def test_register_http_tools():
    registry = ToolRegistry()
    register_http_tools(registry)
    assert "http.request" in registry.tools
