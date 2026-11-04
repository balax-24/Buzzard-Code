import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Any, Optional

def http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    query: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: int = 10
) -> str:
    """
    Executes a raw HTTP request and returns status, headers, body, and duration.
    Arguments:
        method: HTTP method (e.g. GET, POST).
        url: Target URL.
        headers: Dict of HTTP request headers.
        query: Dict of HTTP query parameters.
        body: Raw request body string.
        timeout: Execution timeout in seconds.
    """
    if not url:
        return "Error: URL is required."
        
    method = method.upper()
    
    # 1. Parse URL & apply query parameters
    try:
        url_parts = list(urllib.parse.urlparse(url))
        if query:
            existing_query = urllib.parse.parse_qs(url_parts[4])
            for k, v in query.items():
                existing_query[k] = v
            url_parts[4] = urllib.parse.urlencode(existing_query, doseq=True)
        url = urllib.parse.urlunparse(url_parts)
    except Exception as e:
        return f"Error: Invalid URL or query parameters: {e}"
        
    # 2. Encode body if present
    data = None
    if body is not None:
        data = body.encode("utf-8")
        
    # 3. Create request object
    try:
        req = urllib.request.Request(url, data=data, method=method)
    except Exception as e:
        return f"Error: Failed to create HTTP request: {e}"
        
    # 4. Set headers
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
            
    # 5. Execute request and measure duration
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            duration = time.time() - start_time
            status = response.status
            res_headers = dict(response.getheaders())
            res_body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as he:
        duration = time.time() - start_time
        status = he.code
        res_headers = dict(he.headers)
        res_body = he.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"TOOL ERROR: HTTP request failed: {e}"
        
    # Format output as specified in Setup.md
    headers_str = "\n".join(f"{k}: {v}" for k, v in res_headers.items())
    
    output = f"""STATUS: {status}
HEADERS:
{headers_str}

BODY:
{res_body}

DURATION: {duration:.3f}s"""
    return output

def register_http_tools(registry):
    """
    Registers HTTP tools within the ToolRegistry.
    """
    registry.register(
        name="http.request",
        description="Executes a raw HTTP request. Arguments: method (str), url (str), headers (dict, optional), query (dict, optional), body (str, optional), timeout (int, default 10).",
        func=http_request
    )
