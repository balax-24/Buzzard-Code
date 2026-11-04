"""
Cyber Range Lab Target Server.

A lightweight embedded HTTP server hosting controlled, mock test endpoints
(SQLi, XSS reflection, CORS misconfiguration, Header deficiencies)
for safe offline testing, continuous benchmarks, and evaluation.
See plan sections 62-66 and Phase G.
"""

import http.server
import threading
import urllib.parse
from typing import Tuple, Optional


class LabServerHandler(http.server.BaseHTTPRequestHandler):
    """
    Simulated web application for testing and benchmarking.
    """
    def log_message(self, format, *args):
        # Suppress stdout noise during automated test runs
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Mock SQLi Vulnerable Endpoint (/api/products?id=...)
        if path == "/api/products":
            prod_id = query.get("id", ["1"])[0]
            if "'" in prod_id or "--" in prod_id or "OR" in prod_id:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"SQL syntax error: unrecognized token in sqlite3.OperationalError near 'SELECT * FROM products'")
                return
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"product_id": 1, "name": "Security Benchmark Target Widget"}')
            return

        # 2. Mock XSS Reflection Endpoint (/search?q=...)
        elif path == "/search":
            q = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = f"<html><body><h1>Search Results for: {q}</h1></body></html>"
            self.wfile.write(html.encode("utf-8"))
            return

        # 3. Mock CORS Vulnerable Endpoint (/api/user/profile)
        elif path == "/api/user/profile":
            origin = self.headers.get("Origin")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"user_id": 42, "email": "victim@lab.internal", "role": "admin"}')
            return

        # 4. Standard Homepage with Login Form
        elif path == "/" or path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            login_html = """
            <!DOCTYPE html>
            <html>
            <head><title>Cyber Range Lab Portal</title></head>
            <body>
              <h2>Cyber Range Lab Portal</h2>
              <form action="/login" method="POST">
                <label>Username: <input type="text" name="username" id="username"></label>
                <label>Password: <input type="password" name="password" id="password"></label>
                <button type="submit">Sign In</button>
              </form>
            </body>
            </html>
            """
            self.wfile.write(login_html.strip().encode("utf-8"))
            return

        # Default 404
        self.send_response(404)
        self.end_headers()


class CyberRangeServer:
    """
    Manages the lifecycle of a local cyber range mock server for automated testing.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> Tuple[str, int]:
        self.server = http.server.HTTPServer((self.host, self.port), LabServerHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.host, self.port

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
