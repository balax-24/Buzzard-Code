"""
Deterministic Fake Model Provider for Standalone TUI Testing.
Allows running the complete interactive TUI without requiring live Ollama or network.
"""

from __future__ import annotations

import time
from typing import Iterator, Dict, Any, Optional, List


class FakeModelProvider:
    """
    Fake LLM provider simulating streaming responses, tool choices, and code generation.
    """

    def __init__(self, model_name: str = "qwythos:latest", host: str = "fake://localhost"):
        self.model_name = model_name
        self.host = host
        self.call_history: List[str] = []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        self.call_history.append(prompt)
        prompt_lower = prompt.lower()

        if "explain how jwt authentication works" in prompt_lower or "jwt" in prompt_lower:
            return (
                "JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained "
                "way for securely transmitting information between parties as a JSON object.\n\n"
                "A JWT consists of three parts separated by dots (`.`):\n"
                "1. **Header**: Contains the token type (JWT) and signing algorithm (e.g., HS256, RS256).\n"
                "2. **Payload**: Contains the claims (e.g., `sub`, `name`, `admin`, `exp`).\n"
                "3. **Signature**: Cryptographic signature verifying data integrity."
            )
        elif "explain xss" in prompt_lower or "xss" in prompt_lower:
            return (
                "Cross-Site Scripting (XSS) is a security vulnerability that allows an attacker to inject malicious "
                "scripts into web pages viewed by other users.\n\n"
                "Three primary types of XSS exist:\n"
                "- **Stored (Persistent) XSS**: Malicious payload is stored in the database.\n"
                "- **Reflected (Non-Persistent) XSS**: Payload is reflected off the web server in an immediate response.\n"
                "- **DOM-based XSS**: Vulnerability exists purely in client-side script manipulation of the DOM."
            )
        elif "candidates" in prompt_lower or "action" in prompt_lower or "tool" in prompt_lower:
            # Emits tool call JSON for agentic modes
            return (
                "I should inspect the target HTTP service on port 8080 to map exposed endpoints.\n\n"
                "```json\n"
                "{\n"
                '  "thought": "Probing port 8080 for web endpoints and auth forms.",\n'
                '  "tool": "http.request",\n'
                '  "arguments": {"url": "http://127.0.0.1:8080/login", "method": "GET"}\n'
                "}\n"
                "```"
            )
        else:
            return f"Processed request successfully: {prompt[:80]}..."

    def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Iterator[str]:
        full_text = self.generate(prompt, system_prompt, options)
        # Yield word-by-word with micro delays simulating streaming
        words = full_text.split(" ")
        for i, word in enumerate(words):
            yield word + (" " if i < len(words) - 1 else "")
