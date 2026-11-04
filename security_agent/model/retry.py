"""Bounded retries for cloud provider HTTP requests."""

from __future__ import annotations

import re
import time
from typing import Any, Dict

import httpx

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RETRIES = 5
MAX_RETRY_DELAY = 65.0


def retry_delay(response: httpx.Response, attempt: int) -> float:
    """Uses the delay the server asks for, capped, otherwise exponential backoff."""
    header = response.headers.get("retry-after", "")
    if header.replace(".", "", 1).isdigit():
        return min(float(header), MAX_RETRY_DELAY)
    match = re.search(r'"retryDelay":\s*"(\d+(?:\.\d+)?)s"', response.text)
    if match:
        return min(float(match.group(1)) + 1.0, MAX_RETRY_DELAY)
    return float(2 ** attempt)


def post_with_retries(client: httpx.Client, url: str, headers: Dict[str, str], payload: Dict[str, Any]) -> httpx.Response:
    """POSTs, retrying rate limits, server errors and timeouts. Returns the final response."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException:
            if attempt == MAX_RETRIES:
                raise
            time.sleep(float(2 ** attempt))
            continue
        if response.status_code in RETRYABLE_STATUS and attempt < MAX_RETRIES:
            time.sleep(retry_delay(response, attempt))
            continue
        return response
    raise RuntimeError("Retry loop ended without a response.")
