"""
Data Models and Enums for Qwythos TUI.
"""

from __future__ import annotations

import re
import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Union


class AppMode(str, Enum):
    CHAT = "CHAT"
    ASSIST = "ASSIST"
    INVESTIGATE = "INVESTIGATE"
    BROWSER = "BROWSER"
    REVIEW = "REVIEW"


class MessageRole(str, Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"
    SYSTEM = "SYSTEM"
    TOOL = "TOOL"
    ERROR = "ERROR"


@dataclass
class ToolCallCardData:
    tool_call_id: str = field(default_factory=lambda: f"tc-{uuid.uuid4().hex[:8]}")
    tool_name: str = ""
    target: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    status: str = "RUNNING"  # "RUNNING", "SUCCESS", "FAILURE"
    duration_seconds: float = 0.0
    output_summary: str = ""
    raw_output: str = ""
    error_message: Optional[str] = ""
    evidence_ids: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ChatMessage:
    message_id: str = field(default_factory=lambda: f"msg-{uuid.uuid4().hex[:8]}")
    role: MessageRole = MessageRole.USER
    content: str = ""
    timestamp: float = field(default_factory=time.time)
    reasoning_summary: Optional[str] = None
    tool_cards: List[ToolCallCardData] = field(default_factory=list)
    is_streaming: bool = False
    renderable: Optional[Any] = None


# Sensitive data redaction patterns
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(?:password|passwd|secret|token|bearer|api_key|apikey|private_key|cookie|auth|credential)",
    re.IGNORECASE,
)


def redact_sensitive_value(key: str, val: Any) -> Any:
    if not isinstance(key, str):
        return val
    if SENSITIVE_KEY_PATTERNS.search(key):
        if isinstance(val, str):
            if len(val) <= 6:
                return "***"
            return val[:2] + "***" + val[-2:]
        return "***"
    return val


def redact_sensitive_data(data: Any) -> Any:
    """
    Recursively redacts passwords, tokens, session secrets, private keys, and cookies.
    """
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                redacted[k] = redact_sensitive_data(v)
            else:
                redacted[k] = redact_sensitive_value(k, v)
        return redacted
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    elif isinstance(data, str):
        # Redact raw authorization header formats
        redacted_str = re.sub(
            r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*",
            r"\1***",
            data,
            flags=re.IGNORECASE,
        )
        redacted_str = re.sub(
            r"((?:password|secret|token|apikey|cookie)=)[^\s;&]+",
            r"\1***",
            redacted_str,
            flags=re.IGNORECASE,
        )
        return redacted_str
    return data
