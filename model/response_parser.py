"""
Response Parser Subsystem for Model Outputs.

Provides pure functions for extracting structured JSON, handling Markdown
code fences, and normalizing model decision summaries.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


def extract_json_dict(text: str) -> Optional[Dict[str, Any]]:
    """
    Extracts a JSON object/dictionary from raw model response text.
    Handles Markdown code blocks and embedded JSON substrings.
    """
    if not text or not text.strip():
        return None

    raw = text.strip()

    # Case 1: Markdown code fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    # Case 2: Direct JSON parse
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # Case 3: Embedded JSON substring match
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    return None


def parse_decision_summary(
    content: str,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    thinking_text: str = ""
) -> Dict[str, Any]:
    """
    Parses decision summary from model content or builds a fallback decision summary.
    """
    decision_summary: Optional[Dict[str, Any]] = None

    if content and content.strip():
        decision_summary = extract_json_dict(content)

    if not decision_summary:
        decision_name = tool_calls[0]["function"]["name"] if (tool_calls and len(tool_calls) > 0) else "complete"
        decision_summary = {
            "decision": decision_name,
            "reason": thinking_text or content or "Analyzing next step",
            "expected_information": "N/A",
            "next_step": "N/A",
        }

    return decision_summary
