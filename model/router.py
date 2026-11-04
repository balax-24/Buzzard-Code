"""
ModelRouter: routes tasks across the four local uncensored models based on
the phase of the engagement and keywords in the task text.

Profiles:
  k3-sec:latest    offensive orchestrator / recon / vuln scanning
  qwen-cyber:latest cyber research / exploitation / payload strategy
  deephat:latest   exploit code generation / low-level payloads
  qwythos:latest   analysis, vision, report generation / triage
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

MODEL_PROFILES: Dict[str, Dict[str, Any]] = {
    "k3-sec:latest": {
        "role": "offensive orchestrator & recon",
        "keywords": [
            "scan", "recon", "port", "nmap", "enum", "enumerate", "fingerprint",
            "subdomain", "dns", "discover", "probe", "nikto", "nuclei", "ffuf",
            "gobuster", "dirb", "web", "vuln", "vulnerability", "assess",
            "reconnaissance", "attack surface",
        ],
    },
    "qwen-cyber:latest": {
        "role": "cyber research & exploitation",
        "keywords": [
            "exploit", "exploitation", "cve", "payload", "shell", "reverse",
            "rce", "sqli", "sql injection", "xss", "lfi", "rfi", "ssrf",
            "injection", "bypass", "privilege", "escalation", "pwn", "hack",
            "research", "weaponize", "metasploit", "msf", "buffer",
        ],
    },
    "deephat:latest": {
        "role": "exploit code generation",
        "keywords": [
            "code", "write", "python script", "generate payload", "script",
            "program", "function", "implement", "snippet", "one-liner",
            "encode", "decode", "obfuscate", "source", "compile",
        ],
    },
    "qwythos:latest": {
        "role": "analyst, vision & report",
        "keywords": [
            "analyz", "analys", "report", "summary", "summariz", "explain",
            "interpret", "image", "screenshot", "vision", "visual", "document",
            "writeup", "review", "triage", "recommend", "findings", "conclusion",
            "debrief",
        ],
    },
}

# Fallback order when the routed model is unavailable.
PRIORITY_ORDER = ["k3-sec:latest", "qwen-cyber:latest", "deephat:latest", "qwythos:latest"]

PHASE_MAP = {
    "recon": "k3-sec:latest",
    "scanning": "k3-sec:latest",
    "exploitation": "qwen-cyber:latest",
    "post": "deephat:latest",
    "report": "qwythos:latest",
    "analysis": "qwythos:latest",
}


class ModelRouter:
    """Routes task text to the best-suited local model."""

    def __init__(self, models: Optional[List[str]] = None,
                 available: Optional[List[str]] = None):
        self.models = models or list(MODEL_PROFILES.keys())
        self.available = available or list(self.models)

    def route(self, task_text: str, phase: Optional[str] = None) -> str:
        """Pick the best model for a task; falls back to priority order."""
        if phase and phase.lower() in PHASE_MAP:
            chosen = PHASE_MAP[phase.lower()]
            if chosen in self.available:
                return chosen
        text = (task_text or "").lower()
        best = None
        best_score = 0
        for name in self.models:
            profile = MODEL_PROFILES.get(name, {})
            score = sum(1 for kw in profile.get("keywords", []) if kw in text)
            if score > best_score:
                best_score = score
                best = name
        if best and best in self.available:
            return best
        # Keyword winner unavailable -> first available in priority order.
        for name in PRIORITY_ORDER:
            if name in self.available:
                return name
        return self.models[0] if self.models else "k3-sec:latest"

    def route_all(self) -> List[str]:
        """Return all models in priority order."""
        return [m for m in PRIORITY_ORDER if m in self.models]

    def describe(self) -> str:
        lines = ["Available models:"]
        for name in self.route_all():
            profile = MODEL_PROFILES.get(name, {})
            lines.append(f"  - {name}: {profile.get('role', 'unknown')}")
        return "\n".join(lines)
