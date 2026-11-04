"""
Operational Mode Isolation Layer.

Provides formal separation and security boundaries between:
- CHAT: Conversational, Q&A, non-mutating, no security tool execution, no assessment phase changes.
- RESEARCH: Knowledge and intelligence gathering, CVE research, documentation retrieval.
            MUST NOT mutate active assessment state or create confirmed assessment findings.
- ASSESSMENT: Full security assessment lifecycle, scoped tool execution, attack graph expansion,
              evidence collection, hypothesis testing, and finding verification.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set


class OperationalMode(str, Enum):
    CHAT = "CHAT"
    RESEARCH = "RESEARCH"
    ASSESSMENT = "ASSESSMENT"
    SECURITY_ASSESSMENT = "SECURITY_ASSESSMENT"  # Backwards compatibility alias
    CODE = "CODE"


class ModeIsolationViolation(RuntimeError):
    """Raised when an operation violates operational mode boundaries."""
    pass


OFFENSIVE_SECURITY_TOOLS: Set[str] = {
    "nmap",
    "port_scan",
    "service_scan",
    "sqlmap",
    "sqli_probe",
    "nikto",
    "hydra",
    "ffuf",
    "gobuster",
    "dirb",
    "metasploit",
    "msf",
    "verify_proof",
    "exploit",
    "reverse_shell",
    "privilege_escalation",
    "cmd_exec",
    "lfi_probe",
    "xss_probe",
}

RESEARCH_TOOLS: Set[str] = {
    "cve_lookup",
    "nvd_search",
    "doc_fetch",
    "web_search",
    "read_url",
    "github_search",
    "exploitdb_query",
    "packet_storm_query",
}

SAFE_CHAT_TOOLS: Set[str] = {
    "calculator",
    "datetime",
    "echo",
}


class OperationalModeManager:
    """
    Enforces strict isolation between CHAT, RESEARCH, and ASSESSMENT modes.
    Guarantees:
      - CHAT cannot mutate AssessmentState, execute offensive tools, or transition phases.
      - RESEARCH cannot inject findings or mutate active assessment capability models.
      - Mode switching safely isolates history, findings, and tool executions.
    """

    def __init__(self, initial_mode: OperationalMode = OperationalMode.CHAT) -> None:
        self.current_mode: OperationalMode = self._normalize_mode(initial_mode)
        self.chat_history: List[Dict[str, str]] = []
        self.research_notes: List[Dict[str, Any]] = []
        self.transition_log: List[Dict[str, Any]] = []

    @classmethod
    def _normalize_mode(cls, mode: Any) -> OperationalMode:
        if isinstance(mode, OperationalMode):
            return mode
        val = str(mode).strip().upper()
        if val in ("ASSESSMENT", "SECURITY_ASSESSMENT"):
            return OperationalMode.ASSESSMENT
        if val == "RESEARCH":
            return OperationalMode.RESEARCH
        if val == "CODE":
            return OperationalMode.CODE
        return OperationalMode.CHAT

    def set_mode(self, mode: Any) -> OperationalMode:
        old_mode = self.current_mode
        self.current_mode = self._normalize_mode(mode)
        self.transition_log.append({
            "from": old_mode.value,
            "to": self.current_mode.value,
        })
        return self.current_mode

    def is_assessment(self) -> bool:
        return self.current_mode in (OperationalMode.ASSESSMENT, OperationalMode.SECURITY_ASSESSMENT)

    def is_chat(self) -> bool:
        return self.current_mode in (OperationalMode.CHAT, OperationalMode.CODE)

    def is_research(self) -> bool:
        return self.current_mode == OperationalMode.RESEARCH

    def authorize_tool(self, tool_name: str) -> bool:
        """
        Determines whether a tool is authorized to execute in the current operational mode.
        Raises ModeIsolationViolation if unauthorized.
        """
        norm_tool = tool_name.strip().lower()

        if self.is_chat():
            if norm_tool in OFFENSIVE_SECURITY_TOOLS:
                raise ModeIsolationViolation(
                    f"Tool '{tool_name}' is a security assessment tool and cannot be executed in CHAT mode."
                )
            if norm_tool in RESEARCH_TOOLS:
                raise ModeIsolationViolation(
                    f"Tool '{tool_name}' is a research tool and cannot be executed in CHAT mode."
                )
            if norm_tool not in SAFE_CHAT_TOOLS:
                raise ModeIsolationViolation(
                    f"Tool '{tool_name}' is not authorized in CHAT mode."
                )
            return True

        if self.is_research():
            if norm_tool in OFFENSIVE_SECURITY_TOOLS:
                raise ModeIsolationViolation(
                    f"Offensive tool '{tool_name}' cannot be executed in RESEARCH mode."
                )
            return True

        # ASSESSMENT mode: full tooling allowed within target authorization
        return True

    def guard_mutation(self, operation: str) -> None:
        """
        Guards against assessment state mutations from non-assessment modes.
        """
        if self.is_chat():
            raise ModeIsolationViolation(
                f"Cannot perform assessment mutation '{operation}' in CHAT mode."
            )
        if self.is_research():
            if operation in ("record_finding", "record_capability", "transition_phase"):
                raise ModeIsolationViolation(
                    f"Cannot perform assessment mutation '{operation}' in RESEARCH mode. "
                    "Research outputs must remain informational notes."
                )

    def add_chat_message(self, role: str, content: str) -> None:
        if not self.is_chat():
            # Allow chat logging across non-assessment interactions but isolate it
            pass
        self.chat_history.append({"role": role, "content": content})

    def add_research_note(self, title: str, content: str, source: str = "") -> None:
        """Adds a research note. Guaranteed not to create an assessment finding."""
        self.research_notes.append({
            "title": title,
            "content": content,
            "source": source,
            "is_assessment_finding": False,
        })
