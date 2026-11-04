"""
Structured Agent Event System for professional security assessments.
Emits concise, observable operational events (not hidden internal reasoning).
"""

import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any


class AgentEventType(str, Enum):
    TASK = "TASK"
    ANALYSIS = "ANALYSIS"
    PLAN = "PLAN"
    TOOL_START = "TOOL"
    TOOL_RESULT = "RESULT"
    FINDING = "FINDING"
    HYPOTHESIS = "HYPOTHESIS"
    VERIFICATION = "VERIFICATION"
    ERROR = "ERROR"
    RETRY = "RETRY"
    NEXT = "NEXT"
    WARNING = "WARNING"
    COMPLETE = "COMPLETE"


@dataclass
class AgentEvent:
    """Represents a single structured operational event during an assessment."""
    event_type: AgentEventType
    summary: str
    timestamp: float = field(default_factory=time.time)
    tool: Optional[str] = None
    duration_s: Optional[float] = None
    result_summary: Optional[str] = None
    severity: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def time_str(self) -> str:
        """Returns HH:MM:SS formatted time."""
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value if isinstance(self.event_type, Enum) else str(self.event_type)
        d["time_formatted"] = self.time_str()
        return d

    def format_cli(self) -> str:
        """Formats the event for live CLI output."""
        time_tag = f"[dim #64748b][{self.time_str()}][/dim #64748b]"
        type_str = self.event_type.value if isinstance(self.event_type, Enum) else str(self.event_type)
        
        # Color coding for event types
        color_map = {
            "TASK": "bold #38bdf8",
            "ANALYSIS": "bold #818cf8",
            "PLAN": "bold #a78bfa",
            "TOOL": "bold #00f0ff",
            "RESULT": "bold #10b981",
            "FINDING": "bold #f43f5e",
            "HYPOTHESIS": "bold #fbbf24",
            "VERIFICATION": "bold #34d399",
            "ERROR": "bold #ef4444",
            "RETRY": "bold #f59e0b",
            "NEXT": "bold #94a3b8",
            "WARNING": "bold #eab308",
            "COMPLETE": "bold #22c55e",
        }
        style = color_map.get(type_str, "bold #ffffff")
        header = f"{time_tag} [{style}]{type_str}[/{style}]"
        
        body = self.summary
        if self.tool and type_str == "TOOL":
            body = f"Selected: [bold #00f0ff]{self.tool}[/]"
            if self.summary and self.summary != self.tool:
                body += f" — [dim]{self.summary}[/]"
        elif self.result_summary and type_str == "RESULT":
            dur = f" in {self.duration_s:.1f}s" if self.duration_s is not None else ""
            body = f"{self.result_summary}{dur}"
        elif self.severity and type_str == "FINDING":
            body = f"[{self.severity.upper()}] {self.summary}"
            
        return f"{header}\n{body}\n"
