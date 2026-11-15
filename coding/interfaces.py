"""
Typed interfaces for the lean coding core (roadmap H).

Defines the contracts between the model provider, tool registry, completion gate,
and run session, allowing the pure coding agent to operate independently of
legacy security tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Set, Union


@dataclass
class CodingOutcome:
    status: str  # "completed", "failed", "cancelled", "blocked"
    final_answer: str = ""
    error: Optional[str] = None
    evidence_report: Optional[str] = None
    changed_files: List[str] = field(default_factory=list)
    tests_passed: bool = False
    metrics: Dict[str, Any] = field(default_factory=dict)


class CodingModelProvider(Protocol):
    model_name: str

    def is_available(self) -> bool:
        ...

    def capabilities(self) -> Dict[str, Any]:
        ...

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ...


class CodingGate(Protocol):
    def verify_task(self, prompt: str) -> Any:
        ...


class CodingToolRegistry(Protocol):
    def list_tools(self) -> List[Any]:
        ...

    def execute(self, name: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Any:
        ...
