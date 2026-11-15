"""
Intelligent Model Router for Buzzard Code.

Routes tasks across providers and model capability tiers:
1. Fast Tier (Small): File search, symbol lookup, git status, syntax check
2. Standard Tier (Medium): Implementation, unit tests, refactoring
3. Frontier Tier (Large / Deep Thinking): System architecture, cross-module debugging, security audit

Dynamically incorporates blast radius from ChangeImpactSimulator to select the optimal model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class ModelTier:
    name: str  # 'fast', 'standard', 'frontier'
    preferred_models: List[str]
    description: str


DEFAULT_TIERS: Dict[str, ModelTier] = {
    "fast": ModelTier(
        name="fast",
        preferred_models=[
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash-lite",
            "gpt-4o-mini",
            "qwen2.5-coder:7b",
            "k3-sec:latest",
        ],
        description="Fast lightweight tasks: search, symbol indexing, git diff, syntax validation",
    ),
    "standard": ModelTier(
        name="standard",
        preferred_models=[
            "gemini-2.5-flash",
            "gpt-4o",
            "claude-3-5-sonnet",
            "deepseek-v3",
            "qwen-cyber:latest",
        ],
        description="Standard engineering tasks: feature implementation, unit testing, refactoring",
    ),
    "frontier": ModelTier(
        name="frontier",
        preferred_models=[
            "claude-3-7-sonnet",
            "gemini-2.5-pro",
            "o3-mini",
            "deepseek-r1",
            "deephat:latest",
        ],
        description="Frontier reasoning: architecture design, high-risk security audit, deep debugging",
    ),
}


class CodingModelRouter:
    """
    Intelligently routes engineering tasks to appropriate model tiers.
    """

    def __init__(self, available_models: Optional[List[str]] = None, tiers: Optional[Dict[str, ModelTier]] = None):
        self.available_models = available_models or []
        self.tiers = tiers or DEFAULT_TIERS

    def classify_task_tier(
        self,
        task_text: str,
        risk_level: Optional[str] = None,
        affected_files_count: int = 0,
    ) -> str:
        """
        Determines whether a task requires 'fast', 'standard', or 'frontier' model tier.
        """
        text = (task_text or "").lower()

        # 1. High risk or large blast radius -> Frontier
        if risk_level in ("high", "critical") or affected_files_count >= 5:
            return "frontier"

        # 2. Complex architectural / security / debugging patterns -> Frontier
        frontier_keywords = (
            "architect", "security audit", "vulnerability", "cve", "auth bypass",
            "root cause", "memory leak", "deadlock", "race condition", "redesign",
            "migration", "concurrency", "threat model", "invariant"
        )
        if any(kw in text for kw in frontier_keywords):
            return "frontier"

        # 3. Simple lookup / inspection / formatting -> Fast
        fast_keywords = (
            "where is", "find file", "search for", "list files", "git status",
            "check syntax", "what does", "show line", "grep", "locate"
        )
        if any(kw in text for kw in fast_keywords) and not any(kw in text for kw in ("fix", "refactor", "implement")):
            return "fast"

        # 4. Standard engineering task -> Standard
        return "standard"

    def select_model(
        self,
        task_text: str,
        risk_level: Optional[str] = None,
        affected_files_count: int = 0,
        configured_default: Optional[str] = None,
    ) -> str:
        """
        Selects the best available model for the task.
        """
        tier_name = self.classify_task_tier(task_text, risk_level, affected_files_count)
        tier = self.tiers.get(tier_name, self.tiers["standard"])

        # Check if an available model matches the tier's preferred list
        if self.available_models:
            for pref in tier.preferred_models:
                for avail in self.available_models:
                    if pref.lower() in avail.lower() or avail.lower() in pref.lower():
                        return avail

            # Fallback to configured default if available
            if configured_default and configured_default in self.available_models:
                return configured_default

            return self.available_models[0]

        # No active restriction: return top preferred model
        return tier.preferred_models[0]
