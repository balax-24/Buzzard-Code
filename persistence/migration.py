"""
Phase 18 Schema Versioning and Migration Engine.
Supports migrating legacy checkpoint schemas into current runtime schema version without data loss.
"""

from __future__ import annotations

import copy
from typing import Any, Dict

CURRENT_SCHEMA_VERSION = "1.1"


class MigrationError(Exception):
    """Raised when checkpoint migration fails or unsupported schema encountered."""
    pass


class SchemaMigrator:
    """Manages schema version detection and non-destructive migrations."""

    @classmethod
    def migrate_payload(cls, data: Dict[str, Any], target_version: str = CURRENT_SCHEMA_VERSION) -> Dict[str, Any]:
        """
        Migrates dictionary payload from its declared schema_version to target_version.
        Preserves all existing fields.
        """
        payload = copy.deepcopy(data)
        current_v = str(payload.get("schema_version", "1.0"))

        if current_v == target_version:
            return payload

        # Migration from 1.0 to 1.1: Ensure new Phase 18 fields are present
        if current_v == "1.0" and target_version == "1.1":
            payload = cls._migrate_1_0_to_1_1(payload)
            current_v = "1.1"

        if current_v != target_version:
            raise MigrationError(f"Unsupported migration path from schema version {current_v} to {target_version}")

        payload["schema_version"] = target_version
        return payload

    @classmethod
    def _migrate_1_0_to_1_1(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Upgrades 1.0 payload to 1.1 structure with default backward-compatible fields."""
        upgraded = dict(data)
        upgraded.setdefault("credentials", {})
        upgraded.setdefault("sessions", {})
        upgraded.setdefault("branches", {})
        upgraded.setdefault("model_attribution", {
            "selected_by_model": True,
            "selected_by_backend": False,
            "backend_fallback": False,
        })
        upgraded.setdefault("budget", {
            "iterations_used": 0,
            "max_iterations": 100,
            "tool_calls_used": 0,
            "max_tool_calls": 200,
            "cost_incurred": 0.0,
        })
        upgraded["schema_version"] = "1.1"
        return upgraded
