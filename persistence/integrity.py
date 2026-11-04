"""
Phase 18 State Integrity Engine.
Computes and verifies cryptographic SHA-256 hashes of canonical serialized states.
Detects tampering, bit rot, and unauthorized mutations in checkpoints and artifacts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Tuple


class StateIntegrityError(Exception):
    """Raised when serialized state fails integrity or checksum validation."""
    pass


class StateIntegrity:
    """Computes deterministic canonical hashes across dictionary payloads."""

    @classmethod
    def canonical_json(cls, data: Any) -> str:
        """Produces deterministic canonical JSON string with sorted keys and no whitespace."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def compute_hash(cls, payload: Any) -> str:
        """Computes SHA-256 hash of canonical JSON representation."""
        canonical_str = cls.canonical_json(payload)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def verify_integrity(cls, payload: Dict[str, Any], expected_hash: str) -> Tuple[bool, str]:
        """
        Verifies payload against expected SHA-256 hash.
        Returns: (is_valid, computed_hash)
        """
        computed = cls.compute_hash(payload)
        return (computed == expected_hash, computed)

    @classmethod
    def sign_manifest(cls, manifest_dict: Dict[str, Any], file_hashes: Dict[str, str]) -> Dict[str, Any]:
        """Adds component hashes and overall manifest content hash."""
        manifest = dict(manifest_dict)
        manifest["file_hashes"] = file_hashes
        manifest["content_hash"] = cls.compute_hash(file_hashes)
        return manifest
