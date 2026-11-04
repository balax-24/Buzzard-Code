"""
Phase 18 Atomic Checkpoint Engine.
Manages atomic write strategies (tempfile -> SHA-256 calculation -> atomic rename) to guarantee zero corrupted checkpoints upon crashes.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from security_agent.persistence.integrity import StateIntegrity, StateIntegrityError


class CheckpointError(Exception):
    """Raised when creating, verifying, or reading a checkpoint fails."""
    pass


class AtomicCheckpoint:
    """Provides atomic checkpoint creation, validation, and rollback safety."""

    @classmethod
    def write_atomic(
        cls,
        target_path: str | Path,
        payload: Dict[str, Any],
        compute_checksum: bool = True,
    ) -> Tuple[str, str]:
        """
        Writes serialized payload atomically:
          1. Write to .tmp file in same directory
          2. Compute SHA-256 integrity hash
          3. fsync file buffer to disk
          4. Atomically rename .tmp -> target_path
        Returns: (final_path, sha256_hash)
        """
        dest = Path(target_path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        data = copy_payload = dict(payload)
        if compute_checksum:
            # Strip existing content_hash if present before computing new
            data_to_hash = {k: v for k, v in data.items() if k != "content_hash"}
            content_hash = StateIntegrity.compute_hash(data_to_hash)
            data["content_hash"] = content_hash
        else:
            content_hash = data.get("content_hash", "")

        tmp_path = dest.with_suffix(f".tmp.{os.getpid()}.{time.time_ns()}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            os.replace(tmp_path, dest)
            return (str(dest), content_hash)
        except Exception as exc:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise CheckpointError(f"Atomic checkpoint write failed for {dest}: {exc}") from exc

    @classmethod
    def read_checkpoint(
        cls,
        file_path: str | Path,
        verify_integrity: bool = True,
    ) -> Dict[str, Any]:
        """Reads and validates an atomic checkpoint file."""
        src = Path(file_path).resolve()
        if not src.exists():
            raise CheckpointError(f"Checkpoint file {src} does not exist.")

        try:
            with open(src, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise CheckpointError(f"Failed to parse JSON from {src}: {exc}") from exc

        if verify_integrity and "content_hash" in data:
            expected_hash = data["content_hash"]
            data_to_verify = {k: v for k, v in data.items() if k != "content_hash"}
            is_valid, comp = StateIntegrity.verify_integrity(data_to_verify, expected_hash)
            if not is_valid:
                raise StateIntegrityError(f"Checkpoint {src} corrupted! Expected {expected_hash}, got {comp}")

        return data
