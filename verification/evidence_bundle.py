"""Local Evidence Bundle creation and verification for coding runs."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import redact_secrets
from tui.models import redact_sensitive_data
from verification.coding_verifier import list_changed_files


SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 10_000_000


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _repository_root(workspace: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(workspace), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError("Evidence Bundles require a Git working tree.")
    return Path(result.stdout.strip()).resolve()


def _working_tree_hash(root: Path) -> tuple[str, list[str]]:
    changed = sorted(
        path for path in list_changed_files(root)
        if path.replace("\\", "/") != ".buzzard/evidence"
        and not path.replace("\\", "/").startswith(".buzzard/evidence/")
    )
    digest = hashlib.sha256()
    for relative in changed:
        target = Path(os.path.abspath(root / relative))
        try:
            target.relative_to(root)
        except ValueError as error:
            raise ValueError(f"Changed path escapes the repository: {relative}") from error
        digest.update(relative.replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        if target.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(target).encode("utf-8", errors="surrogateescape"))
        elif target.is_file():
            digest.update(b"file\0")
            with target.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
        else:
            digest.update(b"deleted\0")
    return digest.hexdigest(), changed


def _bundle_digest(bundle: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in bundle.items() if key != "bundle_sha256"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _redact_bundle_values(value: Any) -> Any:
    """Redact sensitive field names and credential-like text before persisting the record."""
    if isinstance(value, dict):
        return {key: _redact_bundle_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_bundle_values(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive_data(value)
    return value


def _ensure_evidence_directory(root: Path) -> Path:
    """Create the runtime directory only when existing links remain inside the repository."""
    directory = root / ".buzzard" / "evidence"
    buzzard_directory = root / ".buzzard"
    for candidate in (buzzard_directory, directory):
        if os.path.lexists(candidate):
            resolved = candidate.resolve(strict=False)
            try:
                resolved.relative_to(root)
            except ValueError as error:
                raise ValueError(f"Evidence path escapes the repository: {candidate}") from error
    directory.mkdir(parents=True, exist_ok=True)
    resolved_directory = directory.resolve(strict=True)
    try:
        resolved_directory.relative_to(root)
    except ValueError as error:
        raise ValueError(f"Evidence path escapes the repository: {directory}") from error
    return resolved_directory


def create_evidence_bundle(
    *,
    workspace: str | Path,
    session_id: str,
    task: str,
    verification: Any,
    approvals_granted: int,
    approvals_denied: int,
    model: str,
    evidence_report: str | None,
) -> Path:
    """Write a redacted, integrity-checkable bundle under `.buzzard/evidence/`."""
    root = _repository_root(Path(workspace).resolve())
    working_tree_sha256, changed_files = _working_tree_hash(root)
    head_result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    head = head_result.stdout.strip() if head_result.returncode == 0 else None
    verification_data = {
        "passed": getattr(verification, "passed", None),
        "requires_action": getattr(verification, "requires_action", None),
        "test_command": getattr(verification, "test_command", None),
        "test_exit_code": getattr(verification, "test_exit_code", None),
        "test_environment": getattr(verification, "test_environment", "unknown"),
        "lint_command": getattr(verification, "lint_command", None),
        "lint_status": getattr(verification, "lint_status", "not measured"),
        "changed_line_coverage": None,
    }
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "repository": {
            "root": str(root),
            "head": head,
            "working_tree_sha256": working_tree_sha256,
            "changed_files": changed_files,
        },
        "task": task,
        "verification": verification_data,
        "approvals": {"granted": approvals_granted, "denied": approvals_denied},
        "runtime": {
            "model": model,
            "buzzard_version": "1.0.0",
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "evidence_report": evidence_report,
    }
    bundle = _redact_bundle_values(redact_secrets(bundle))
    bundle["bundle_sha256"] = _bundle_digest(bundle)

    safe_session = "".join(char for char in session_id if char.isalnum() or char in "-_")[:80] or "run"
    output_directory = _ensure_evidence_directory(root)
    output_path = output_directory / f"{safe_session}.json"
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".evidence-", suffix=".tmp", dir=output_directory, delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(_canonical_json(bundle) + b"\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
    return output_path


def verify_evidence_bundle(bundle_path: str | Path, workspace: str | Path | None = None) -> dict[str, Any]:
    """Verify bundle integrity and whether its recorded working tree is still present."""
    path = Path(bundle_path).resolve()
    try:
        if path.stat().st_size > MAX_BUNDLE_BYTES:
            return {"valid": False, "reason": "Evidence Bundle exceeds the 10 MB size limit."}
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {"valid": False, "reason": f"Cannot read Evidence Bundle: {error}"}
    if not isinstance(bundle, dict) or bundle.get("schema_version") != SCHEMA_VERSION:
        return {"valid": False, "reason": "Unsupported or malformed Evidence Bundle schema."}
    recorded_digest = bundle.get("bundle_sha256")
    if not isinstance(recorded_digest, str) or recorded_digest != _bundle_digest(bundle):
        return {"valid": False, "reason": "Evidence Bundle integrity hash does not match."}

    repository = bundle.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("working_tree_sha256"), str):
        return {"valid": False, "reason": "Evidence Bundle has no repository state hash."}
    try:
        root = _repository_root(Path(workspace).resolve()) if workspace else Path(str(repository.get("root"))).resolve()
        current_hash, _changed_files = _working_tree_hash(root)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        return {"valid": False, "reason": f"Cannot verify repository state: {error}"}
    matches = current_hash == repository["working_tree_sha256"]
    return {
        "valid": matches,
        "reason": "Bundle matches the current repository state." if matches else "Repository working tree differs from the recorded state.",
        "repository_matches": matches,
        "bundle_sha256": recorded_digest,
    }
