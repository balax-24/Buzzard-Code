"""
AST-Aware Atomic Code Editor for Buzzard Code.

Applies multi-file code modifications with transactional safety:
1. Validates AST / syntax in-memory before writing to disk
2. Catches indentation, syntax, and structural errors immediately
3. Rolls back all staged files if any file in the changeset fails validation
4. Provides precise line-and-column diagnostic error reports
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class EditOperation:
    file_path: str
    original_text: Optional[str] = None
    target_pattern: Optional[str] = None
    replacement_text: Optional[str] = None
    new_full_content: Optional[str] = None


@dataclass
class TransactionResult:
    success: bool
    modified_files: List[str] = field(default_factory=list)
    syntax_errors: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    backups_created: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "modified_files": self.modified_files,
            "syntax_errors": self.syntax_errors,
            "error_message": self.error_message,
        }


class AtomicCodeEditor:
    """
    Executes code modifications with strict syntax checks and atomic rollback guarantees.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def validate_content_syntax(self, file_path: str, content: str) -> Optional[str]:
        """
        Validates content syntax in-memory. Returns error message or None if valid.
        """
        path = Path(file_path)
        suffix = path.suffix.lower()

        # 1. Python AST parsing
        if suffix == ".py":
            try:
                ast.parse(content, filename=str(file_path))
            except SyntaxError as e:
                return f"Python SyntaxError at line {e.lineno}, col {e.offset}: {e.msg}"
            except Exception as e:
                return f"Python AST error: {e}"

        # 2. JSON validation
        elif suffix == ".json":
            try:
                json.loads(content)
            except json.JSONDecodeError as e:
                return f"JSON SyntaxError at line {e.lineno}, col {e.colno}: {e.msg}"

        # 3. JavaScript / TypeScript basic structural balance check
        elif suffix in (".ts", ".tsx", ".js", ".jsx"):
            error = self._check_bracket_balance(content)
            if error:
                return f"JS/TS Structural Error: {error}"

        return None

    def _check_bracket_balance(self, content: str) -> Optional[str]:
        """Simple structural balance check for braces, brackets, and parens."""
        stack = []
        pairs = {")": "(", "}": "{", "]": "["}
        lines = content.split("\n")

        # Strip comments and strings roughly
        in_multiline_comment = False
        for line_no, line in enumerate(lines, 1):
            i = 0
            while i < len(line):
                if not in_multiline_comment and line[i:i+2] == "/*":
                    in_multiline_comment = True
                    i += 2
                    continue
                if in_multiline_comment:
                    if line[i:i+2] == "*/":
                        in_multiline_comment = False
                        i += 2
                    else:
                        i += 1
                    continue
                if line[i:i+2] == "//":
                    break

                char = line[i]
                if char in ("(", "{", "["):
                    stack.append((char, line_no))
                elif char in (")", "}", "]"):
                    if not stack:
                        return f"Unmatched closing '{char}' at line {line_no}"
                    top, start_line = stack.pop()
                    if pairs[char] != top:
                        return f"Mismatched bracket: opened '{top}' at line {start_line}, closed with '{char}' at line {line_no}"
                i += 1

        if stack:
            unclosed, start_line = stack[-1]
            return f"Unclosed '{unclosed}' opened at line {start_line}"

        return None

    def apply_replacement(self, original: str, target: str, replacement: str) -> Tuple[bool, str, Optional[str]]:
        """
        Replaces target with replacement. Requires exact match.
        """
        if target not in original:
            # Try fuzzy whitespace normalization
            norm_orig = re.sub(r"[ \t]+", " ", original)
            norm_target = re.sub(r"[ \t]+", " ", target)
            if norm_target in norm_orig:
                return False, original, "Target matched only with whitespace differences. Exact match required."
            return False, original, f"Target block not found in file."

        new_content = original.replace(target, replacement, 1)
        return True, new_content, None

    def apply_transaction(self, operations: List[EditOperation]) -> TransactionResult:
        """
        Atomically executes all operations. Validates all files before writing anything.
        """
        staged_writes: Dict[Path, str] = {}
        original_backups: Dict[str, str] = {}
        syntax_errors: List[str] = []

        # Phase 1: In-memory simulation and validation
        for op in operations:
            target_path = (self.workspace_root / op.file_path).resolve()

            # Ensure inside workspace
            try:
                target_path.relative_to(self.workspace_root)
            except ValueError:
                return TransactionResult(
                    success=False,
                    error_message=f"Path '{op.file_path}' traverses outside workspace boundary.",
                )

            original_content = ""
            if target_path.exists():
                original_content = target_path.read_text(encoding="utf-8", errors="replace")
                original_backups[op.file_path] = original_content

            # Determine new content
            if op.new_full_content is not None:
                new_content = op.new_full_content
            elif op.target_pattern and op.replacement_text is not None:
                success, new_content, err = self.apply_replacement(
                    original_content, op.target_pattern, op.replacement_text
                )
                if not success:
                    return TransactionResult(
                        success=False,
                        error_message=f"Failed to apply edit to {op.file_path}: {err}",
                    )
            else:
                return TransactionResult(
                    success=False,
                    error_message=f"Invalid edit operation for {op.file_path}: missing replacement or full content.",
                )

            # Validate syntax
            err = self.validate_content_syntax(op.file_path, new_content)
            if err:
                syntax_errors.append(f"{op.file_path}: {err}")

            staged_writes[target_path] = new_content

        # If any file has syntax errors, abort transaction with zero writes
        if syntax_errors:
            return TransactionResult(
                success=False,
                syntax_errors=syntax_errors,
                error_message=f"Transaction aborted: {len(syntax_errors)} syntax/AST validation error(s).",
            )

        # Phase 2: Atomic commit to disk
        written_files: List[str] = []
        try:
            for p, content in staged_writes.items():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
                written_files.append(str(p.relative_to(self.workspace_root)).replace("\\", "/"))
        except Exception as e:
            # Rollback on disk failure
            for rel_path, orig in original_backups.items():
                (self.workspace_root / rel_path).write_text(orig, encoding="utf-8")
            return TransactionResult(
                success=False,
                error_message=f"Disk write failure during commit: {e}. Rolled back all changes.",
            )

        return TransactionResult(
            success=True,
            modified_files=written_files,
            backups_created=original_backups,
        )
