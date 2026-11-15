"""
AST-Native Structural Code Morphing for Buzzard Code.

Replaces brittle string/regex search-and-replace with syntactic AST node transformations:
1. Replaces functions or methods by target symbol name regardless of whitespace.
2. Inserts imports cleanly without duplicate entries.
3. Guarantees AST syntax validity before emitting modified files.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class MorphResult:
    success: bool
    modified_code: str
    target_found: bool
    error: Optional[str] = None


class AstMorphEngine:
    """
    Performs structural code modifications on Python abstract syntax trees.
    """

    def replace_function(self, source_code: str, func_name: str, new_func_code: str) -> MorphResult:
        """
        Replaces the definition and body of a top-level function with new_func_code.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Original file has syntax error: {e}")

        try:
            ast.parse(new_func_code)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"New function code has syntax error: {e}")

        lines = source_code.splitlines(keepends=True)
        target_node = None

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                target_node = node
                break

        if not target_node:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Function '{func_name}' not found.")

        start_line = target_node.lineno - 1
        end_line = getattr(target_node, "end_lineno", target_node.lineno)

        # Build replacement lines with proper newline
        rep = new_func_code.rstrip() + "\n"
        new_lines = lines[:start_line] + [rep] + lines[end_line:]
        result_code = "".join(new_lines)

        # Validate morphed output
        try:
            ast.parse(result_code)
            return MorphResult(success=True, modified_code=result_code, target_found=True)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=True, error=f"Morphed output failed validation: {e}")

    def replace_method(self, source_code: str, class_name: str, method_name: str, new_method_code: str) -> MorphResult:
        """
        Replaces a method inside a specific class definition.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Original file syntax error: {e}")

        lines = source_code.splitlines(keepends=True)
        target_class = None
        target_method = None

        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                target_class = node
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method_name:
                        target_method = item
                        break
                break

        if not target_class:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Class '{class_name}' not found.")
        if not target_method:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Method '{method_name}' not found in '{class_name}'.")

        start_line = target_method.lineno - 1
        end_line = getattr(target_method, "end_lineno", target_method.lineno)

        # Indent new method code to match class body indentation (default 4 spaces)
        method_lines = new_method_code.splitlines()
        indented_lines = ["    " + line if line.strip() else line for line in method_lines]
        rep = "\n".join(indented_lines).rstrip() + "\n"

        new_lines = lines[:start_line] + [rep] + lines[end_line:]
        result_code = "".join(new_lines)

        try:
            ast.parse(result_code)
            return MorphResult(success=True, modified_code=result_code, target_found=True)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=True, error=f"Morphed method output failed validation: {e}")

    def insert_import(self, source_code: str, import_stmt: str) -> MorphResult:
        """
        Inserts an import statement at the top of the file if not already present.
        """
        stmt_clean = import_stmt.strip()
        if stmt_clean in source_code:
            return MorphResult(success=True, modified_code=source_code, target_found=True)

        lines = source_code.splitlines(keepends=True)
        insert_idx = 0

        # Skip docstring or shebang
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''") or not stripped:
                insert_idx = idx + 1
            else:
                break

        lines.insert(insert_idx, stmt_clean + "\n")
        result_code = "".join(lines)

        try:
            ast.parse(result_code)
            return MorphResult(success=True, modified_code=result_code, target_found=True)
        except SyntaxError as e:
            return MorphResult(success=False, modified_code=source_code, target_found=False, error=f"Invalid import statement: {e}")
