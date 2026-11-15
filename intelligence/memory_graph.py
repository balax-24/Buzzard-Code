"""
Engineering Memory Graph for Buzzard Code.

Maintains an in-memory, AST-informed relational graph of the codebase:
- Files and modules
- Imports and dependencies
- Symbol definitions (classes, functions)
- Associated test mappings
- Cross-file call impact radius
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class SymbolNode:
    name: str
    kind: str  # 'function', 'class', 'module'
    file_path: str
    line_number: int
    docstring: Optional[str] = None
    calls: Set[str] = field(default_factory=set)


@dataclass
class FileNode:
    path: str
    language: str
    imports: Set[str] = field(default_factory=set)
    imported_by: Set[str] = field(default_factory=set)
    symbols: Dict[str, SymbolNode] = field(default_factory=dict)
    associated_tests: Set[str] = field(default_factory=set)


class EngineeringMemoryGraph:
    """
    Constructs and queries the structural and relational graph of a repository.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.files: Dict[str, FileNode] = {}
        self.symbol_index: Dict[str, List[SymbolNode]] = {}

    def index_workspace(self, max_files: int = 500) -> Dict[str, int]:
        """
        Scans the workspace and builds the relational graph.
        """
        count = 0
        py_files = []
        js_ts_files = []

        ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache"}

        for p in self.workspace_root.rglob("*"):
            if count >= max_files:
                break
            if not p.is_file():
                continue
            if any(part in ignore_dirs for part in p.parts):
                continue

            rel_str = str(p.relative_to(self.workspace_root)).replace("\\", "/")
            if p.suffix == ".py":
                py_files.append((p, rel_str))
                count += 1
            elif p.suffix in (".ts", ".tsx", ".js", ".jsx"):
                js_ts_files.append((p, rel_str))
                count += 1

        for p, rel_path in py_files:
            self._index_python_file(p, rel_path)

        for p, rel_path in js_ts_files:
            self._index_js_ts_file(p, rel_path)

        self._map_cross_file_relationships()
        self._map_test_associations()

        return {
            "total_files": len(self.files),
            "total_symbols": sum(len(f.symbols) for f in self.files.values()),
        }

    def _index_python_file(self, file_path: Path, rel_path: str) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(file_path))
        except Exception:
            return

        node = FileNode(path=rel_path, language="python")

        for item in ast.walk(tree):
            if isinstance(item, ast.Import):
                for alias in item.names:
                    node.imports.add(alias.name)
            elif isinstance(item, ast.ImportFrom):
                if item.module:
                    node.imports.add(item.module)

            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sym = SymbolNode(
                    name=item.name,
                    kind="function",
                    file_path=rel_path,
                    line_number=item.lineno,
                    docstring=ast.get_docstring(item),
                )
                node.symbols[item.name] = sym
                self.symbol_index.setdefault(item.name, []).append(sym)

            elif isinstance(item, ast.ClassDef):
                sym = SymbolNode(
                    name=item.name,
                    kind="class",
                    file_path=rel_path,
                    line_number=item.lineno,
                    docstring=ast.get_docstring(item),
                )
                node.symbols[item.name] = sym
                self.symbol_index.setdefault(item.name, []).append(sym)

        self.files[rel_path] = node

    def _index_js_ts_file(self, file_path: Path, rel_path: str) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        node = FileNode(path=rel_path, language="typescript" if file_path.suffix.startswith(".t") else "javascript")

        # Fast regex extraction for imports and function/class exports
        import_pattern = re.compile(r'(?:import|from)\s+[\'"]([^\'"]+)[\'"]')
        for match in import_pattern.finditer(content):
            node.imports.add(match.group(1))

        func_pattern = re.compile(r'(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)|const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(')
        for line_no, line in enumerate(content.splitlines(), start=1):
            m = func_pattern.search(line)
            if m:
                name = m.group(1) or m.group(2)
                if name:
                    sym = SymbolNode(name=name, kind="function", file_path=rel_path, line_number=line_no)
                    node.symbols[name] = sym
                    self.symbol_index.setdefault(name, []).append(sym)

        self.files[rel_path] = node

    def _map_cross_file_relationships(self) -> None:
        """Connects imported_by across indexed files."""
        for src_path, src_node in self.files.items():
            for imp in src_node.imports:
                # Resolve relative or module imports
                for target_path, target_node in self.files.items():
                    if target_path == src_path:
                        continue
                    # Match module name or relative path
                    target_module = target_path.replace("/", ".").rsplit(".", 1)[0]
                    target_base = Path(target_path).stem
                    if imp.endswith(target_base) or imp == target_module or imp in target_path:
                        target_node.imported_by.add(src_path)

    def _map_test_associations(self) -> None:
        """Associates source files with their corresponding test files."""
        test_files = [p for p in self.files.keys() if "test" in p.lower()]

        for src_path, src_node in self.files.items():
            if src_path in test_files:
                continue
            src_stem = Path(src_path).stem
            for t in test_files:
                t_lower = t.lower()
                if src_stem.lower() in t_lower or f"test_{src_stem.lower()}" in t_lower:
                    src_node.associated_tests.add(t)

    def get_impact_radius(self, target_path: str) -> Dict[str, Any]:
        """
        Given a file being modified, returns all direct callers, importers, and associated tests.
        """
        normalized = target_path.replace("\\", "/")
        node = self.files.get(normalized)
        if not node:
            # Try suffix match
            for k, v in self.files.items():
                if k.endswith(normalized) or normalized.endswith(k):
                    node = v
                    normalized = k
                    break

        if not node:
            return {
                "file": target_path,
                "found": False,
                "imported_by": [],
                "associated_tests": [],
                "symbols": [],
            }

        return {
            "file": normalized,
            "found": True,
            "imported_by": sorted(list(node.imported_by)),
            "associated_tests": sorted(list(node.associated_tests)),
            "symbols": sorted(list(node.symbols.keys())),
        }
