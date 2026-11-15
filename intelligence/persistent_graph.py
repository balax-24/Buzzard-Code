"""
Persistent SQLite Storage for Engineering Memory Graph.

Stores AST symbol hierarchies, import dependencies, and test mappings in
`.buzzard/memory.db` to enable sub-millisecond cold starts and incremental
dirty-file synchronization on large codebases.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from intelligence.memory_graph import EngineeringMemoryGraph, FileNode, SymbolNode


class PersistentMemoryGraphStore:
    """
    Manages SQLite disk persistence for the EngineeringMemoryGraph.
    """

    def __init__(self, workspace_root: Path, db_path: Optional[Path] = None):
        self.workspace_root = workspace_root.resolve()
        buzzard_dir = self.workspace_root / ".buzzard"
        buzzard_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path or (buzzard_dir / "memory.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    path TEXT PRIMARY KEY,
                    language TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    content_hash TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS symbols (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    docstring TEXT,
                    calls TEXT,
                    FOREIGN KEY (file_path) REFERENCES files (path) ON DELETE CASCADE
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dependencies (
                    source_path TEXT NOT NULL,
                    imported_path TEXT NOT NULL,
                    PRIMARY KEY (source_path, imported_path)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS test_associations (
                    source_path TEXT NOT NULL,
                    test_path TEXT NOT NULL,
                    PRIMARY KEY (source_path, test_path)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_path)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name)")

    def _hash_file(self, path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            return ""

    def save_graph(self, graph: EngineeringMemoryGraph) -> None:
        """Saves the entire in-memory graph to SQLite."""
        with self._get_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            conn.execute("DELETE FROM symbols")
            conn.execute("DELETE FROM dependencies")
            conn.execute("DELETE FROM test_associations")
            conn.execute("DELETE FROM files")

            for rel_path, fnode in graph.files.items():
                abs_p = self.workspace_root / rel_path
                mtime = abs_p.stat().st_mtime if abs_p.exists() else 0.0
                c_hash = self._hash_file(abs_p) if abs_p.exists() else ""

                conn.execute(
                    "INSERT INTO files (path, language, mtime, content_hash) VALUES (?, ?, ?, ?)",
                    (rel_path, fnode.language, mtime, c_hash),
                )

                for sym in fnode.symbols.values():
                    conn.execute(
                        "INSERT INTO symbols (file_path, name, kind, line_number, docstring, calls) VALUES (?, ?, ?, ?, ?, ?)",
                        (rel_path, sym.name, sym.kind, sym.line_number, sym.docstring, json.dumps(list(sym.calls))),
                    )

                for imp in fnode.imports:
                    conn.execute(
                        "INSERT OR IGNORE INTO dependencies (source_path, imported_path) VALUES (?, ?)",
                        (rel_path, imp),
                    )

                for t in fnode.associated_tests:
                    conn.execute(
                        "INSERT OR IGNORE INTO test_associations (source_path, test_path) VALUES (?, ?)",
                        (rel_path, t),
                    )

            conn.commit()

    def load_graph(self) -> Optional[EngineeringMemoryGraph]:
        """Loads the graph from SQLite if database has records."""
        with self._get_connection() as conn:
            file_rows = conn.execute("SELECT * FROM files").fetchall()
            if not file_rows:
                return None

            graph = EngineeringMemoryGraph(self.workspace_root)

            for f_row in file_rows:
                rel_path = f_row["path"]
                node = FileNode(path=rel_path, language=f_row["language"])
                graph.files[rel_path] = node

            symbol_rows = conn.execute("SELECT * FROM symbols").fetchall()
            for s_row in symbol_rows:
                rel_path = s_row["file_path"]
                if rel_path in graph.files:
                    calls_set = set(json.loads(s_row["calls"])) if s_row["calls"] else set()
                    sym = SymbolNode(
                        name=s_row["name"],
                        kind=s_row["kind"],
                        file_path=rel_path,
                        line_number=s_row["line_number"],
                        docstring=s_row["docstring"],
                        calls=calls_set,
                    )
                    graph.files[rel_path].symbols[sym.name] = sym
                    graph.symbol_index.setdefault(sym.name, []).append(sym)

            dep_rows = conn.execute("SELECT * FROM dependencies").fetchall()
            for d_row in dep_rows:
                src, imp = d_row["source_path"], d_row["imported_path"]
                if src in graph.files:
                    graph.files[src].imports.add(imp)
                if imp in graph.files:
                    graph.files[imp].imported_by.add(src)

            test_rows = conn.execute("SELECT * FROM test_associations").fetchall()
            for t_row in test_rows:
                src, test_p = t_row["source_path"], t_row["test_path"]
                if src in graph.files:
                    graph.files[src].associated_tests.add(test_p)

            return graph

    def incremental_sync(self, graph: EngineeringMemoryGraph) -> Dict[str, int]:
        """
        Scans workspace files, compares against SQLite hashes/mtimes,
        and re-indexes ONLY dirty or added files.
        """
        updated = 0
        removed = 0

        with self._get_connection() as conn:
            db_records = {r["path"]: r for r in conn.execute("SELECT * FROM files").fetchall()}

        disk_files: Dict[str, Path] = {}
        ignore_dirs = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".buzzard"}

        for p in self.workspace_root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in ignore_dirs for part in p.parts):
                continue
            if p.suffix in (".py", ".ts", ".tsx", ".js", ".jsx"):
                rel_path = str(p.relative_to(self.workspace_root)).replace("\\", "/")
                disk_files[rel_path] = p

        # Check for deleted files
        for rel_path in list(graph.files.keys()):
            if rel_path not in disk_files:
                del graph.files[rel_path]
                removed += 1

        # Check for new or modified files
        dirty_files = []
        for rel_path, abs_p in disk_files.items():
            db_rec = db_records.get(rel_path)
            current_mtime = abs_p.stat().st_mtime
            if db_rec is None or db_rec["mtime"] < current_mtime:
                current_hash = self._hash_file(abs_p)
                if db_rec is None or db_rec["content_hash"] != current_hash:
                    dirty_files.append((abs_p, rel_path))

        for abs_p, rel_path in dirty_files:
            if abs_p.suffix == ".py":
                graph._index_python_file(abs_p, rel_path)
                updated += 1
            elif abs_p.suffix in (".ts", ".tsx", ".js", ".jsx"):
                graph._index_js_ts_file(abs_p, rel_path)
                updated += 1

        if dirty_files or removed > 0:
            graph._map_cross_file_relationships()
            graph._map_test_associations()
            self.save_graph(graph)

        return {"updated": updated, "removed": removed, "total_tracked": len(graph.files)}
