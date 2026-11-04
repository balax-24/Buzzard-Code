"""
Assessment Memory and Long-Term Target Intelligence.

Maintains multi-tier memory (recent events, persistent asset knowledge, previous findings)
across recurring assessments on the same target domain.
See plan sections 50, 71 and Phase H.
"""

from typing import Dict, Any, List, Optional
import json
import sqlite3
from pathlib import Path


class AssessmentMemory:
    """
    Manages structured short-term and persistent cross-session memory for targets.
    """
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path.home() / ".security-agent" / "memory.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        schema = """
        CREATE TABLE IF NOT EXISTS target_memory (
            target TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (target, key)
        );
        """
        with self._get_conn() as conn:
            conn.executescript(schema)
            conn.commit()

    def store(self, target: str, key: str, value: Any) -> None:
        """Stores or updates a memory value for a target."""
        val_str = json.dumps(value) if not isinstance(value, str) else value
        now = __import__("time").time()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO target_memory (target, key, value, updated_at) VALUES (?, ?, ?, ?)",
                (target, key, val_str, now)
            )
            conn.commit()

    def recall(self, target: str, key: str) -> Optional[Any]:
        """Recalls a stored value for a target."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT value FROM target_memory WHERE target = ? AND key = ?",
                (target, key)
            ).fetchone()
            if row:
                try:
                    return json.loads(row["value"])
                except Exception:
                    return row["value"]
        return None

    def get_all_target_knowledge(self, target: str) -> Dict[str, Any]:
        """Retrieves all memory entries associated with a target."""
        knowledge = {}
        with self._get_conn() as conn:
            rows = conn.execute("SELECT key, value FROM target_memory WHERE target = ?", (target,)).fetchall()
            for r in rows:
                try:
                    knowledge[r["key"]] = json.loads(r["value"])
                except Exception:
                    knowledge[r["key"]] = r["value"]
        return knowledge
