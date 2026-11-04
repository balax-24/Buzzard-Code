import os
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from model.schemas import Finding, Evidence, Severity, Confidence, EvidenceType, TaskStatus

DEFAULT_DB_DIR = Path.home() / ".security-agent"
DEFAULT_DB_FILE = DEFAULT_DB_DIR / "storage.db"

class StorageManager:
    """
    Manages SQLite database storage for sessions, plans, findings, and evidence.
    """
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = DEFAULT_DB_FILE
            
        # Ensure directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """
        Creates and returns a connection to the database.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """
        Initializes schema tables if they do not exist.
        """
        schema = """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            scope TEXT NOT NULL,
            goal TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS plans (
            session_id TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            task_description TEXT NOT NULL,
            status TEXT NOT NULL,
            PRIMARY KEY (session_id, step_index),
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            session_id TEXT NOT NULL,
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            affected_asset TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            impact TEXT NOT NULL,
            verification TEXT NOT NULL,
            remediation TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidence (
            session_id TEXT NOT NULL,
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            target TEXT NOT NULL,
            description TEXT NOT NULL,
            data TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
        );
        """
        with self._get_connection() as conn:
            conn.executescript(schema)
            conn.commit()

    def create_session(self, session_id: str, target: str, scope: List[str], goal: str) -> None:
        """
        Creates a new session record in the database.
        """
        now = datetime.now().isoformat()
        scope_str = json.dumps(scope)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (id, target, scope, goal, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, target, scope_str, goal, TaskStatus.RUNNING.value, now, now)
            )
            conn.commit()

    def update_session_status(self, session_id: str, status: TaskStatus) -> None:
        """
        Updates the execution status of a session.
        """
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE sessions SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, session_id)
            )
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a session dict by session_id.
        """
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if row:
                d = dict(row)
                d["scope"] = json.loads(d["scope"])
                return d
        return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        Lists all recorded sessions.
        """
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
            sessions = []
            for r in rows:
                d = dict(r)
                d["scope"] = json.loads(d["scope"])
                sessions.append(d)
            return sessions
        return []

    def save_plan(self, session_id: str, plan: List[str], current_index: int = 0) -> None:
        """
        Saves/updates steps of a session plan.
        """
        with self._get_connection() as conn:
            # Delete old plan steps
            conn.execute("DELETE FROM plans WHERE session_id = ?", (session_id,))
            
            # Insert new steps
            for idx, task in enumerate(plan):
                status = "completed" if idx < current_index else ("running" if idx == current_index else "pending")
                conn.execute(
                    """
                    INSERT INTO plans (session_id, step_index, task_description, status)
                    VALUES (?, ?, ?, ?)
                    """,
                    (session_id, idx, task, status)
                )
            conn.commit()

    def get_plan(self, session_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves the plan steps for a session.
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM plans WHERE session_id = ? ORDER BY step_index ASC",
                (session_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def add_finding(self, session_id: str, finding: Finding) -> None:
        """
        Inserts a new finding into findings table.
        """
        now = datetime.now().isoformat()
        evidence_str = json.dumps(finding.evidence)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings 
                (session_id, id, title, severity, confidence, affected_asset, description, evidence, impact, verification, remediation, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id, 
                    finding.id, 
                    finding.title, 
                    finding.severity.value, 
                    finding.confidence.value, 
                    finding.affected_asset, 
                    finding.description, 
                    evidence_str, 
                    finding.impact, 
                    finding.verification, 
                    finding.remediation, 
                    finding.status, 
                    now
                )
            )
            conn.commit()

    def get_findings(self, session_id: str) -> List[Finding]:
        """
        Retrieves findings list parsed to Pydantic models.
        """
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE session_id = ?", (session_id,)).fetchall()
            findings = []
            for r in rows:
                data = dict(r)
                findings.append(Finding(
                    id=data["id"],
                    title=data["title"],
                    severity=Severity(data["severity"]),
                    confidence=Confidence(data["confidence"]),
                    affected_asset=data["affected_asset"],
                    description=data["description"],
                    evidence=json.loads(data["evidence"]),
                    impact=data["impact"],
                    verification=data["verification"],
                    remediation=data["remediation"],
                    status=data["status"]
                ))
            return findings

    def add_evidence(self, session_id: str, evidence: Evidence) -> None:
        """
        Inserts a new evidence record.
        """
        data_str = json.dumps(evidence.data) if not isinstance(evidence.data, str) else evidence.data
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence (session_id, id, type, target, description, data, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    evidence.id,
                    evidence.type.value,
                    evidence.target,
                    evidence.description,
                    data_str,
                    evidence.timestamp
                )
            )
            conn.commit()

    def get_evidence_list(self, session_id: str) -> List[Evidence]:
        """
        Retrieves all evidence associated with a session.
        """
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE session_id = ?", (session_id,)).fetchall()
            evidence_list = []
            for r in rows:
                data = dict(r)
                try:
                    raw_data = json.loads(data["data"])
                except Exception:
                    raw_data = data["data"]
                    
                evidence_list.append(Evidence(
                    id=data["id"],
                    type=EvidenceType(data["type"]),
                    target=data["target"],
                    description=data["description"],
                    data=raw_data,
                    timestamp=data["timestamp"]
                ))
            return evidence_list

    # Convenient alias
    get_evidence = get_evidence_list
