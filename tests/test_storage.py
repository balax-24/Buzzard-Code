import pytest
import os
import tempfile
from pathlib import Path
from storage.db import StorageManager
from model.schemas import Finding, Evidence, Severity, Confidence, EvidenceType, TaskStatus


def test_db_initialization(temp_db):
    """
    Verifies database tables are created correctly.
    """
    mgr = StorageManager(db_path=temp_db)
    assert Path(temp_db).exists()
    
    # Test listing sessions on empty db
    sessions = mgr.list_sessions()
    assert len(sessions) == 0

def test_session_lifecycle(temp_db):
    """
    Verifies session creation and updates.
    """
    mgr = StorageManager(db_path=temp_db)
    session_id = "test-task-001"
    
    mgr.create_session(
        session_id=session_id,
        target="localhost",
        scope=["localhost", "127.0.0.1"],
        goal="Verify port scanning isolation"
    )
    
    session = mgr.get_session(session_id)
    assert session is not None
    assert session["target"] == "localhost"
    assert session["status"] == TaskStatus.RUNNING.value
    assert session["scope"] == ["localhost", "127.0.0.1"]
    
    mgr.update_session_status(session_id, TaskStatus.COMPLETED)
    session = mgr.get_session(session_id)
    assert session["status"] == TaskStatus.COMPLETED.value

def test_plan_storage(temp_db):
    """
    Verifies plan saving and retrieval.
    """
    mgr = StorageManager(db_path=temp_db)
    session_id = "test-plan-001"
    mgr.create_session(session_id, "localhost", [], "Test plan")
    
    plan_steps = ["Step 1", "Step 2", "Step 3"]
    mgr.save_plan(session_id, plan_steps, current_index=1)
    
    saved_plan = mgr.get_plan(session_id)
    assert len(saved_plan) == 3
    assert saved_plan[0]["task_description"] == "Step 1"
    assert saved_plan[0]["status"] == "completed"
    assert saved_plan[1]["status"] == "running"
    assert saved_plan[2]["status"] == "pending"

def test_findings_and_evidence(temp_db):
    """
    Verifies inserting and fetching findings and evidence.
    """
    mgr = StorageManager(db_path=temp_db)
    session_id = "test-findings-001"
    mgr.create_session(session_id, "localhost", [], "Test findings")
    
    # Add evidence
    evidence = Evidence(
        id="EVID-001",
        type=EvidenceType.TERMINAL,
        target="port-80",
        description="Nmap trace output",
        data="80/tcp open http",
        timestamp="2026-08-16T12:00:00Z"
    )
    mgr.add_evidence(session_id, evidence)
    
    ev_list = mgr.get_evidence_list(session_id)
    assert len(ev_list) == 1
    assert ev_list[0].id == "EVID-001"
    assert ev_list[0].data == "80/tcp open http"
    
    # Add finding referencing evidence
    finding = Finding(
        id="FIND-001",
        title="Open HTTP Port",
        severity=Severity.INFO,
        confidence=Confidence.CONFIRMED,
        affected_asset="port-80",
        description="HTTP service is running on target port 80",
        evidence=["EVID-001"],
        impact="Information disclosure",
        verification="Nmap scan",
        remediation="Close port if unused"
    )
    mgr.add_finding(session_id, finding)
    
    findings_list = mgr.get_findings(session_id)
    assert len(findings_list) == 1
    assert findings_list[0].id == "FIND-001"
    assert findings_list[0].evidence == ["EVID-001"]
