import pytest
from security_agent.storage.db import StorageManager
from security_agent.tools.registry import ToolRegistry
from security_agent.tools.evidence import register_evidence_tools
from security_agent.model.schemas import Severity, Confidence, EvidenceType

def test_evidence_and_finding_tools(temp_db):
    """
    Verifies that the log_evidence and log_finding tools persist data to the DB.
    """
    registry = ToolRegistry()
    register_evidence_tools(registry)
    storage = StorageManager(db_path=temp_db)
    
    session_id = "test-session-ev"
    storage.create_session(session_id, "localhost", ["localhost"], "Test task")
    
    context = {
        "session_id": session_id,
        "storage_manager": storage
    }
    
    # 1. Test log_evidence
    evidence_res = registry.execute(
        name="log_evidence",
        arguments={
            "type": "terminal",
            "target": "localhost:22",
            "description": "SSH banner response",
            "data": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        },
        context=context
    )
    
    assert "Evidence logged successfully with ID:" in evidence_res
    evidence_id = evidence_res.split(":")[-1].strip()
    
    # Retrieve evidence from DB
    ev_list = storage.get_evidence_list(session_id)
    assert len(ev_list) == 1
    assert ev_list[0].id == evidence_id
    assert ev_list[0].type == EvidenceType.TERMINAL
    assert ev_list[0].target == "localhost:22"
    assert ev_list[0].description == "SSH banner response"
    assert ev_list[0].data == "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    
    # 2. Test log_finding
    finding_res = registry.execute(
        name="log_finding",
        arguments={
            "title": "Outdated SSH Banner",
            "severity": "medium",
            "confidence": "confirmed",
            "affected_asset": "localhost:22",
            "description": "Server reveals software version",
            "impact": "Information disclosure helps attackers customize exploits",
            "verification": "Connect via netcat to port 22",
            "remediation": "Update SSH config to hide banner version",
            "evidence_ids": [evidence_id]
        },
        context=context
    )
    
    assert "Finding logged successfully with ID:" in finding_res
    finding_id = finding_res.split(":")[-1].strip()
    
    # Retrieve finding from DB
    findings = storage.get_findings(session_id)
    assert len(findings) == 1
    assert findings[0].id == finding_id
    assert findings[0].title == "Outdated SSH Banner"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].affected_asset == "localhost:22"
    assert findings[0].evidence == [evidence_id]
