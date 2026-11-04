"""
Phase 14 Tests: Operation & Entity Idempotency.
Verifies deduplication of evidence, findings, capabilities, graph edges, and operations across turns and crash-restarts.
"""

from persistence.idempotency import IdempotencyManager


def test_operation_idempotency():
    im = IdempotencyManager()
    op_id = IdempotencyManager.generate_operation_id("sess-1", 1, "tool-01", "TOOL_EXECUTION")
    
    assert im.is_operation_completed(op_id) is False
    rec = im.record_operation(
        operation_id=op_id,
        session_id="sess-1",
        turn_id=1,
        tool_call_id="tool-01",
        op_type="TOOL_EXECUTION",
        target="127.0.0.1",
        result_data={"ports": [80, 22]}
    )
    assert rec.operation_id == op_id
    assert im.is_operation_completed(op_id) is True


def test_evidence_and_finding_idempotency():
    im = IdempotencyManager()

    # Evidence
    assert im.is_evidence_duplicate("Port 80 is open", "nmap", "127.0.0.1") is False
    assert im.is_evidence_duplicate("Port 80 is open", "nmap", "127.0.0.1") is True

    # Finding
    assert im.is_finding_duplicate("JWT Auth Bypass", "127.0.0.1:8080", "auth_bypass") is False
    assert im.is_finding_duplicate("JWT Auth Bypass", "127.0.0.1:8080", "auth_bypass") is True


def test_graph_edge_idempotency():
    im = IdempotencyManager()

    assert im.is_edge_duplicate("node-host", "node-service", "DISCOVERED_ON") is False
    assert im.is_edge_duplicate("node-host", "node-service", "DISCOVERED_ON") is True


def test_idempotency_serialization_roundtrip():
    im = IdempotencyManager()
    op_id = IdempotencyManager.generate_operation_id("sess-1", 1, "tool-01", "TOOL_EXECUTION")
    im.record_operation(op_id, "sess-1", 1, "tool-01", "TOOL_EXECUTION", "127.0.0.1", "result")
    im.is_evidence_duplicate("evidence text", "http", "target1")
    im.is_finding_duplicate("Finding title", "target1", "xss")

    data = im.to_dict()
    im_restored = IdempotencyManager.from_dict(data)

    assert im_restored.is_operation_completed(op_id) is True
    assert im_restored.is_evidence_duplicate("evidence text", "http", "target1") is True
    assert im_restored.is_finding_duplicate("Finding title", "target1", "xss") is True
