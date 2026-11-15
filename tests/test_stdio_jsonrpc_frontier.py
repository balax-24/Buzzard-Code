"""
Unit and integration tests for Buzzard Code JSON-RPC Frontier Superpower handlers (Phase 12).
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
import pytest

from runtime.stdio_server import StdioRuntimeServer, RpcError


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        sample_code = """
def calculate_vat(amount: float) -> float:
    if amount < 0:
        raise ValueError("Negative amount")
    return amount * 0.20

def process_bill(user: str, raw_val: float):
    vat = calculate_vat(raw_val)
    return {"user": user, "vat": vat, "total": raw_val + vat}
"""
        (ws / "sample_billing.py").write_text(sample_code, encoding="utf-8")
        yield ws


@pytest.fixture
def rpc_server(temp_workspace):
    in_stream = io.StringIO()
    out_stream = io.StringIO()
    server = StdioRuntimeServer(in_stream, out_stream)
    server.workspace = str(temp_workspace)
    server.session = object()  # mark session as initialized
    return server


def test_rpc_synthesize_and_execute_poc(rpc_server):
    # 1. Synthesize PoC via RPC
    res = rpc_server._dispatch("engineering/synthesizePoc", {
        "issue": "ValueError: Negative amount",
        "targetFile": "sample_billing.py"
    })
    assert "artifactId" in res
    assert res["artifactId"].startswith("repro_")
    art_id = res["artifactId"]

    # 2. Execute PoC via RPC
    exec_res = rpc_server._dispatch("engineering/executePoc", {
        "artifactId": art_id
    })
    assert exec_res["artifactId"] == art_id
    assert exec_res["isFailingExpectedly"] is True


def test_rpc_cpg_query(rpc_server):
    res = rpc_server._dispatch("engineering/cpgQuery", {
        "symbol": "process_bill",
        "direction": "callees",
        "depth": 2
    })
    assert res["symbol"] == "process_bill"
    assert res["direction"] == "callees"
    assert isinstance(res["results"], list)
    callees = [r.get("to") for r in res["results"]]
    assert "calculate_vat" in callees


def test_rpc_bounty_race(rpc_server):
    res = rpc_server._dispatch("engineering/bountyRace", {
        "targetFile": "sample_billing.py",
        "functions": ["calculate_vat"]
    })
    assert "target_file" in res or "targetFile" in res or "attacks_attempted" in res


def test_rpc_checkpoint_lifecycle(rpc_server, temp_workspace):
    # 1. Create checkpoint 1
    c1 = rpc_server._dispatch("checkpoint/create", {
        "stepId": 1,
        "description": "Initial billing code",
        "files": ["sample_billing.py"]
    })
    assert c1["step_id"] == 1

    # Mutate file
    target_f = temp_workspace / "sample_billing.py"
    target_f.write_text("# Corrupted billing\n", encoding="utf-8")

    # 2. Create checkpoint 2
    c2 = rpc_server._dispatch("checkpoint/create", {
        "stepId": 2,
        "description": "Corrupted state",
        "files": ["sample_billing.py"]
    })
    assert c2["step_id"] == 2

    # 3. List checkpoints
    lst = rpc_server._dispatch("checkpoint/list", {})
    assert len(lst["checkpoints"]) == 2

    # 4. Rewind to checkpoint 1
    rew = rpc_server._dispatch("checkpoint/rewind", {"target": 1})
    assert rew["success"] is True
    assert "calculate_vat" in target_f.read_text(encoding="utf-8")


def test_rpc_context_distill(rpc_server):
    res = rpc_server._dispatch("context/distill", {
        "turns": [
            {"role": "user", "content": "Refactor billing system"},
            {"role": "agent", "content": "Ran tests on tests/test_billing.py and passed"},
        ],
        "files": ["sample_billing.py"]
    })
    assert "savingsPercent" in res
    assert "distilledTokens" in res
    assert "prompt" in res
    assert res["savingsPercent"] >= 0.0


def test_rpc_unknown_method_error(rpc_server):
    with pytest.raises(RpcError) as exc_info:
        rpc_server._dispatch("nonexistent/method", {})
    assert exc_info.value.code == -32601
