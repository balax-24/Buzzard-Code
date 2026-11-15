"""
Unit test suite for Buzzard Code Frontier Superpowers (Phases 7 - 12).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from verification.poc_synthesizer import ZeroShotPocSynthesizer
from intelligence.code_property_graph import CodePropertyGraph
from agent.bounty_engine import AdversarialBountyEngine
from runtime.checkpoint_manager import SemanticCheckpointManager
from intelligence.context_distiller import HierarchicalContextDistiller


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        ws = Path(tmpdir)
        # Create a sample python file
        sample_code = """
def calculate_discount(price, rate):
    if rate < 0:
        raise ValueError("Rate cannot be negative")
    return price * (1.0 - rate)

def process_checkout(user_id, total):
    discounted = calculate_discount(total, 0.1)
    return {"user": user_id, "final": discounted}
"""
        (ws / "sample_shop.py").write_text(sample_code, encoding="utf-8")
        yield ws


def test_zero_shot_poc_synthesizer(temp_workspace):
    synth = ZeroShotPocSynthesizer(temp_workspace)
    assert not synth.is_coding_gate_unlocked()

    # Synthesize reproduction
    art = synth.synthesize_reproducer("ZeroDivisionError: division by zero", "sample_shop.py")
    assert art.artifact_id.startswith("repro_")
    assert art.repro_file_path.exists()

    # Execute reproducer -> should fail expectedly
    exec_res = synth.execute_reproducer(art.artifact_id)
    assert exec_res.is_failing_expectedly
    assert synth.is_coding_gate_unlocked(art.artifact_id)

    # Register custom passing reproducer
    pass_code = "import sys\nprint('OK')\nsys.exit(0)\n"
    pass_art = synth.register_custom_reproducer(pass_code)
    pass_res = synth.execute_reproducer(pass_art.artifact_id)
    assert pass_res.is_resolved

    synth.cleanup()


def test_code_property_graph(temp_workspace):
    cpg = CodePropertyGraph(temp_workspace)
    count = cpg.index_workspace()
    assert count >= 1

    # Query symbols
    syms = cpg.query_symbols("calculate_discount")
    assert len(syms) == 1
    assert syms[0].name == "calculate_discount"

    # Query call hierarchy
    hierarchy = cpg.get_call_hierarchy("process_checkout", direction="callees")
    assert len(hierarchy) >= 1
    assert hierarchy[0]["to"] == "calculate_discount"

    # Check taint analysis
    taints = cpg.find_taint_flows()
    assert isinstance(taints, list)


def test_adversarial_bounty_engine(temp_workspace):
    engine = AdversarialBountyEngine(temp_workspace)
    report = engine.run_bounty_challenge("sample_shop.py", ["calculate_discount"], max_rounds=1)
    assert report.attacks_attempted > 0
    assert report.execution_time_ms > 0
    assert isinstance(report.breaches_found, list)


def test_semantic_checkpoint_manager(temp_workspace):
    mgr = SemanticCheckpointManager(temp_workspace)
    target_f = temp_workspace / "sample_shop.py"

    # Checkpoint 1
    c1 = mgr.create_checkpoint(1, "Initial state", ["sample_shop.py"])
    assert c1.step_id == 1

    # Modify file
    target_f.write_text("# Modified line\n", encoding="utf-8")

    # Checkpoint 2
    c2 = mgr.create_checkpoint(2, "Modified state", ["sample_shop.py"])
    assert c2.step_id == 2
    assert len(mgr.list_timeline()) == 2

    # Rewind to step 1
    ok, msg = mgr.rewind_to(1)
    assert ok
    assert "calculate_discount" in target_f.read_text(encoding="utf-8")
    assert len(mgr.list_timeline()) == 1


def test_hierarchical_context_distiller(temp_workspace):
    distiller = HierarchicalContextDistiller(temp_workspace)
    fact = distiller.record_fact("FILE_MODIFIED", "sample_shop.py", "Added calculate_discount", 1)
    assert fact.fact_type == "FILE_MODIFIED"

    raw_turns = [
        {"role": "user", "content": "Please inspect sample_shop.py"},
        {"role": "agent", "content": "Ran tests on tests/test_shop.py and PASSED"},
    ]
    distilled = distiller.distill_turns(raw_turns, ["sample_shop.py"])
    assert len(distilled.causal_facts) >= 1
    assert distilled.savings_percent >= 0.0
    prompt = distilled.format_as_prompt()
    assert "BUZZARD DISTILLED CAUSAL CONTEXT" in prompt
