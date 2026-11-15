"""
Unit tests for EngineeringMemoryGraph and ChangeImpactSimulator.
"""

from pathlib import Path
from intelligence.memory_graph import EngineeringMemoryGraph
from coding.impact_simulator import ChangeImpactSimulator


def test_engineering_memory_graph_indexing(tmp_path: Path):
    # Create sample repository layout
    auth_py = tmp_path / "auth.py"
    auth_py.write_text("def generate_token(user_id: str):\n    return f'token-{user_id}'\n", encoding="utf-8")

    api_py = tmp_path / "api.py"
    api_py.write_text("from auth import generate_token\n\ndef login():\n    return generate_token('user1')\n", encoding="utf-8")

    test_auth_py = tmp_path / "test_auth.py"
    test_auth_py.write_text("from auth import generate_token\n\ndef test_token():\n    assert generate_token('1') == 'token-1'\n", encoding="utf-8")

    graph = EngineeringMemoryGraph(tmp_path)
    stats = graph.index_workspace()

    assert stats["total_files"] == 3
    assert stats["total_symbols"] >= 3

    # Check impact radius of auth.py
    impact = graph.get_impact_radius("auth.py")
    assert impact["found"] is True
    assert "api.py" in impact["imported_by"]
    assert "test_auth.py" in impact["associated_tests"]
    assert "generate_token" in impact["symbols"]


def test_change_impact_simulator(tmp_path: Path):
    auth_py = tmp_path / "auth.py"
    auth_py.write_text("def verify_credentials(): pass\n", encoding="utf-8")

    server_py = tmp_path / "server.py"
    server_py.write_text("import auth\n", encoding="utf-8")

    test_auth = tmp_path / "test_auth.py"
    test_auth.write_text("import auth\n", encoding="utf-8")

    simulator = ChangeImpactSimulator(tmp_path)
    pred = simulator.simulate(["auth.py"])

    assert "auth.py" in pred.target_files
    assert "server.py" in pred.affected_files
    assert "test_auth.py" in pred.priority_tests
    assert pred.risk_level in ("medium", "high", "critical")
    assert pred.suggest_checkpoint is True

    summary = pred.format_summary()
    assert "CHANGE IMPACT SIMULATION" in summary
    assert "server.py" in summary
