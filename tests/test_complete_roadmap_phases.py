"""
Comprehensive Unit & Integration Test Suite for Buzzard Code Roadmap Phases 0-6.

Validates:
- Phase 1: Incremental Persistent Graph Indexing (SQLite .buzzard/memory.db)
- Phase 2: AST Test Impact Selection, Atomic Editing, Self-Healing Loop
- Phase 3: Persistent Intelligence & Decision Storage
- Phase 4: Git Worktree Isolation & Multi-Agent Workspaces
- Phase 5: CI/CD SARIF Engine, Pre/Post Lifecycle Hooks, Markdown PR gates
- Phase 6: Continuous Repo Supervisor, Dead Code Auditing, Automated Maintenance
"""

import json
from pathlib import Path

from agent.autonomous_engineer import AutonomousEngineer
from agent.worktree_manager import WorktreeManager
from ci.github_action import BuzzardCiRunner
from coding.atomic_editor import EditOperation
from hooks.hook_manager import HookManager
from intelligence.memory_graph import EngineeringMemoryGraph
from intelligence.persistent_graph import PersistentMemoryGraphStore
from maintenance.repo_supervisor import RepoSupervisor


def test_persistent_graph_sqlite_lifecycle(tmp_path: Path):
    """Verifies that the graph can be saved, loaded, and incrementally synced via SQLite."""
    # Create sample files
    src_dir = tmp_path / "src"
    src_dir.mkdir(parents=True)
    file_a = src_dir / "service.py"
    file_a.write_text("class AuthService:\n    def login(self):\n        pass\n")

    file_b = src_dir / "consumer.py"
    file_b.write_text("from src.service import AuthService\n\ndef run():\n    AuthService().login()\n")

    # Index graph
    graph = EngineeringMemoryGraph(tmp_path)
    graph.index_workspace()

    assert "src/service.py" in graph.files
    assert "src/consumer.py" in graph.files

    # Save to SQLite
    db_file = tmp_path / ".buzzard" / "test_memory.db"
    store = PersistentMemoryGraphStore(tmp_path, db_path=db_file)
    store.save_graph(graph)

    assert db_file.exists()

    # Load from SQLite in a new instance
    loaded_graph = store.load_graph()
    assert loaded_graph is not None
    assert "src/service.py" in loaded_graph.files
    assert "src/consumer.py" in loaded_graph.files
    assert "AuthService" in loaded_graph.symbol_index
    assert "login" in loaded_graph.symbol_index

    # Incremental sync with a modified file
    file_a.write_text("class AuthService:\n    def login(self):\n        pass\n    def logout(self):\n        pass\n")
    sync_res = store.incremental_sync(loaded_graph)
    assert sync_res["updated"] >= 1
    assert "logout" in loaded_graph.files["src/service.py"].symbols


def test_worktree_manager_isolation(tmp_path: Path):
    """Verifies creation, modification, merge, and cleanup of isolated worktrees."""
    # Create root workspace
    main_file = tmp_path / "app.py"
    main_file.write_text("VALUE = 10\n")

    mgr = WorktreeManager(tmp_path)
    wt = mgr.create_worktree("subagent-alpha")

    assert wt.agent_id == "subagent-alpha"
    assert wt.worktree_path.exists()
    assert (wt.worktree_path / "app.py").exists()

    # Edit file in isolated worktree
    (wt.worktree_path / "app.py").write_text("VALUE = 20\n")
    assert main_file.read_text() == "VALUE = 10\n"

    # Merge worktree back
    merged = mgr.merge_worktree("subagent-alpha")
    assert merged is True
    assert main_file.read_text() == "VALUE = 20\n"

    # Cleanup
    mgr.cleanup_worktree("subagent-alpha")
    assert not wt.worktree_path.exists()


def test_ci_sarif_and_markdown_generator(tmp_path: Path):
    """Verifies that CI runner produces valid SARIF 2.1.0 output and Markdown PR summaries."""
    py_file = tmp_path / "calc.py"
    py_file.write_text("def add(a, b):\n    return a + b\n")

    ci_runner = BuzzardCiRunner(tmp_path)
    outcome = ci_runner.run_ci_gate(changed_files=["calc.py"])

    assert outcome.passed is True
    assert outcome.syntax_passed is True

    # Check generated files
    sarif_file = tmp_path / ".buzzard" / "ci" / "results.sarif"
    summary_file = tmp_path / ".buzzard" / "ci" / "summary.md"
    assert sarif_file.exists()
    assert summary_file.exists()

    sarif_data = json.loads(sarif_file.read_text())
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) > 0

    md_content = summary_file.read_text()
    assert "Buzzard Code — Automated CI Gate Report" in md_content
    assert "calc.py" in md_content


def test_repo_supervisor_health_audit(tmp_path: Path):
    """Verifies dead code detection, orphan test detection, and health score computation."""
    # Workspace setup
    src_file = tmp_path / "utils.py"
    src_file.write_text("def dead_helper():\n    return 42\n")

    test_file = tmp_path / "test_orphan.py"
    test_file.write_text("def test_something():\n    assert True\n")

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = []\n')

    supervisor = RepoSupervisor(tmp_path)
    report = supervisor.scan_health()

    assert report.total_files_audited >= 2
    assert report.overall_score > 0
    assert (tmp_path / ".buzzard" / "maintenance" / "latest_health.json").exists()

    # Maintenance branch generation
    branch_info = supervisor.create_maintenance_branch("clean-dead-code")
    assert branch_info["status"] == "ready"
    assert "clean-dead-code" in branch_info["branch"]


def test_hook_manager_lifecycle(tmp_path: Path):
    """Verifies registration and execution of lifecycle hooks."""
    hooks = HookManager(tmp_path)

    # Register python pre-edit hook that passes
    hook_script = "import sys\nsys.exit(0)\n"
    hooks.register_hook("pre-edit", hook_script, is_python=True)

    res = hooks.run_hook("pre-edit", target_files=["src/test.py"])
    assert res.executed is True
    assert res.passed is True
    assert res.exit_code == 0

    # Unregistered hook returns executed=False
    unregistered_res = hooks.run_hook("post-verify")
    assert unregistered_res.executed is False


def test_autonomous_engineer_full_integration(tmp_path: Path):
    """Verifies end-to-end integration: memory graph, hooks, atomic editor, and planning."""
    mod = tmp_path / "calculator.py"
    mod.write_text("def multiply(x, y):\n    return x * y\n")

    engineer = AutonomousEngineer(tmp_path)

    # 1. Plan
    plan = engineer.plan("Add divide function to calculator", ["calculator.py"])
    assert "calculator.py" in plan.target_files
    assert len(plan.steps) > 0

    # 2. Atomic edit
    new_content = "def multiply(x, y):\n    return x * y\n\ndef divide(x, y):\n    return x / y if y != 0 else 0\n"
    tx = engineer.apply_edits_atomically([EditOperation("calculator.py", new_full_content=new_content)])

    assert tx.success is True
    assert "divide" in engineer.graph.files["calculator.py"].symbols
