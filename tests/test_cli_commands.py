import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
import storage.db
from storage.db import StorageManager
from model.schemas import Finding, Evidence, Severity, Confidence, EvidenceType, TaskStatus
from cli.commands import list_tasks, get_task_status, resume_task, generate_report

@pytest.fixture(autouse=True)
def setup_test_db(temp_db):
    """
    Redirects the default database file to a temporary one for testing.
    """
    old_default = storage.db.DEFAULT_DB_FILE
    storage.db.DEFAULT_DB_FILE = Path(temp_db)
    yield
    storage.db.DEFAULT_DB_FILE = old_default

def test_list_tasks_empty():
    """
    Verifies list_tasks prints message when no tasks exist.
    """
    with patch("cli.renderer.console.print") as mock_print:
        list_tasks()
        mock_print.assert_any_call("[bold cyan]No tasks recorded yet.[/bold cyan]")

def test_list_tasks_with_data():
    """
    Verifies list_tasks prints table when tasks exist.
    """
    storage = StorageManager()
    session_id = "test-session-list"
    storage.create_session(session_id, "localhost", ["localhost"], "Test Goal")
    
    with patch("cli.renderer.console.print") as mock_print:
        list_tasks()
        # Verify that print was called with rich Table object
        args, kwargs = mock_print.call_args
        table = args[0]
        assert table.title == "BUZZARD CODE AUDIT TASKS"
        # Check rows
        row_values = [list(table.columns[i].cells) for i in range(len(table.columns))]
        assert session_id in row_values[0]

def test_get_task_status():
    """
    Verifies get_task_status displays info and progress.
    """
    storage = StorageManager()
    session_id = "test-session-status"
    storage.create_session(session_id, "localhost", ["localhost"], "Test Status Goal")
    storage.save_plan(session_id, ["Step 1", "Step 2"], current_index=0)
    
    with patch("cli.renderer.console.print") as mock_print:
        get_task_status(session_id)
        # Verify it printed the status panel
        found_panel = False
        for call in mock_print.call_args_list:
            args, kwargs = call
            if args and hasattr(args[0], "title") and "TASK STATUS" in str(args[0].title):
                found_panel = True
                break
        assert found_panel

def test_generate_report(tmp_path):
    """
    Verifies generate_report generates a correct markdown file.
    """
    storage = StorageManager()
    session_id = "test-session-report"
    storage.create_session(session_id, "localhost", ["localhost"], "Test Report Goal")
    
    # Add a finding
    finding = Finding(
        id="F01",
        title="SQL Injection",
        description="A SQL injection vulnerability exists in parameter ID.",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        affected_asset="localhost",
        impact="Data exfiltration",
        verification="Run sqlmap",
        remediation="Use parameterized queries",
        status="active"
    )
    storage.add_finding(session_id, finding)
    
    # Add evidence
    evidence = Evidence(
        id="E01",
        type=EvidenceType.SCREENSHOT,
        target="localhost/page",
        description="Screenshot showing error page",
        data="mock_base64_data",
        timestamp="2026-08-16T12:00:00"
    )
    storage.add_evidence(session_id, evidence)
    
    # Set status
    storage.update_session_status(session_id, TaskStatus.COMPLETED)
    
    # Patch Path to save in tmp_path
    with patch("cli.commands.Path") as mock_path:
        mock_path.return_value = tmp_path
        mock_path.side_path = tmp_path
        
        # Run report generation
        # We specify the db_path to be sure it reads the correct db
        report_path_str = generate_report(session_id, db_path=storage.db_path)
        assert os.path.exists(report_path_str)
        
        with open(report_path_str, "r") as f:
            content = f.read()
            assert "# Security Assessment Report" in content
            assert "SQL Injection" in content
            assert "HIGH" in content
            assert "SCREENSHOT" in content

@patch("model.ollama.OllamaProvider.is_available", return_value=True)
@patch("agent.loop.AgentLoop.run")
def test_resume_task(mock_run, mock_available):
    """
    Verifies resume_task correctly initializes the loop and calls run.
    """
    storage = StorageManager()
    session_id = "test-session-resume"
    storage.create_session(session_id, "localhost", ["localhost"], "Test Resume Goal")
    storage.save_plan(session_id, ["Step 1", "Step 2"], current_index=0)
    
    # Run resume
    resume_task(session_id)
    
    # Assert run was called with correct goal, target, and scope
    mock_run.assert_called_once_with(
        task_goal="Test Resume Goal",
        target="localhost",
        scope=["localhost"],
        session_id=session_id
    )

@patch("cli.commands.OllamaProvider")
@patch("cli.commands.subprocess.run")
@patch("cli.commands.shutil.which")
@patch("cli.commands.render_doctor")
def test_run_doctor(mock_render, mock_which, mock_run, mock_ollama_prov):
    """
    Verifies run_doctor performs all diagnostic checks and calls render_doctor.
    """
    # Mock OllamaProvider
    mock_prov_instance = MagicMock()
    mock_prov_instance.is_available.return_value = True
    mock_prov_instance.get_available_models.return_value = ["qwen3.6:27b-uncensored"]
    mock_ollama_prov.return_value = mock_prov_instance

    # Mock shutil.which
    mock_which.side_effect = lambda x: "/usr/bin/" + x

    # Mock subprocess.run
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_run.return_value = mock_res

    from cli.commands import run_doctor
    run_doctor()

    mock_render.assert_called_once()
    args, kwargs = mock_render.call_args
    checks = args[0]
    
    assert checks["Ollama reachable"][0] is True
    assert checks["Docker CLI installed"][0] is True
    assert checks["Tool registry populated"][0] is True
    assert checks["Tool schemas valid"][0] is True
    assert checks["Event emitter active"][0] is True
