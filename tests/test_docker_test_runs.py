"""Tests for running the completion gate's tests in Docker."""

import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from verification import coding_verifier, docker_tests
from verification.coding_verifier import CodingVerifier
from verification.docker_tests import (
    IsolationConfigError,
    container_command,
    resolve_isolation,
    run_tests_in_docker,
)
from verification.evidence_report import build_evidence_report


def test_resolve_defaults_and_validation():
    host = resolve_isolation({}, "pytest")
    assert host.mode == "host" and host.image == "python:3.12-slim" and host.network == "none"
    with_setup = resolve_isolation({"test_isolation": "docker", "test_setup": "pip install -e ."}, "pytest")
    assert with_setup.network == "bridge"
    for bad in (
        {"test_isolation": "vm"},
        {"test_isolation": "docker", "test_image": "--privileged"},
        {"test_isolation": "docker", "test_image": "a b"},
        {"test_isolation": "docker", "test_network": "host"},
        {"test_isolation": "docker", "test_setup": ""},
    ):
        with pytest.raises(IsolationConfigError):
            resolve_isolation(bad, "pytest")
    with pytest.raises(IsolationConfigError):
        resolve_isolation({"test_isolation": "docker"}, None)


def test_container_command_replaces_host_virtualenv_only_for_detected_runners():
    assert container_command("pytest", ".venv/Scripts/python.exe -m pytest -q", False) == "python -m pytest -q"
    assert container_command("pytest", "pytest -x tests", True) == "pytest -x tests"
    assert container_command("npm", "npm test", False) == "npm test"


def test_docker_run_is_locked_down_and_uses_a_copy(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "marker").write_text("host venv", encoding="utf-8")
    seen = {}

    def fake_run(command, **kwargs):
        if command[:2] == ["docker", "run"]:
            mount = command[command.index("-v") + 1].rsplit(":/workspace", 1)[0]
            seen["command"] = command
            seen["copied"] = sorted(p.name for p in __import__("pathlib").Path(mount).iterdir())
            (__import__("pathlib").Path(mount) / "app.py").write_text("tampered\n", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="1 passed", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_tests.subprocess, "run", fake_run)
    isolation = resolve_isolation({"test_isolation": "docker"}, "pytest")
    result = run_tests_in_docker(tmp_path, "python -m pytest -q", isolation, timeout=30)
    command = seen["command"]
    assert result["exit_code"] == 0 and result["sandbox_image"] == "python:3.12-slim"
    for flag in ("--cap-drop", "--security-opt", "--memory", "--pids-limit"):
        assert flag in command
    assert command[command.index("--network") + 1] == "none"
    assert command[-3:] == ["sh", "-c", "python -m pytest -q"]
    assert seen["copied"] == ["app.py"]
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "x = 1\n"


def test_docker_timeout_removes_container(tmp_path, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command[:3])
        if command[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(command, 5)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(docker_tests.subprocess, "run", fake_run)
    result = run_tests_in_docker(tmp_path, "pytest", resolve_isolation({"test_isolation": "docker"}, "pytest"), timeout=5)
    assert result["exit_code"] == 124 and "timed out" in result["stderr"]
    assert ["docker", "rm", "-f"] in calls


def _project(tmp_path, settings):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".buzzard").mkdir()
    (tmp_path / ".buzzard" / "project.json").write_text(json.dumps(settings), encoding="utf-8")
    return tmp_path


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_gate_requires_docker_when_configured_and_never_falls_back(tmp_path, monkeypatch):
    _project(tmp_path, {"test_isolation": "docker"})
    monkeypatch.setattr(coding_verifier, "docker_available", lambda: False)
    host_calls = []
    verifier = CodingVerifier(workspace=str(tmp_path))
    monkeypatch.setattr(verifier.sandbox, "execute", lambda *a, **k: host_calls.append(a) or {"exit_code": 0})
    result = verifier.verify_task("fix the bug")
    assert not result.passed and "Docker is not reachable" in result.message
    assert host_calls == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_gate_runs_in_docker_and_reports_environment(tmp_path, monkeypatch):
    _project(tmp_path, {"test_isolation": "auto", "test_setup": "pip install pytest"})
    monkeypatch.setattr(coding_verifier, "docker_available", lambda: True)
    approved = []
    captured = {}

    def fake_docker(workspace, command, isolation, timeout):
        captured.update(command=command, isolation=isolation)
        return {"exit_code": 0, "stdout": "1 passed", "stderr": ""}

    monkeypatch.setattr(coding_verifier, "run_tests_in_docker", fake_docker)
    verifier = CodingVerifier(workspace=str(tmp_path), command_approver=lambda c: approved.append(c) or True)
    result = verifier.verify_task("fix the bug")
    assert result.passed, result.message
    assert approved[0] == "pip install pytest && python -m pytest -q"
    assert captured["command"] == "python -m pytest -q" and captured["isolation"].network == "bridge"
    assert result.test_environment.startswith("Docker image python:3.12-slim")
    report = build_evidence_report(result, str(tmp_path), approved=1, denied=0)
    assert "✓ Test environment: Docker image python:3.12-slim" in report


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_gate_auto_falls_back_to_host_and_says_so(tmp_path, monkeypatch):
    _project(tmp_path, {"test_isolation": "auto"})
    monkeypatch.setattr(coding_verifier, "docker_available", lambda: False)
    verifier = CodingVerifier(workspace=str(tmp_path))
    monkeypatch.setattr(verifier.sandbox, "execute", lambda *a, **k: {"exit_code": 0, "stdout": "ok", "stderr": ""})
    result = verifier.verify_task("fix the bug")
    assert result.passed and result.test_environment == "host (Docker not reachable)"
    assert "⚠ Test environment: host (Docker not reachable)" in build_evidence_report(result, str(tmp_path), 0, 0)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_gate_rejects_invalid_isolation_settings(tmp_path):
    _project(tmp_path, {"test_isolation": "sometimes"})
    result = CodingVerifier(workspace=str(tmp_path)).verify_task("fix the bug")
    assert not result.passed and "Invalid test isolation settings" in result.message


@pytest.mark.skipif(not docker_tests.docker_available(), reason="Docker is not running")
def test_real_container_cannot_change_workspace(tmp_path):
    (tmp_path / "keep.txt").write_text("original", encoding="utf-8")
    isolation = resolve_isolation({"test_isolation": "docker", "test_image": "alpine:3.20"}, None)
    result = run_tests_in_docker(tmp_path, "echo changed > keep.txt && cat keep.txt", isolation, timeout=120)
    assert result["exit_code"] == 0 and "changed" in result["stdout"]
    assert (tmp_path / "keep.txt").read_text(encoding="utf-8") == "original"
