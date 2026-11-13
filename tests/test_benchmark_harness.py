"""Tests for manifest validation, isolated workspaces, scoring, and run records."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import types
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.common import BenchmarkError, RuntimeClient, _load_manifest, _prepare_checkout, _run_verifier, run_benchmark
from benchmarks.swe_bench.export_manifest import main as export_swe_manifest


def make_git_repo(path: Path) -> str:
    path.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Benchmark test"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "benchmark@test.local"], cwd=path, check=True)
    (path / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    subprocess.run(["git", "add", "calc.py"], cwd=path, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=path, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


def test_manifest_requires_valid_task_and_terminal_verifier(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    revision = make_git_repo(repo)
    manifest = tmp_path / "tasks.jsonl"
    manifest.write_text(
        json.dumps({"task_id": "one", "repo": str(repo), "revision": revision, "goal": "fix it"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkError, match="verifier_command is required"):
        _load_manifest(manifest, "terminal_bench")

    task = {"task_id": "one", "repo": str(repo), "revision": revision, "goal": "fix it", "verifier_command": ["python", "-m", "pytest"]}
    manifest.write_text(json.dumps(task) + "\n", encoding="utf-8")
    assert _load_manifest(manifest, "terminal_bench") == [task]


def test_manifest_rejects_remote_credentials_and_injection_shaped_commands(tmp_path: Path) -> None:
    manifest = tmp_path / "tasks.jsonl"
    manifest.write_text(
        json.dumps({
            "task_id": "one", "repo": "https://user:password@example.com/repo.git",
            "goal": "fix it", "test_command": ["python", "-m", "pytest"],
        }) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkError, match="without credentials"):
        _load_manifest(manifest, "swe_bench")

    manifest.write_text(
        json.dumps({
            "task_id": "one", "repo": str(tmp_path), "goal": "fix it",
            "test_command": "pytest; remove-files",
        }) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(BenchmarkError, match="array of argument strings"):
        _load_manifest(manifest, "swe_bench")


def test_checkout_is_independent_and_verifier_records_result(tmp_path: Path) -> None:
    source = tmp_path / "source"
    revision = make_git_repo(source)
    workspace = tmp_path / "workspace"
    assert _prepare_checkout(str(source), revision, workspace) == revision
    (workspace / "calc.py").write_text("changed\n", encoding="utf-8")
    assert "return a - b" in (source / "calc.py").read_text(encoding="utf-8")

    result = _run_verifier([sys.executable, "-c", "print('verified')"], workspace, 5)
    assert result is not None and result["passed"] is True
    assert result["stdout"].strip() == "verified"


def test_benchmark_run_records_metrics_evidence_patch_and_verifier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    revision = make_git_repo(source)
    manifest = tmp_path / "tasks.jsonl"
    manifest.write_text(
        json.dumps({
            "task_id": "smoke-1", "repo": str(source), "revision": revision,
            "goal": "Fix addition", "test_command": [sys.executable, "-c", "print('pass')"],
        }) + "\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "run-output"

    class FakeRuntimeClient:
        server_info = {
            "model": "test-provider/test-model", "provider": "TestProvider",
            "settings": {"maxIterations": 12},
        }

        def __init__(self, workspace: Path, timeout_seconds: int) -> None:
            self.workspace = workspace

        def run_task(self, goal, approve):
            assert goal == "Fix addition"
            assert approve({"tool": "file_edit"}) is True
            (self.workspace / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            (self.workspace / "new_module.py").write_text("VALUE = 1\n", encoding="utf-8")
            return {
                "status": "completed", "runId": "task-123", "finalAnswer": "Fixed",
                "evidenceReport": "Tests pass", "metrics": {
                    "turns": 4, "modelCalls": 3, "inputCount": 120,
                    "outputCount": 60, "countsEstimated": False,
                    "elapsedSeconds": 1.25, "costUsd": None,
                },
            }

        def close(self):
            pass

    monkeypatch.setattr("benchmarks.common.RuntimeClient", FakeRuntimeClient)
    result = run_benchmark(
        "swe_bench",
        ["--manifest", str(manifest), "--output-dir", str(output_dir), "--auto-approve"],
    )
    assert result == 0
    run = json.loads((output_dir / "run.json").read_text(encoding="utf-8"))
    recorded = run["tasks"][0]
    assert recorded["model"] == "test-provider/test-model"
    assert recorded["model_provider"] == "TestProvider"
    assert recorded["runtime_settings"]["maxIterations"] == 12
    assert recorded["turns"] == 4 and recorded["model_calls"] == 3
    assert recorded["input_tokens"] == 120 and recorded["cost_usd"] is None
    assert recorded["evidence_report"] == "Tests pass"
    assert "return a + b" in recorded["patch"]
    assert "new_module.py" in recorded["patch"] and "VALUE = 1" in recorded["patch"]
    assert recorded["verifier"]["passed"] is True
    prediction = json.loads((output_dir / "predictions.jsonl").read_text(encoding="utf-8"))
    assert prediction["instance_id"] == "smoke-1" and "return a + b" in prediction["patch"]


def test_benchmark_cli_rejects_unknown_task_selection(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    revision = make_git_repo(repo)
    manifest = tmp_path / "tasks.jsonl"
    manifest.write_text(
        json.dumps({"task_id": "known", "repo": str(repo), "revision": revision, "goal": "fix it"}) + "\n",
        encoding="utf-8",
    )
    assert run_benchmark("swe_bench", ["--manifest", str(manifest), "--task-id", "missing"], output_stream=sys.stdout) == 2


def test_runtime_client_preserves_notifications_arriving_before_rpc_response(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RuntimeClient.__new__(RuntimeClient)
    client.pending_messages = []
    client.messages = queue.Queue()
    client._request_id = 0
    client.timeout_seconds = 1
    client.process = SimpleNamespace(poll=lambda: None)

    def send(_message):
        client.messages.put({"jsonrpc": "2.0", "method": "run/finished", "params": {"status": "completed"}})
        client.messages.put({"jsonrpc": "2.0", "id": 1, "result": {"accepted": True}})

    monkeypatch.setattr(client, "_send", send)
    assert client._request("approval/respond", {}) == {"accepted": True}
    assert client._next_message(time.monotonic() + 1)["method"] == "run/finished"


def test_swe_exporter_records_the_pinned_revision_and_task_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    revision = "a" * 40
    rows = [
        {"instance_id": "sympy__sympy-1", "repo": "sympy/sympy", "base_commit": "b" * 40,
         "problem_statement": "Fix the issue."},
        {"instance_id": "sympy__sympy-2", "repo": "sympy/sympy", "base_commit": "c" * 40,
         "problem_statement": "Fix another issue."},
    ]
    observed = {}

    def fake_load_dataset(dataset: str, split: str, revision: str):
        observed.update(dataset=dataset, split=split, revision=revision)
        return rows

    monkeypatch.setitem(sys.modules, "datasets", types.SimpleNamespace(load_dataset=fake_load_dataset))
    manifest_path = tmp_path / "manifest.jsonl"
    monkeypatch.setattr(
        sys, "argv",
        ["export_manifest", "--revision", revision, "--limit", "1", "--output", str(manifest_path)],
    )

    assert export_swe_manifest() == 0
    exported = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert observed == {
        "dataset": "princeton-nlp/SWE-bench_Verified", "split": "test", "revision": revision,
    }
    assert exported["task_id"] == "sympy__sympy-1"
    assert exported["repo"] == "https://github.com/sympy/sympy.git"
    assert exported["revision"] == "b" * 40
    assert exported["dataset_revision"] == revision
