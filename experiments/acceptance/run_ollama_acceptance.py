"""
Runs the Buzzard Code acceptance scenario against a configured model provider.

Every outcome is checked independently with git and pytest; the agent's own claims
are never treated as evidence. Approvals go through a scripted operator that records
each request and approves it, standing in for a human.

Usage:
    python experiments/acceptance/run_ollama_acceptance.py --provider gemini --model gemini-3.1-flash-lite
Results are written to artifacts/acceptance/.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

from agent.loop import CODING_TOOL_NAMES, AgentLoop
from model.factory import get_model_provider
from storage.db import StorageManager
from tools.filesystem import set_active_workspace

OUTPUT_DIR = Path("artifacts/acceptance")
SCOPE = ["localhost", "127.0.0.1"]

PROJECT_FILES = {
    "pyproject.toml": "[project]\nname = 'shopcart'\nversion = '0.1.0'\n",
    "pricing.py": (
        "def apply_discount(price, percent):\n"
        "    \"\"\"Returns price reduced by percent.\"\"\"\n"
        "    return price * percent / 100\n"
    ),
    "inventory.py": (
        "class Inventory:\n"
        "    def __init__(self):\n"
        "        self.stock = {}\n\n"
        "    def restock(self, sku, quantity):\n"
        "        self.stock[sku] = self.stock.get(sku, 0) + quantity\n"
    ),
    "test_pricing.py": (
        "from pricing import apply_discount\n\n"
        "def test_apply_discount():\n"
        "    assert apply_discount(200, 25) == 150\n"
    ),
    "test_inventory.py": (
        "from inventory import Inventory\n\n"
        "def test_restock_adds_stock():\n"
        "    inventory = Inventory()\n"
        "    inventory.restock('a', 2)\n"
        "    assert inventory.stock['a'] == 2\n"
    ),
}

CONTROLLED_FAILURE_TEST = (
    "\n\ndef test_restock_rejects_negative_quantity():\n"
    "    import pytest\n"
    "    with pytest.raises(ValueError):\n"
    "        Inventory().restock('a', -1)\n"
)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, timeout=30)
    return result.stdout


def run_tests(repo: Path) -> Dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {"exit_code": result.returncode, "tail": result.stdout[-300:]}


def create_project(repo: Path) -> None:
    git(repo, "init")
    git(repo, "config", "user.name", "Acceptance")
    git(repo, "config", "user.email", "acceptance@test.local")
    for name, content in PROJECT_FILES.items():
        (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "Initial project with a deliberate bug")


def run_agent(provider_name: str, model: str, task: str, iterations: int, limit_seconds: int) -> Dict[str, Any]:
    approvals: List[Dict[str, Any]] = []

    def scripted_operator(tool_name: str, arguments: Dict[str, Any], metadata: Any) -> bool:
        approvals.append({"tool": tool_name, "arguments": arguments})
        return True

    stop_event = threading.Event()
    timer = threading.Timer(limit_seconds, stop_event.set)
    timer.start()
    started = time.time()
    try:
        result = AgentLoop(
            provider=get_model_provider(provider_name=provider_name, model_name=model),
            storage_manager=StorageManager(),
            max_iterations=iterations,
            stop_event=stop_event,
            quiet=True,
            approval_callback=scripted_operator,
        ).run(task_goal=task, target="localhost", scope=SCOPE)
    except Exception as e:  # A crash is a recorded acceptance outcome, not a harness failure
        return {"status": "crashed", "error": repr(e), "seconds": round(time.time() - started), "approvals": approvals}
    finally:
        timer.cancel()

    messages = result.get("messages", [])
    assistant_text = [m.get("content") or "" for m in messages if m.get("role") == "assistant"]
    return {
        "status": result.get("status"),
        "error": result.get("error"),
        "session_id": result.get("session_id"),
        "iterations": result.get("iterations"),
        "seconds": round(time.time() - started),
        "approvals": approvals,
        "final_text": next((text for text in reversed(assistant_text) if text.strip()), "")[:1500],
        "assistant_turns": [text[:600] for text in assistant_text],
        "observations": str(result.get("observations"))[:1500],
    }


def check(results: List[Dict[str, Any]], step: str, passed: bool, detail: Any = "") -> None:
    results.append({"step": step, "passed": passed, "detail": detail})
    print(f"[{'PASS' if passed else 'FAIL'}] {step}: {str(detail)[:200]}", flush=True)


def run_scenario(provider_name: str, model: str, repo: Path, iterations: int, limit_seconds: int) -> Dict[str, Any]:
    steps: List[Dict[str, Any]] = []
    runs: Dict[str, Any] = {}

    create_project(repo)
    set_active_workspace(repo)
    check(steps, "1 open disposable project", run_tests(repo)["exit_code"] == 1, "bug present, tests fail")

    runs["explain"] = run_agent(
        provider_name, model, "Explain the architecture of this project repository without changing any files.",
        iterations, limit_seconds,
    )
    text = runs["explain"].get("final_text", "").lower()
    check(steps, "2 explain architecture", "pricing" in text and "inventory" in text, runs["explain"]["status"])
    check(steps, "2b explain left repo unchanged", git(repo, "status", "--porcelain") == "")

    runs["identify"] = run_agent(
        provider_name, model, "Identify the bug behind the failing test in this project. Do not change any files.",
        iterations, limit_seconds,
    )
    text = runs["identify"].get("final_text", "").lower()
    check(steps, "3 identify bug", "apply_discount" in text, runs["identify"]["status"])
    check(steps, "3b identify left repo unchanged", git(repo, "status", "--porcelain") == "")

    runs["fix"] = run_agent(provider_name, model, "Fix the bug in pricing.py so the test suite passes.", iterations, limit_seconds)
    changed = git(repo, "status", "--porcelain").split()
    check(steps, "4 fix created", "pricing.py" in changed, changed)
    check(steps, "5 change is reviewable as a diff", "apply_discount" in git(repo, "diff") or "price" in git(repo, "diff"))
    edit_approvals = [a for a in runs["fix"]["approvals"] if a["tool"] in ("file_edit", "file.edit", "file_write", "file.write")]
    check(steps, "6 edit went through approval", bool(edit_approvals), runs["fix"]["approvals"])
    security_tools_used = [
        a["tool"] for run in runs.values() for a in run["approvals"]
        if a["tool"] not in CODING_TOOL_NAMES and a["tool"] not in ("file.edit", "file.write")
    ]
    check(steps, "6b no security tools on coding tasks", not security_tools_used, security_tools_used)
    tests_after_fix = run_tests(repo)
    check(steps, "7 tests pass independently", tests_after_fix["exit_code"] == 0, tests_after_fix["tail"])
    check(
        steps,
        "7b reported status matches tests",
        (runs["fix"]["status"] == "completed") == (tests_after_fix["exit_code"] == 0),
        runs["fix"]["status"],
    )

    git(repo, "add", ".")
    git(repo, "commit", "--allow-empty", "-m", "Checkpoint after fix")
    with (repo / "test_inventory.py").open("a", encoding="utf-8") as test_file:
        test_file.write(CONTROLLED_FAILURE_TEST)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "Add controlled failing test")
    check(steps, "8 controlled failure introduced", run_tests(repo)["exit_code"] == 1)

    runs["recover"] = run_agent(
        provider_name, model, "The test suite is failing. Fix inventory.py so all tests pass. Do not modify the tests.",
        iterations, limit_seconds,
    )
    tests_after_recovery = run_tests(repo)
    check(steps, "9 recovery fixes the failure", tests_after_recovery["exit_code"] == 0, tests_after_recovery["tail"])
    check(
        steps,
        "9b reported status matches tests",
        (runs["recover"]["status"] == "completed") == (tests_after_recovery["exit_code"] == 0),
        runs["recover"]["status"],
    )
    final_diff = git(repo, "diff")
    tests_changed = "test_" in git(repo, "status", "--porcelain")
    check(steps, "10 git diff inspected, tests untouched", bool(final_diff) and not tests_changed, final_diff[:400])
    check(steps, "11 final result verified", tests_after_recovery["exit_code"] == 0 and not tests_changed)

    sessions = [run.get("session_id") for run in runs.values() if run.get("session_id")]
    audit_present = bool(sessions) and all(
        (Path("assessments") / session / "timeline.jsonl").is_file() for session in sessions
    )
    check(steps, "12 audit records exist", audit_present, sessions)

    return {"provider": provider_name, "model": model, "steps": steps, "runs": runs, "final_diff": final_diff}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", default="ollama", help="Provider name, such as gemini or ollama")
    parser.add_argument("--model", required=True, help="Model name for that provider")
    parser.add_argument("--iterations", type=int, default=12)
    parser.add_argument("--limit-seconds", type=int, default=600, help="Time limit per agent run")
    args = parser.parse_args()

    # The verifier's test command runs `python` from PATH
    os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        report = run_scenario(args.provider, args.model, Path(temp_dir).resolve(), args.iterations, args.limit_seconds)

    passed = sum(step["passed"] for step in report["steps"])
    report["summary"] = f"{passed}/{len(report['steps'])} checks passed"
    output_path = OUTPUT_DIR / f"{args.provider}_{args.model.replace(':', '_').replace('/', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"{report['summary']} -> {output_path}", flush=True)
    return 0 if passed == len(report["steps"]) else 1


if __name__ == "__main__":
    sys.exit(main())
