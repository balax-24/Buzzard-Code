"""
Contract tests for `buzzard serve --stdio`, driven only through the protocol.

Each test starts the runtime as a real subprocess and talks JSON-RPC over its stdin and
stdout. A scripted model stands in for the provider so runs are deterministic.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent

HARNESS = r'''
import json, os, sys
sys.path.insert(0, os.environ["BUZZARD_ROOT"])
from runtime.stdio_server import serve_stdio

class ScriptedProvider:
    model_name = "scripted"
    def __init__(self, turns):
        self.turns = list(turns)
    def is_available(self):
        return True
    def capabilities(self):
        return {"native_tools": True}
    def chat(self, messages, tools=None, options=None):
        turn = self.turns.pop(0) if self.turns else {"content": "Done."}
        if turn.get("wait_for_file"):
            import time
            while not os.path.exists(turn["wait_for_file"]):
                time.sleep(0.05)
        return {"message": {"role": "assistant", "content": turn.get("content", ""), "tool_calls": turn.get("tool_calls", [])}, "done": True, "metrics": {}}

turns = json.loads(os.environ["BUZZARD_SCRIPT"])
serve_stdio(provider_factory=lambda config: ScriptedProvider(turns))
'''


def call(name: str, **arguments: Any) -> Dict[str, Any]:
    return {"id": f"call_{name}", "type": "function", "function": {"name": name, "arguments": arguments}}


class Client:
    """Minimal protocol client: sends requests, collects responses and notifications."""

    def __init__(self, command: List[str], env: Dict[str, str], cwd: Path):
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", env=env, cwd=str(cwd),
        )
        self.messages: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.seen: List[Dict[str, Any]] = []
        self._next_id = 0
        self.stderr: List[str] = []
        threading.Thread(target=self._read, daemon=True).start()
        # A full stderr pipe would block the runtime, so it is drained continuously
        threading.Thread(target=lambda: self.stderr.extend(self.process.stderr), daemon=True).start()

    def _read(self) -> None:
        for line in self.process.stdout:
            self.messages.put(json.loads(line))

    def send_raw(self, text: str) -> None:
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 60) -> Dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self.send_raw(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}))
        return self.wait(lambda m: m.get("id") == request_id, timeout)

    def wait(self, predicate: Callable[[Dict[str, Any]], bool], timeout: float = 60) -> Dict[str, Any]:
        for message in self.seen:
            if predicate(message) and not message.get("_consumed"):
                message["_consumed"] = True
                return message
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                message = self.messages.get(timeout=0.1)
            except queue.Empty:
                continue
            self.seen.append(message)
            if predicate(message):
                message["_consumed"] = True
                return message
        raise AssertionError(f"timed out; seen: {[m.get('method') or m.get('id') for m in self.seen]}")

    def notification(self, method: str, timeout: float = 60) -> Dict[str, Any]:
        return self.wait(lambda m: m.get("method") == method, timeout)["params"]

    def close(self) -> int:
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            return self.process.wait(timeout=20)
        finally:
            if self.process.poll() is None:
                self.process.kill()


@pytest.fixture
def project(tmp_path):
    repo = tmp_path / "shop"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    git("init")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@test.local")
    (repo / "pyproject.toml").write_text("[project]\nname = 'shop'\nversion = '0.1.0'\n", encoding="utf-8")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (repo / "test_calc.py").write_text("from calc import add\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-m", "buggy")
    return repo


def start(tmp_path: Path, script: List[Dict[str, Any]]) -> Client:
    harness = tmp_path / "harness.py"
    harness.write_text(HARNESS, encoding="utf-8")
    env = {
        **os.environ,
        "BUZZARD_ROOT": str(ROOT),
        "BUZZARD_SCRIPT": json.dumps(script),
        "BUZZARD_HOME": str(tmp_path / "home"),
        "BUZZARD_MCP_CONFIG": str(tmp_path / "no-mcp.json"),
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "PYTHONIOENCODING": "utf-8",
    }
    return Client([sys.executable, str(harness)], env, tmp_path)


def initialize(client: Client, workspace: Path) -> Dict[str, Any]:
    response = client.request("initialize", {"protocolVersion": "1.0", "workspace": str(workspace), "client": "tests"})
    assert "result" in response, response
    return response["result"]


FIX_SCRIPT = [
    {"tool_calls": [call("file_edit", path="calc.py", old_str="return a - b", new_str="return a + b")]},
    {"content": "Fixed add."},
]


def test_full_fix_through_stdio(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    try:
        info = initialize(client, project)
        assert info["protocolVersion"] == "1.0" and info["model"] == "scripted"
        run_id = client.request("run/start", {"goal": "Fix the bug in calc.py so the tests pass"})["result"]["runId"]
        edit = client.notification("approval/requested")
        assert edit["tool"] == "file_edit" and edit["arguments"]["new_str"] == "return a + b"
        assert client.request("approval/respond", {"requestId": edit["requestId"], "decision": "allow"})["result"]["accepted"]
        tests = client.notification("approval/requested")
        assert tests["tool"] == "terminal.execute" and "pytest" in tests["arguments"]["command"]
        client.request("approval/respond", {"requestId": tests["requestId"], "decision": "allow"})
        evidence = client.notification("run/evidence")
        assert "exit 0" in evidence["report"] and evidence["runId"] == run_id
        finished = client.notification("run/finished")
        assert finished["status"] == "completed" and finished["finalAnswer"] == "Fixed add."
        assert finished["metrics"]["modelCalls"] == 2
        assert finished["metrics"]["turns"] > 0
        assert finished["metrics"]["inputCount"] > 0
        assert finished["metrics"]["countsEstimated"] is True
        assert finished["metrics"]["costUsd"] is None
        assert any(m.get("method") == "tool/started" and m["params"]["tool"] == "file_edit" for m in client.seen)
        assert "return a + b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        assert client.close() == 0


def test_denied_edit_changes_nothing(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py"})
        edit = client.notification("approval/requested")
        client.request("approval/respond", {"requestId": edit["requestId"], "decision": "deny"})
        client.notification("run/finished")
        assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        client.close()


def test_plan_mode_refuses_edits_without_asking(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py", "planMode": True})
        client.notification("run/finished")
        assert not any(m.get("method") == "approval/requested" for m in client.seen)
        assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        client.close()


def test_plan_mode_refuses_multi_edit_without_asking(tmp_path, project):
    script = [{"tool_calls": [call("multi_edit", path="calc.py", edits=[
        {"old_str": "return a - b", "new_str": "return a + b"},
    ])]}]
    client = start(tmp_path, script)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py", "planMode": True})
        client.notification("run/finished")
        assert not any(message.get("method") == "approval/requested" for message in client.seen)
        assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        client.close()


def test_plan_mode_refuses_apply_patch_without_asking(tmp_path, project):
    script = [{"tool_calls": [call("apply_patch", patch=(
        "--- a/calc.py\n+++ b/calc.py\n@@ -2 +2 @@\n-    return a - b\n+    return a + b\n"
    ))]}]
    client = start(tmp_path, script)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py", "planMode": True})
        client.notification("run/finished")
        assert not any(message.get("method") == "approval/requested" for message in client.seen)
        assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        client.close()


def test_cancel_while_waiting_denies_and_finishes(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py"})
        edit = client.notification("approval/requested")
        assert client.request("run/cancel")["result"]["cancelled"] is True
        assert client.notification("run/finished")["status"] == "cancelled"
        late = client.request("approval/respond", {"requestId": edit["requestId"], "decision": "allow"})
        assert "error" in late
        assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")
    finally:
        client.close()


def test_disconnect_while_waiting_denies_and_exits(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    initialize(client, project)
    client.request("run/start", {"goal": "Fix the bug in calc.py"})
    client.notification("approval/requested")
    assert client.close() == 0
    assert "return a - b" in (project / "calc.py").read_text(encoding="utf-8")


def test_one_run_at_a_time_and_approval_answers_are_checked(tmp_path, project):
    client = start(tmp_path, FIX_SCRIPT)
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "Fix the bug in calc.py"})
        edit = client.notification("approval/requested")
        busy = client.request("run/start", {"goal": "Something else"})
        assert busy["error"]["code"] == -32001
        assert "error" in client.request("approval/respond", {"requestId": "approval-unknown", "decision": "allow"})
        assert "error" in client.request("approval/respond", {"requestId": edit["requestId"], "decision": "maybe"})
        assert client.request("approval/respond", {"requestId": edit["requestId"], "decision": "deny"})["result"]["accepted"]
        assert "error" in client.request("approval/respond", {"requestId": edit["requestId"], "decision": "allow"})
        client.notification("run/finished")
    finally:
        client.close()


def test_protocol_errors(tmp_path, project):
    client = start(tmp_path, [])
    try:
        assert client.request("run/start", {"goal": "x"})["error"]["code"] == -32002
        client.send_raw("{not json")
        assert client.wait(lambda m: m.get("error", {}).get("code") == -32700)
        mismatch = client.request("initialize", {"protocolVersion": "2.0", "workspace": str(project)})
        assert mismatch["error"]["code"] == -32602 and "not supported" in mismatch["error"]["message"]
        assert client.request("initialize", {"protocolVersion": "1.0", "workspace": str(project / "missing")})["error"]["code"] == -32602
        initialize(client, project)
        assert "cannot change" in client.request("initialize", {"protocolVersion": "1.0", "workspace": str(tmp_path)})["error"]["message"]
        assert client.request("no/such")["error"]["code"] == -32601
        assert client.request("run/start", {"goal": ""})["error"]["code"] == -32602
        assert client.request("shutdown")["result"]["ok"] is True
    finally:
        assert client.close() == 0


def test_secrets_are_redacted_in_notifications(tmp_path, project):
    client = start(tmp_path, [{"content": "Your key is sk-abcdefghijklmnopqrstuvwx"}])
    try:
        initialize(client, project)
        client.request("run/start", {"goal": "What does calc.py do?"})
        finished = client.notification("run/finished")
        assert "sk-abcdefghijklmnopqrstuvwx" not in json.dumps(client.seen)
        assert "[REDACTED]" in finished["finalAnswer"]
    finally:
        client.close()


def test_memory_and_undo_methods(tmp_path, project):
    client = start(tmp_path, [])
    try:
        initialize(client, project)
        assert client.request("memory/list")["result"] == {"enabled": True, "notes": []}
        assert "off" in client.request("memory/setEnabled", {"enabled": False})["result"]["message"]
        assert client.request("memory/forget", {"number": 1})["error"]["code"] == -32602
        assert "message" in client.request("edit/undo")["result"]
    finally:
        client.close()


def test_real_cli_entry_point_speaks_the_protocol(tmp_path, project):
    env = {**os.environ, "BUZZARD_HOME": str(tmp_path / "home"), "PYTHONIOENCODING": "utf-8"}
    client = Client([sys.executable, "-m", "cli.main", "serve", "--stdio"], env, ROOT)
    try:
        assert client.request("run/start", {"goal": "x"}, timeout=90)["error"]["code"] == -32002
        assert client.request("initialize", {"protocolVersion": "9", "workspace": str(project)})["error"]["code"] == -32602
        assert client.request("shutdown")["result"]["ok"] is True
    finally:
        assert client.close() == 0
