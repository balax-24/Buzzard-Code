"""Tests for the LSP client and tools against a scripted language server process."""

import json
import sys
from pathlib import Path

import pytest

from intelligence import lsp_client
from intelligence.lsp_client import LspError, LspManager, server_command
from tools import lsp_tools
from tools.filesystem import set_active_workspace

FAKE_SERVER = r'''
import json, sys, time
mode = sys.argv[1]
out = sys.stdout.buffer

def send(message):
    body = json.dumps(message).encode()
    out.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    out.flush()

def read():
    length = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            sys.exit(0)
        if not line.strip():
            break
        if line.lower().startswith(b"content-length"):
            length = int(line.split(b":")[1])
    return json.loads(sys.stdin.buffer.read(length))

opened = {}
while True:
    message = read()
    method = message.get("method")
    if method == "initialize":
        caps = {"definitionProvider": True, "referencesProvider": True}
        if mode == "pull":
            caps["diagnosticProvider"] = {"interFileDependencies": False, "workspaceDiagnostics": False}
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"capabilities": caps}})
    elif method == "initialized":
        # A server request the client must answer before work continues
        send({"jsonrpc": "2.0", "id": 900, "method": "workspace/configuration", "params": {"items": [{"section": "x"}]}})
    elif method in ("textDocument/didOpen", "textDocument/didChange"):
        uri = message["params"]["textDocument"]["uri"]
        text = message["params"]["textDocument"].get("text") or message["params"]["contentChanges"][0]["text"]
        opened[uri] = text
        if mode == "push":
            problems = [] if "fixed" in text else [{"range": {"start": {"line": 2, "character": 4}, "end": {"line": 2, "character": 9}},
                                                     "severity": 1, "message": "Type mismatch\nmore detail"}]
            send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": {"uri": uri, "diagnostics": problems}})
    elif method == "textDocument/definition":
        if mode == "hang":
            continue
        uri = message["params"]["textDocument"]["uri"].replace("app.py", "lib.py")
        send({"jsonrpc": "2.0", "id": message["id"], "result": [{"uri": uri, "range": {"start": {"line": 0, "character": 4}, "end": {"line": 0, "character": 9}}}]})
    elif method == "textDocument/references":
        uri = message["params"]["textDocument"]["uri"]
        send({"jsonrpc": "2.0", "id": message["id"], "result": [
            {"uri": uri, "range": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 5}}}]})
    elif method == "textDocument/diagnostic":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"kind": "full", "items": [
            {"range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}, "severity": 2, "message": "pulled"}]}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": message["id"], "result": None})
    elif method == "exit":
        sys.exit(0)
    elif "id" in message and "method" not in message:
        assert message["id"] == 900 and message["result"] == [None]
'''


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    (root / "lib.py").write_text("def price(x):\n    return x\n", encoding="utf-8")
    (root / "app.py").write_text("from lib import price\n\nTOTAL = price(3)\n", encoding="utf-8")
    server = tmp_path / "fake_server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    set_active_workspace(str(root))
    managers = []

    def use(mode):
        config = tmp_path / f"lsp-{mode}.json"
        config.write_text(json.dumps({"servers": {"python": {"command": [sys.executable, str(server), mode]}}}), encoding="utf-8")
        monkeypatch.setenv("BUZZARD_LSP_CONFIG", str(config))
        manager = LspManager()
        managers.append(manager)
        monkeypatch.setattr(lsp_client, "_manager", manager)
        monkeypatch.setattr(lsp_tools, "get_lsp_manager", lambda: manager)
        return manager

    yield root, use
    for manager in managers:
        manager.shutdown()
    set_active_workspace(None)


def test_definition_and_references_are_relative_and_one_based(project):
    root, use = project
    use("push")
    assert lsp_tools.lsp_definition("app.py", 3, 9) == "lib.py:1:5: def price(x):"
    references = lsp_tools.lsp_references("app.py", 3, 9)
    assert references.startswith("1 reference(s):") and "app.py:3:1: TOTAL = price(3)" in references


def test_pushed_diagnostics_follow_file_changes(project):
    root, use = project
    use("push")
    first = lsp_tools.lsp_diagnostics("app.py")
    assert first == "1 problem(s):\napp.py:3:5: error: Type mismatch"
    (root / "app.py").write_text("# fixed\nfrom lib import price\nTOTAL = price(3)\n", encoding="utf-8")
    assert lsp_tools.lsp_diagnostics("app.py") == "No problems reported in app.py."


def test_pulled_diagnostics(project):
    _, use = project
    use("pull")
    assert lsp_tools.lsp_diagnostics("app.py") == "1 problem(s):\napp.py:1:1: warning: pulled"


def test_hanging_server_is_dropped_and_index_is_suggested(project, monkeypatch):
    _, use = project
    manager = use("hang")
    monkeypatch.setattr(lsp_client, "REQUEST_TIMEOUT_SECONDS", 1.0)
    first = lsp_tools.lsp_definition("app.py", 3, 9)
    assert "did not answer" in first and "code_symbols" in first
    second = lsp_tools.lsp_definition("app.py", 3, 9)
    assert "stopped responding" in second


def test_input_validation(project):
    _, use = project
    use("push")
    assert "1-based" in lsp_tools.lsp_definition("app.py", 0, 1)
    assert "whole numbers" in lsp_tools.lsp_definition("app.py", "x", 1)
    assert "not a file" in lsp_tools.lsp_diagnostics("missing.py")
    assert "escapes" in lsp_tools.lsp_definition("../outside.py", 1, 1)
    (project[0] / "README").write_text("hello\n", encoding="utf-8")
    assert "no language server support" in lsp_tools.lsp_definition("README", 1, 1)


def test_no_server_installed_points_to_install_and_index(tmp_path, monkeypatch):
    monkeypatch.setenv("BUZZARD_LSP_CONFIG", str(tmp_path / "none.json"))
    monkeypatch.setattr(lsp_client.shutil, "which", lambda name: None)
    with pytest.raises(LspError, match="no go language server is installed"):
        LspManager().server_for(tmp_path, "main.go")


def test_config_is_validated(tmp_path, monkeypatch):
    config = tmp_path / "lsp.json"
    monkeypatch.setenv("BUZZARD_LSP_CONFIG", str(config))
    config.write_text('{"servers": {"go": {"command": "gopls"}}}', encoding="utf-8")
    with pytest.raises(LspError, match="needs a \"command\" list"):
        server_command("go")
    config.write_text('{"servers": {"go": {"command": ["no-such-server-xyz"]}}}', encoding="utf-8")
    with pytest.raises(LspError, match="was not found"):
        server_command("go")
    config.write_text("{not json", encoding="utf-8")
    with pytest.raises(LspError, match="could not read"):
        server_command("go")


def test_repository_settings_cannot_choose_a_server(tmp_path, monkeypatch):
    """Only the user-level config is read; a project's .buzzard folder is ignored."""
    monkeypatch.setenv("BUZZARD_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("BUZZARD_LSP_CONFIG", raising=False)
    (tmp_path / ".buzzard").mkdir()
    (tmp_path / ".buzzard" / "lsp.json").write_text('{"servers": {"go": {"command": ["evil"]}}}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(lsp_client.shutil, "which", lambda name: None)
    assert server_command("go") is None
