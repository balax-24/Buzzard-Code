"""
Language Server Protocol client for Buzzard Code (roadmap item B1).

Starts a language server per language per workspace over stdio and asks it for definitions,
references and diagnostics, so the agent gets exact answers instead of pattern matches.

Which servers can run:
- The defaults below, when their executable is on PATH.
- Entries in the user-level file ``~/.buzzard/lsp.json`` (or ``BUZZARD_LSP_CONFIG``):
  ``{"servers": {"python": {"command": ["pyright-langserver", "--stdio"]}}}``.
A repository can never choose a server command, because starting one runs a program.

Each request has a timeout; a server that fails or hangs is reported and the caller falls back
to the repository index. Servers are shut down when the process exits.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 30.0
DIAGNOSTICS_WAIT_SECONDS = 20.0
MAX_FILE_BYTES = 2_000_000

LANGUAGES: Dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go", ".rs": "rust", ".java": "java",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
}
LANGUAGE_IDS = {"typescript": "typescript", "javascript": "javascript"}
SERVER_GROUP = {"typescript": "typescript", "javascript": "typescript", "c": "c", "cpp": "c"}

DEFAULT_SERVERS: Dict[str, List[List[str]]] = {
    "python": [["pyright-langserver", "--stdio"], ["basedpyright-langserver", "--stdio"], ["pylsp"]],
    "typescript": [["typescript-language-server", "--stdio"]],
    "go": [["gopls"]],
    "rust": [["rust-analyzer"]],
    "java": [["jdtls"]],
    "c": [["clangd"]],
}
INSTALL_HINTS = {
    "python": "npm install -g pyright",
    "typescript": "npm install -g typescript typescript-language-server",
    "go": "go install golang.org/x/tools/gopls@latest",
    "rust": "rustup component add rust-analyzer",
    "java": "install Eclipse JDT Language Server (jdtls)",
    "c": "install clangd",
}


class LspError(RuntimeError):
    """A server could not start, failed a request or timed out; the message is safe to show."""


def language_for(path: str) -> Optional[str]:
    return LANGUAGES.get(Path(path).suffix.lower())


def path_to_uri(path: Path) -> str:
    return path.resolve().as_uri()


def uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    return Path(url2pathname(unquote(parsed.path)) if os.name == "nt" else unquote(parsed.path))


def _config_path() -> Path:
    override = os.environ.get("BUZZARD_LSP_CONFIG")
    if override:
        return Path(override)
    return Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "lsp.json"


def server_command(group: str) -> Optional[List[str]]:
    """The user's configured command for a language group, else the first default on PATH."""
    try:
        configured = json.loads(_config_path().read_text(encoding="utf-8")).get("servers", {}).get(group)
    except FileNotFoundError:
        configured = None
    except (OSError, ValueError, AttributeError) as error:
        raise LspError(f"could not read {_config_path()}: {error}") from None
    if configured is not None:
        command = configured.get("command") if isinstance(configured, dict) else None
        if not (isinstance(command, list) and command and all(isinstance(part, str) for part in command)):
            raise LspError(f'"{group}" in {_config_path()} needs a "command" list such as ["gopls"]')
        executable = shutil.which(command[0]) or (command[0] if Path(command[0]).is_file() else None)
        if executable is None:
            raise LspError(f"the configured {group} language server '{command[0]}' was not found")
        return [executable, *command[1:]]
    for candidate in DEFAULT_SERVERS.get(group, []):
        executable = shutil.which(candidate[0])
        if executable:
            return [executable, *candidate[1:]]
    return None


class LanguageServer:
    """One running server. Messages use the LSP base protocol (Content-Length framing)."""

    def __init__(self, group: str, command: List[str], root: Path):
        self.group = group
        self.root = root
        self.diagnostics: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self.unresponsive = False
        self._opened: Dict[str, Tuple[int, float, int]] = {}  # uri -> (version, mtime, size)
        self._next_id = 0
        self._pending: Dict[int, "queue.Queue[Dict[str, Any]]"] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._diagnostics_changed = threading.Condition()
        if os.name == "nt" and command[0].lower().endswith((".cmd", ".bat")):
            # npm installs servers as .cmd launchers, which only start through cmd; the arguments
            # come from Buzzard's defaults or the user's config, never from a repository
            command = ["cmd", "/c", *command]
        try:
            self._process = subprocess.Popen(
                command, cwd=str(root), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
            )
        except OSError as error:
            raise LspError(f"could not start the {group} language server: {error}") from None
        threading.Thread(target=self._read_loop, daemon=True).start()
        self.capabilities = self.request("initialize", {
            "processId": os.getpid(),
            "rootUri": path_to_uri(root),
            "workspaceFolders": [{"uri": path_to_uri(root), "name": root.name}],
            "capabilities": {
                "textDocument": {
                    "definition": {"linkSupport": False},
                    "references": {},
                    "publishDiagnostics": {"relatedInformation": False},
                    "diagnostic": {"dynamicRegistration": False},
                    "synchronization": {"didSave": False},
                },
                "workspace": {"configuration": True, "workspaceFolders": True},
            },
            "clientInfo": {"name": "buzzard-code"},
        }, timeout=60).get("capabilities", {})
        self.notify("initialized", {})

    # -- transport -------------------------------------------------------------------------
    def _send(self, message: Dict[str, Any]) -> None:
        body = json.dumps(message).encode("utf-8")
        with self._write_lock:
            try:
                self._process.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
                self._process.stdin.flush()
            except (OSError, ValueError) as error:
                raise LspError(f"the {self.group} language server stopped: {error}") from None

    def _read_loop(self) -> None:
        stream = self._process.stdout
        while True:
            length = None
            while True:
                header = stream.readline()
                if not header:
                    self._fail_pending("the language server exited")
                    return
                header = header.strip()
                if not header:
                    break
                name, _, value = header.decode("ascii", "replace").partition(":")
                if name.lower() == "content-length":
                    length = int(value.strip())
            if length is None:
                continue
            body = stream.read(length)
            try:
                message = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                continue
            self._dispatch(message)

    def _dispatch(self, message: Dict[str, Any]) -> None:
        if "id" in message and "method" not in message:
            waiter = self._pending.pop(message["id"], None)
            if waiter is not None:
                waiter.put(message)
            return
        method = message.get("method")
        if method == "textDocument/publishDiagnostics":
            params = message.get("params", {})
            with self._diagnostics_changed:
                self.diagnostics[params.get("uri", "")] = (time.time(), params.get("diagnostics", []))
                self._diagnostics_changed.notify_all()
            return
        if "id" in message:  # a request from the server: answer conservatively
            if method == "workspace/configuration":
                items = message.get("params", {}).get("items", [])
                result: Any = [None] * len(items)
            elif method == "workspace/workspaceFolders":
                result = [{"uri": path_to_uri(self.root), "name": self.root.name}]
            else:
                result = None
            self._send({"jsonrpc": "2.0", "id": message["id"], "result": result})

    def _fail_pending(self, reason: str) -> None:
        for waiter in list(self._pending.values()):
            waiter.put({"error": {"message": reason}})
        self._pending.clear()

    def request(self, method: str, params: Dict[str, Any], timeout: float = REQUEST_TIMEOUT_SECONDS) -> Any:
        with self._lock:
            self._next_id += 1
            request_id = self._next_id
        waiter: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._pending[request_id] = waiter
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        try:
            response = waiter.get(timeout=timeout)
        except queue.Empty:
            self._pending.pop(request_id, None)
            self.unresponsive = True  # stop using it: every later call would wait just as long
            raise LspError(f"the {self.group} language server did not answer {method} within {timeout:.0f}s") from None
        if "error" in response:
            raise LspError(f"the {self.group} language server failed {method}: {response['error'].get('message', 'unknown error')}")
        return response.get("result")

    def notify(self, method: str, params: Dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    @property
    def alive(self) -> bool:
        return self._process.poll() is None

    # -- documents -------------------------------------------------------------------------
    def sync(self, path: Path) -> str:
        """Opens the file, or sends its new content if it changed on disk. Returns its URI."""
        stat = path.stat()
        if stat.st_size > MAX_FILE_BYTES:
            raise LspError(f"{path.name} is too large for language-server analysis")
        uri = path_to_uri(path)
        known = self._opened.get(uri)
        if known and known[1:] == (stat.st_mtime, stat.st_size):
            return uri
        text = path.read_text(encoding="utf-8", errors="replace")
        language = language_for(str(path)) or "plaintext"
        if known is None:
            self._opened[uri] = (1, stat.st_mtime, stat.st_size)
            self.notify("textDocument/didOpen", {"textDocument": {
                "uri": uri, "languageId": LANGUAGE_IDS.get(language, language), "version": 1, "text": text}})
        else:
            version = known[0] + 1
            self._opened[uri] = (version, stat.st_mtime, stat.st_size)
            self.notify("textDocument/didChange", {
                "textDocument": {"uri": uri, "version": version}, "contentChanges": [{"text": text}]})
        return uri

    def wait_for_diagnostics(self, uri: str, since: float, timeout: float = DIAGNOSTICS_WAIT_SECONDS) -> Optional[List[Dict[str, Any]]]:
        deadline = time.time() + timeout
        with self._diagnostics_changed:
            while True:
                entry = self.diagnostics.get(uri)
                if entry and entry[0] >= since:
                    return entry[1]
                remaining = deadline - time.time()
                if remaining <= 0:
                    return entry[1] if entry else None
                self._diagnostics_changed.wait(remaining)

    def shutdown(self) -> None:
        if not self.alive:
            return
        try:
            self.request("shutdown", {}, timeout=5)
            self.notify("exit", {})
        except LspError:
            pass  # the server is being stopped either way
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()


class LspManager:
    """One server per (workspace, language group), started on first use."""

    def __init__(self) -> None:
        self._servers: Dict[Tuple[str, str], LanguageServer] = {}
        self._failed: Dict[Tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def server_for(self, root: Path, path: str) -> LanguageServer:
        language = language_for(path)
        if language is None:
            raise LspError(f"no language server support for {Path(path).suffix or 'this file type'}")
        group = SERVER_GROUP.get(language, language)
        key = (str(root.resolve()), group)
        with self._lock:
            server = self._servers.get(key)
            if server is not None and server.unresponsive:
                self._failed[key] = f"the {group} language server stopped responding; using the repository index instead"
                del self._servers[key]
                threading.Thread(target=server.shutdown, daemon=True).start()
            elif server is not None and server.alive:
                return server
            if key in self._failed:
                raise LspError(self._failed[key])
            command = server_command(group)
            if command is None:
                raise LspError(
                    f"no {group} language server is installed ({INSTALL_HINTS.get(group, 'install one')}); "
                    "using the repository index instead"
                )
            try:
                server = LanguageServer(group, command, root)
            except LspError as error:
                self._failed[key] = str(error)
                raise
            self._servers[key] = server
            return server

    def shutdown(self) -> None:
        with self._lock:
            servers = list(self._servers.values())
            self._servers.clear()
        for server in servers:
            server.shutdown()


_manager: Optional[LspManager] = None


def get_lsp_manager() -> LspManager:
    global _manager
    if _manager is None:
        _manager = LspManager()
        atexit.register(_manager.shutdown)
    return _manager
