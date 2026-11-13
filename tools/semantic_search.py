"""
Semantic code search for Buzzard Code (roadmap A3).

``code_search(query)`` finds functions, classes and methods by what they do, not only by name.
Every symbol in the repository index (``code_index``) becomes one chunk: its kind, qualified name
and the first lines of its source. Chunks are embedded and stored in SQLite under
``BUZZARD_HOME/semantic/``; like the index, a file is re-embedded only when its size or mtime
changes. A query is embedded the same way and ranked by cosine similarity, with a bonus when its
words appear in the symbol's name (the name index).

Embedders (setting ``semantic_search.embedder``):

- ``auto`` (default): a local Ollama embedding model when one answers, otherwise ``lexical``.
- ``ollama``: a local Ollama embedding model (``semantic_search.model``, default
  ``nomic-embed-text``, at ``semantic_search.url``, default ``http://127.0.0.1:11434``). Only a
  loopback address is used unless ``semantic_search.allow_remote`` is true, so no code leaves the
  machine unless the user chooses it.
- ``lexical``: a built-in hashed bag of words over identifiers, comments and strings. It needs no
  model, matches words that appear in a function's body or docstring, but does not know synonyms.

Read-only and confined to the workspace boundary.
"""

from __future__ import annotations

import array
import hashlib
import ipaddress
import math
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx

from tools.code_index import (
    CodeIndex, Symbol, _footer, _in_scope, _scope_filter, get_index,
)

DEFAULT_MODEL = "nomic-embed-text"
DEFAULT_URL = "http://127.0.0.1:11434"
LEXICAL_DIMENSIONS = 512
CHUNK_MAX_LINES = 60
CHUNK_MAX_CHARS = 2_000
EMBED_BATCH = 32
EMBED_TIMEOUT_SECONDS = 60.0
NAME_BONUS = 0.15
DEFAULT_LIMIT = 10
MAX_LIMIT = 30

_WORD = re.compile(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])|[a-z]+|\d+")
_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on", "with", "as", "by",
    "we", "do", "does", "where", "what", "how", "which", "that", "this", "be", "are", "self",
    "def", "return", "class", "function", "func", "fn", "const", "let", "var", "import", "from",
    "if", "else", "elif", "not", "none", "true", "false", "null", "new", "pass", "public",
    "private", "static", "void", "int", "str", "string",
})


class EmbeddingError(RuntimeError):
    """The configured embedding model could not embed the text."""


def _words(text: str) -> List[str]:
    """Lower-case word stems from identifiers and prose (snake_case and camelCase split)."""
    stems = []
    for raw in _WORD.findall(text):
        word = raw.lower()
        if len(word) < 2 or word in _STOPWORDS:
            continue
        for suffix in ("ing", "ed", "es", "s"):
            if word.endswith(suffix) and len(word) - len(suffix) >= 3:
                word = word[: -len(suffix)]
                break
        stems.append(word)
    return stems


def _normalise(vector: Sequence[float]) -> List[float]:
    norm = math.sqrt(sum(v * v for v in vector))
    return [v / norm for v in vector] if norm else [0.0 for _ in vector]


class LexicalEmbedder:
    """Hashed bag of word stems; deterministic and model-free."""

    name = f"lexical-{LEXICAL_DIMENSIONS}"

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        vectors = []
        for text in texts:
            vector = [0.0] * LEXICAL_DIMENSIONS
            for word in _words(text):
                digest = hashlib.blake2b(word.encode(), digest_size=4).digest()
                vector[int.from_bytes(digest, "little") % LEXICAL_DIMENSIONS] += 1.0
            vectors.append(_normalise([math.sqrt(v) for v in vector]))
        return vectors


class OllamaEmbedder:
    """Embeddings from a local Ollama server (``POST /api/embed``)."""

    def __init__(self, model: str, url: str, client: Optional[httpx.Client] = None):
        self.model = model
        self.url = url.rstrip("/")
        self.name = f"ollama:{model}"
        self._client = client

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        client = self._client or httpx.Client(timeout=EMBED_TIMEOUT_SECONDS)
        try:
            for start in range(0, len(texts), EMBED_BATCH):
                batch = list(texts[start:start + EMBED_BATCH])
                try:
                    response = client.post(f"{self.url}/api/embed", json={"model": self.model, "input": batch})
                except httpx.HTTPError as error:
                    raise EmbeddingError(f"Ollama at {self.url} did not answer ({type(error).__name__}).") from error
                if response.status_code != 200:
                    raise EmbeddingError(
                        f"Ollama returned HTTP {response.status_code} for model '{self.model}'; "
                        f"pull it with `ollama pull {self.model}` or set semantic_search.model."
                    )
                try:
                    embeddings = response.json()["embeddings"]
                except (ValueError, KeyError, TypeError) as error:
                    raise EmbeddingError("Ollama returned a response without 'embeddings'.") from error
                if (not isinstance(embeddings, list) or len(embeddings) != len(batch)
                        or not all(isinstance(e, list) and e for e in embeddings)):
                    raise EmbeddingError("Ollama returned the wrong number of embeddings.")
                vectors.extend(_normalise([float(v) for v in e]) for e in embeddings)
        finally:
            if self._client is None:
                client.close()
        return vectors


@dataclass(frozen=True)
class SearchSettings:
    embedder: str = "auto"
    model: str = DEFAULT_MODEL
    url: str = DEFAULT_URL
    allow_remote: bool = False


def settings_from(config: Dict[str, Any]) -> SearchSettings:
    """Reads ``semantic_search`` from a config dict; raises ValueError for invalid values."""
    raw = config.get("semantic_search")
    raw = {} if raw is None else raw
    if not isinstance(raw, dict):
        raise ValueError("semantic_search must be an object.")
    embedder = str(raw.get("embedder", "auto")).lower()
    if embedder not in ("auto", "ollama", "lexical"):
        raise ValueError("semantic_search.embedder must be 'auto', 'ollama' or 'lexical'.")
    url = str(raw.get("url", DEFAULT_URL))
    if urlparse(url).scheme not in ("http", "https") or not urlparse(url).hostname:
        raise ValueError(f"semantic_search.url is not an http(s) URL: {url!r}.")
    return SearchSettings(embedder, str(raw.get("model", DEFAULT_MODEL)), url, bool(raw.get("allow_remote", False)))


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _load_settings() -> SearchSettings:
    from core.config import load_merged_config
    return settings_from(load_merged_config())


def _store_path(root: str) -> Path:
    base = Path(os.environ.get("BUZZARD_HOME") or Path.home() / ".buzzard") / "semantic"
    base.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha1(os.path.normcase(os.path.abspath(root)).encode()).hexdigest()[:16]
    return base / f"{key}.sqlite"


def _chunk_text(lines: List[str], symbol: Symbol, next_line: Optional[int]) -> str:
    end = symbol.end_line if symbol.end_line > symbol.line else (next_line - 1 if next_line else symbol.line + CHUNK_MAX_LINES)
    end = min(end, symbol.line + CHUNK_MAX_LINES - 1)
    body = "".join(lines[symbol.line - 1:end])[:CHUNK_MAX_CHARS]
    return f"{symbol.kind} {symbol.qualified} ({symbol.path})\n{body}"


class SemanticStore:
    """SQLite store of symbol embeddings for one workspace, refreshed by file signature."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS chunks (path TEXT, line INTEGER, name TEXT, kind TEXT, "
                "qualified TEXT, size INTEGER, mtime INTEGER, embedder TEXT, vector BLOB)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS chunks_path ON chunks(path)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    def refresh(self, index: CodeIndex, embedder: Any) -> int:
        """Embeds changed files; returns how many files were (re-)embedded."""
        with self._lock:
            db = self._connect()
            try:
                stored = {
                    row[0]: (row[1], row[2], row[3])
                    for row in db.execute("SELECT path, MAX(size), MAX(mtime), MAX(embedder) FROM chunks GROUP BY path")
                }
                changed = [
                    rel for rel, entry in index.files.items()
                    if entry.symbols and stored.get(rel) != (entry.signature[0], entry.signature[1], embedder.name)
                ]
                gone = [rel for rel in stored if rel not in index.files or not index.files[rel].symbols]
                for rel in gone:
                    db.execute("DELETE FROM chunks WHERE path = ?", (rel,))
                for rel in changed:
                    entry = index.files[rel]
                    try:
                        with open(os.path.join(index.root, rel), "r", encoding="utf-8", errors="replace") as handle:
                            lines = handle.readlines()
                    except OSError:
                        continue
                    ordered = sorted(entry.symbols, key=lambda s: s.line)
                    texts = [
                        _chunk_text(lines, symbol, ordered[i + 1].line if i + 1 < len(ordered) else None)
                        for i, symbol in enumerate(ordered)
                    ]
                    vectors = embedder.embed(texts)  # EmbeddingError propagates; nothing is half-written
                    db.execute("DELETE FROM chunks WHERE path = ?", (rel,))
                    db.executemany(
                        "INSERT INTO chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            (rel, s.line, s.name, s.kind, s.qualified, entry.signature[0], entry.signature[1],
                             embedder.name, array.array("f", v).tobytes())
                            for s, v in zip(ordered, vectors)
                        ],
                    )
                    db.commit()
                db.commit()
                return len(changed)
            finally:
                db.close()

    def rows(self, embedder_name: str) -> Iterable[Tuple[str, int, str, str, str, List[float]]]:
        db = self._connect()
        try:
            for path, line, name, kind, qualified, blob in db.execute(
                "SELECT path, line, name, kind, qualified, vector FROM chunks WHERE embedder = ?", (embedder_name,)
            ):
                vector = array.array("f")
                vector.frombytes(blob)
                yield path, line, name, kind, qualified, vector.tolist()
        finally:
            db.close()


_stores: Dict[str, SemanticStore] = {}
_stores_lock = threading.Lock()


def _store_for(root: str) -> SemanticStore:
    path = _store_path(root)
    with _stores_lock:
        return _stores.setdefault(str(path), SemanticStore(path))


def _embedders(settings: SearchSettings) -> List[Any]:
    """Embedders to try, in order. Raises ValueError when the configuration forbids every one."""
    if settings.embedder == "lexical":
        return [LexicalEmbedder()]
    if not settings.allow_remote and not _is_loopback(settings.url):
        if settings.embedder == "ollama":
            raise ValueError(
                f"semantic_search.url {settings.url} is not on this machine; code would leave it. "
                "Set semantic_search.allow_remote to true to allow that."
            )
        return [LexicalEmbedder()]
    ollama = OllamaEmbedder(settings.model, settings.url)
    return [ollama] if settings.embedder == "ollama" else [ollama, LexicalEmbedder()]


def _name_bonus(query_words: List[str], symbol_name: str) -> float:
    if not query_words:
        return 0.0
    name_words = set(_words(symbol_name))
    return NAME_BONUS * sum(1 for w in query_words if w in name_words) / len(query_words)


def code_search(query: str, path: str = ".", limit: int = DEFAULT_LIMIT) -> str:
    """
    Finds functions, classes and methods by what they do (semantic search over the code index).
    Arguments:
        query: Plain-language description, e.g. 'where do we handle refunds'.
        path: Optional sub-directory or file to search within (default '.').
        limit: Number of results (default 10, at most 30).
    """
    query = str(query or "").strip()
    if not query:
        return "Error: query must describe what to find."
    try:
        limit = max(1, min(int(limit), MAX_LIMIT))
    except (TypeError, ValueError):
        return "Error: limit must be a number."
    try:
        scope = _scope_filter(path)
        index = get_index()
        candidates = _embedders(_load_settings())
    except (PermissionError, ValueError) as error:
        return f"Error: {error}"
    store = _store_for(index.root)
    notes = []
    embedder = None
    query_vector: List[float] = []
    for candidate in candidates:
        try:
            query_vector = candidate.embed([query])[0]
            store.refresh(index, candidate)
            embedder = candidate
            break
        except EmbeddingError as error:
            if candidate is candidates[-1]:
                return f"Error: {error}"
            notes.append(f"{error} Using the built-in lexical search instead (no synonyms).")
    assert embedder is not None
    query_words = _words(query)
    scored = []
    for rel, line, name, kind, qualified, vector in store.rows(embedder.name):
        if not _in_scope(rel, scope) or len(vector) != len(query_vector):
            continue
        similarity = sum(a * b for a, b in zip(query_vector, vector))
        scored.append((similarity + _name_bonus(query_words, name), rel, line, kind, qualified))
    if not scored or max(s[0] for s in scored) <= 0:
        return "\n".join(notes + [f"No code matches '{query}'."]) + _footer(index)
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))
    lines = [f"{rel}:{line}  {kind} {qualified}  (score {score:.2f})" for score, rel, line, kind, qualified in scored[:limit] if score > 0]
    header = f"Semantic search ({embedder.name}), best {len(lines)} of {len(scored)} symbols:"
    return "\n".join(notes + [header] + lines) + _footer(index)


def register_semantic_search_tool(registry) -> None:
    """Registers the read-only ``code_search`` tool."""
    from tools.registry import ToolCategory

    registry.register(
        name="code_search",
        description=(
            "Semantic code search: finds functions, classes and methods by what they do, even when the "
            "words are not in their names (local embeddings over the code index). Arguments: query (str), "
            "path (str, default '.'), limit (int, default 10)."
        ),
        func=code_search, category=ToolCategory.AUTOMATION, risk_level="LOW", read_only=True,
        sandbox_required=False, scope_required=False, approval_required=False, timeout=600,
    )
