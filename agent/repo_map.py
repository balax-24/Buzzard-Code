"""Deterministic, task-focused repository maps built from the code index."""

from __future__ import annotations

import re
from collections import defaultdict

from tools.code_index import CodeIndex

_TOKEN_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]*|[A-Z]+(?=[A-Z][a-z]|\b)")
_STOP_WORDS = frozenset({
    "about", "after", "before", "could", "file", "files", "from", "have", "into",
    "make", "please", "should", "that", "them", "there", "these", "this", "those",
    "through", "using", "with", "would", "your", "code", "project", "repository",
})


def _query_terms(task: str) -> set[str]:
    terms: set[str] = set()
    for token in _TOKEN_PATTERN.findall(task):
        normalized = token.casefold()
        if len(normalized) >= 3 and normalized not in _STOP_WORDS:
            terms.add(normalized)
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_.$/-]+", task):
        for part in re.split(r"[._$/-]+", token):
            normalized = part.casefold()
            if len(normalized) >= 3 and normalized not in _STOP_WORDS:
                terms.add(normalized)
    return terms


def _symbol_terms(symbol_name: str) -> set[str]:
    terms = {part.casefold() for part in re.split(r"[^A-Za-z0-9]+", symbol_name) if len(part) >= 3}
    terms.update(part.casefold() for part in _TOKEN_PATTERN.findall(symbol_name) if len(part) >= 3)
    return terms


def _personalized_rank(
    paths: list[str], graph: dict[str, set[str]], personalization: dict[str, float],
) -> dict[str, float]:
    if not paths:
        return {}
    total_weight = sum(personalization.values())
    if total_weight:
        personal = {path: personalization.get(path, 0.0) / total_weight for path in paths}
    else:
        personal = {path: 1.0 / len(paths) for path in paths}
    scores = dict(personal)
    for _ in range(20):
        next_scores = {path: 0.15 * personal[path] for path in paths}
        dangling = 0.0
        for path in paths:
            neighbors = graph[path]
            if not neighbors:
                dangling += scores[path]
                continue
            share = 0.85 * scores[path] / len(neighbors)
            for neighbor in neighbors:
                next_scores[neighbor] += share
        if dangling:
            for path in paths:
                next_scores[path] += 0.85 * dangling * personal[path]
        scores = next_scores
    return scores


def build_repo_map(index: CodeIndex, task: str, budget_chars: int = 8000) -> str:
    """Return a bounded map of relevant files and import-neighbor files.

    File and symbol matches personalize PageRank over the local import graph. The graph is
    constructed as undirected relationships so both dependencies and their callers are useful.
    No source contents are copied into the prompt.
    """
    if budget_chars < 1:
        raise ValueError("budget_chars must be positive")
    paths = sorted(index.files)
    if not paths:
        return ""

    terms = _query_terms(task)
    personalization: dict[str, float] = defaultdict(float)
    symbol_names: dict[str, list[str]] = {}
    for path in paths:
        path_terms = _symbol_terms(path)
        path_hits = path_terms & terms
        if path_hits:
            personalization[path] += 3.0 * len(path_hits)
        names = sorted({symbol.qualified for symbol in index.files[path].symbols})
        symbol_names[path] = names
        for name in names:
            hits = _symbol_terms(name) & terms
            if hits:
                personalization[path] += 2.0 * len(hits)

    graph: dict[str, set[str]] = {path: set() for path in paths}
    for path, entry in index.files.items():
        for imported in entry.imports:
            neighbor = index.resolve_import(path, imported)
            if neighbor and neighbor != path:
                graph[path].add(neighbor)
                graph[neighbor].add(path)

    page_rank = _personalized_rank(paths, graph, personalization)
    max_rank = max(page_rank.values(), default=1.0) or 1.0
    max_personalization = max(personalization.values(), default=1.0) or 1.0

    def sort_key(path: str) -> tuple[float, str]:
        lexical = personalization[path] / max_personalization
        graph_score = page_rank[path] / max_rank
        return (0.8 * lexical + 0.2 * graph_score, path)

    ranked_paths = sorted(paths, key=sort_key, reverse=True)
    header = "Repository map (ranked by task matches and local import relationships):"
    lines = [header]
    used_chars = len(header)
    for path in ranked_paths:
        names = symbol_names[path]
        line = f"- {path}"
        if names:
            line += " — " + ", ".join(names[:8])
            if len(names) > 8:
                line += f", … ({len(names)} symbols)"
        if used_chars + len(line) + 1 > budget_chars:
            break
        lines.append(line)
        used_chars += len(line) + 1
    if len(lines) == 1:
        return ""
    return "\n".join(lines)
