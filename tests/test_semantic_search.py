"""Tests for semantic code search (roadmap A3): embedders, the SQLite store and code_search."""

import os

import httpx
import pytest

from tools import semantic_search
from tools.filesystem import set_active_workspace
from tools.semantic_search import (
    EmbeddingError, LexicalEmbedder, OllamaEmbedder, SearchSettings, code_search, settings_from,
)


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repo(tmp_path, monkeypatch):
    _write(tmp_path, "shop/payments.py", (
        "def reverse_charge(order):\n"
        '    """Gives the customer their money back when an order is refunded."""\n'
        "    order.balance += order.paid\n"
        "    return order\n"
        "\n"
        "def apply_discount(price, rate):\n"
        "    return price * (1 - rate)\n"
    ))
    _write(tmp_path, "shop/shipping.py", (
        "class Courier:\n"
        "    def track_parcel(self, code):\n"
        "        # look up the delivery status with the carrier\n"
        "        return code\n"
    ))
    _write(tmp_path, "web/cart.ts", "export function emptyBasket(cart) {\n  cart.items = [];\n}\n")
    set_active_workspace(str(tmp_path))
    semantic_search._stores.clear()
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: SearchSettings(embedder="lexical"))
    return tmp_path


def test_finds_refund_handler_whose_name_lacks_the_word(repo):
    out = code_search("where do we handle refunds")
    first = out.splitlines()[1]
    assert first.startswith("shop/payments.py:1  function reverse_charge"), out
    assert "lexical" in out.splitlines()[0]


def test_name_index_and_other_languages(repo):
    assert code_search("empty basket").splitlines()[1].startswith("web/cart.ts:1  function emptyBasket")
    assert code_search("parcel tracking").splitlines()[1].startswith("shop/shipping.py:2  method Courier.track_parcel")


def test_scope_limit_and_bad_input(repo):
    out = code_search("money back refund", path="shop/shipping.py")
    assert "payments.py" not in out
    assert len(code_search("price discount order", limit=1).splitlines()) == 2
    assert code_search("  ").startswith("Error")
    assert code_search("x", limit="many").startswith("Error")
    assert code_search("x", path="../outside").startswith("Error")
    assert code_search("zebra giraffe").startswith("No code matches")


def test_store_refreshes_only_changed_files(repo, monkeypatch):
    calls = []
    real = LexicalEmbedder.embed

    def counting(self, texts):
        calls.append(len(texts))
        return real(self, texts)

    monkeypatch.setattr(LexicalEmbedder, "embed", counting)
    code_search("refund")
    first_run = sum(calls)
    assert first_run == 1 + 5  # the query, then every symbol
    calls.clear()
    code_search("refund")
    assert calls == [1]  # nothing re-embedded
    calls.clear()
    path = _write(repo, "shop/shipping.py", "def cancel_delivery(code):\n    return None\n")
    os.utime(path, ns=(1, 1))
    out = code_search("cancel delivery")
    assert calls == [1, 1]  # the query and the one changed file
    assert "cancel_delivery" in out and "track_parcel" not in out
    os.remove(repo / "web/cart.ts")
    assert "emptyBasket" not in code_search("empty basket", limit=30)


def _ollama_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ollama_embedder_batches_and_normalises():
    seen = []

    def handler(request):
        body = __import__("json").loads(request.content)
        seen.append((request.url.path, body["model"], len(body["input"])))
        return httpx.Response(200, json={"embeddings": [[3.0, 4.0] for _ in body["input"]]})

    embedder = OllamaEmbedder("nomic-embed-text", "http://127.0.0.1:11434/", client=_ollama_client(handler))
    vectors = embedder.embed([f"t{i}" for i in range(40)])
    assert len(vectors) == 40 and vectors[0] == pytest.approx([0.6, 0.8])
    assert seen == [("/api/embed", "nomic-embed-text", 32), ("/api/embed", "nomic-embed-text", 8)]


@pytest.mark.parametrize("response, message", [
    (httpx.Response(404, json={"error": "model not found"}), "ollama pull"),
    (httpx.Response(200, json={"nothing": []}), "without 'embeddings'"),
    (httpx.Response(200, json={"embeddings": []}), "wrong number"),
])
def test_ollama_errors_are_reported(response, message):
    embedder = OllamaEmbedder("m", "http://127.0.0.1:1", client=_ollama_client(lambda request: response))
    with pytest.raises(EmbeddingError, match=message):
        embedder.embed(["text"])


def test_auto_falls_back_to_lexical_when_ollama_is_down(repo, monkeypatch):
    def down(self, texts):
        raise EmbeddingError("Ollama at http://127.0.0.1:11434 did not answer (ConnectError).")

    monkeypatch.setattr(OllamaEmbedder, "embed", down)
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: SearchSettings(embedder="auto"))
    out = code_search("refund money back")
    assert "did not answer" in out and "lexical" in out and "reverse_charge" in out
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: SearchSettings(embedder="ollama"))
    assert code_search("refund").startswith("Error: Ollama")


def test_ollama_vectors_are_used_when_available(repo, monkeypatch):
    def fake(self, texts):  # a toy "semantic" model: refund-ish texts point one way
        return [[1.0, 0.0] if any(w in t for w in ("refund", "money back")) else [0.0, 1.0] for t in texts]

    monkeypatch.setattr(OllamaEmbedder, "embed", fake)
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: SearchSettings(embedder="ollama"))
    out = code_search("refund")
    assert "ollama:nomic-embed-text" in out and out.splitlines()[1].startswith("shop/payments.py:1")


def test_remote_embedding_url_needs_opt_in(repo, monkeypatch):
    remote = SearchSettings(embedder="ollama", url="http://203.0.113.5:11434")
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: remote)
    assert "allow_remote" in code_search("refund")
    monkeypatch.setattr(semantic_search, "_load_settings", lambda: SearchSettings(embedder="auto", url=remote.url))
    assert "lexical" in code_search("refund")  # auto never sends code to a remote host
    assert semantic_search._is_loopback("http://localhost:11434")
    assert semantic_search._is_loopback("http://[::1]:11434")


def test_settings_validation():
    assert settings_from({}) == SearchSettings()
    assert settings_from({"semantic_search": {"embedder": "Lexical"}}).embedder == "lexical"
    for bad in ({"semantic_search": []}, {"semantic_search": {"embedder": "gpt"}},
                {"semantic_search": {"url": "file:///etc"}}):
        with pytest.raises(ValueError):
            settings_from(bad)


def test_registered_read_only_for_the_coding_agent():
    from agent.loop import CODING_TOOL_NAMES
    from agent.tool_executor import WORKSPACE_STATE_TOOLS
    from tools.registry import create_authoritative_registry

    definition = create_authoritative_registry().definitions["code_search"]
    assert definition.read_only and not definition.approval_required
    assert "code_search" in CODING_TOOL_NAMES and "code_search" in WORKSPACE_STATE_TOOLS
