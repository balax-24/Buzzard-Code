"""Tests for web search and documentation fetch (roadmap D5): SSRF, allow/deny lists, untrusted output."""

import httpx
import pytest

from tools import web_tools
from tools.web_tools import (
    UNTRUSTED_BANNER, WebError, WebSettings, settings_from, web_lookup, web_read,
)


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Every host resolves to a public address unless a test overrides it."""
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(web_tools, "_load_settings", lambda: WebSettings())


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_web_read_returns_readable_text_marked_untrusted():
    def handler(request):
        assert request.headers["user-agent"].startswith("BuzzardCode")
        return httpx.Response(200, html="<html><head><style>b{}</style><script>evil()</script></head>"
                                        "<body><h1>Title</h1><p>Hello &amp; welcome</p></body></html>")

    out = web_read("https://example.com/doc", _client=_client(handler))
    assert out.startswith(UNTRUSTED_BANNER)
    assert "Title Hello & welcome" in out
    assert "evil()" not in out and "<p>" not in out


def test_web_read_truncates_long_pages():
    big = "x" * (web_tools.MAX_TEXT_CHARS + 500)
    out = web_read("https://host.test/p", _client=_client(lambda r: httpx.Response(200, text=big)))
    assert "truncated at" in out and out.count("x") == web_tools.MAX_TEXT_CHARS


def test_web_read_rejects_non_http_and_missing_host():
    assert web_read("ftp://example.com").startswith("Error")
    assert "no host" in web_read("http://").lower() or "resolve" in web_read("http://").lower()
    assert web_read("   ").startswith("Error")


def test_ssrf_private_address_is_refused(monkeypatch):
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["127.0.0.1"])
    out = web_read("http://localhost/admin", _client=_client(lambda r: httpx.Response(200, text="secret")))
    assert out.startswith("Error") and "non-public" in out
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["169.254.169.254"])
    assert "non-public" in web_read("http://metadata/")
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["10.0.0.5"])
    assert "non-public" in web_read("http://intranet/")


def test_allow_private_opt_in(monkeypatch):
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: ["127.0.0.1"])
    monkeypatch.setattr(web_tools, "_load_settings", lambda: WebSettings(allow_private=True))
    out = web_read("http://localhost/x", _client=_client(lambda r: httpx.Response(200, text="ok local")))
    assert "ok local" in out


def test_deny_and_allow_lists(monkeypatch):
    ok = _client(lambda r: httpx.Response(200, text="page"))
    monkeypatch.setattr(web_tools, "_load_settings", lambda: WebSettings(deny=("evil.com",)))
    assert "web.deny" in web_read("https://sub.evil.com/x", _client=ok)
    monkeypatch.setattr(web_tools, "_load_settings", lambda: WebSettings(allow=("docs.python.org",)))
    assert "not on the web.allow" in web_read("https://example.com/x", _client=ok)
    assert "page" in web_read("https://docs.python.org/3/", _client=ok)


def test_redirect_to_private_host_is_blocked(monkeypatch):
    hosts = {"public.example.com": ["93.184.216.34"], "internal": ["127.0.0.1"]}
    monkeypatch.setattr(web_tools, "_resolve_addresses", lambda host: hosts[host])

    def handler(request):
        if request.url.host == "public.example.com":
            return httpx.Response(302, headers={"location": "http://internal/secret"})
        return httpx.Response(200, text="LEAKED")

    out = web_read("https://public.example.com/go", _client=_client(handler))
    assert out.startswith("Error") and "non-public" in out and "LEAKED" not in out


def test_too_many_redirects(monkeypatch):
    out = web_read(
        "https://example.com/loop",
        _client=_client(lambda r: httpx.Response(302, headers={"location": "https://example.com/loop"})),
    )
    assert "Too many redirects" in out


def test_web_lookup_parses_results():
    page = """
    <div class="result__body">
      <a class="result__a" href="/l/?uddg=https%3A%2F%2Fdocs.python.org%2F3%2F">Python Docs</a>
      <a class="result__snippet">The official <b>Python</b> documentation.</a>
    </div></div>
    <div class="result__body">
      <a class="result__a" href="https://realpython.com/">Real Python</a>
      <a class="result__snippet">Tutorials</a>
    </div></div>
    """

    def handler(request):
        assert request.url.params.get("q") == "python json parsing"
        return httpx.Response(200, text=page)

    out = web_lookup("python json parsing", _client=_client(handler))
    assert out.startswith(UNTRUSTED_BANNER)
    assert "https://docs.python.org/3/" in out and "official Python documentation" in out
    assert "https://realpython.com/" in out


def test_web_lookup_limits_and_bad_input():
    page = "".join(
        f'<div class="result__body"><a class="result__a" href="https://e{i}.com/">R{i}</a>'
        f'<a class="result__snippet">s{i}</a></div></div>' for i in range(10)
    )
    out = web_lookup("q", max_results=2, _client=_client(lambda r: httpx.Response(200, text=page)))
    assert out.count("https://e") == 2
    assert web_lookup("   ").startswith("Error")
    assert web_lookup("q", max_results="lots").startswith("Error")


def test_http_error_status_reported():
    assert "HTTP 404" in web_read("https://example.com/missing", _client=_client(lambda r: httpx.Response(404)))
    assert "HTTP 503" in web_lookup("q", _client=_client(lambda r: httpx.Response(503)))


def test_settings_validation():
    assert settings_from({}) == WebSettings()
    assert settings_from({"web": {"deny": ["Evil.COM", ".internal"]}}).deny == ("evil.com", "internal")
    for bad in ({"web": []}, {"web": {"allow": "x"}}, {"web": {"deny": [1]}}, {"web": {"allow": [""]}}):
        with pytest.raises(ValueError):
            settings_from(bad)


def test_registered_needs_approval_and_network():
    from agent.loop import CODING_TOOL_NAMES
    from tools.registry import create_authoritative_registry

    registry = create_authoritative_registry()
    for name in ("web_lookup", "web_read"):
        definition = registry.definitions[name]
        assert definition.approval_required and definition.network_required
        assert not definition.scope_required
        assert name in CODING_TOOL_NAMES


def test_plan_mode_refuses_web_tools():
    from agent.run_session import RunSession

    session = RunSession(None, None, None, {}, ask_approval=lambda request: "allow")
    session.plan_mode = True
    assert session.approve("web_lookup", {"query": "x"}, None) is False
    assert session.approve("web_read", {"url": "https://example.com"}, None) is False
    session.plan_mode = False
    assert session.approve("web_read", {"url": "https://example.com"}, None) is True


def test_scope_does_not_block_web_tools():
    from security.policy import PolicyEngine

    engine = PolicyEngine(["localhost"])
    assert engine._check_scope("web_read", {"url": "https://example.com/doc"})[0] is True
    # a scope-required tool with an out-of-scope url is still refused
    assert engine._check_scope("web_fetch", {"url": "https://example.com/doc"})[0] is False
