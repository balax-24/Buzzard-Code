"""
Phase 16 Tests: Action Semantics & Equivalence.
Proves that various syntax representations map to the identical canonical key.
"""

from intelligence.action_identity import ActionIdentity, SemanticActionKey


def test_action_semantic_normalization_across_syntax():
    # curl vs http_request vs web_probe
    key1 = ActionIdentity.generate_canonical_key("curl", {"url": "http://127.0.0.1:8080/admin", "method": "GET"}, "127.0.0.1")
    key2 = ActionIdentity.generate_canonical_key("http_request", {"url": "http://127.0.0.1:8080/admin", "method": "get"}, "127.0.0.1")
    key3 = ActionIdentity.generate_canonical_key("web_probe", {"url": "http://127.0.0.1:8080/admin"}, "127.0.0.1")

    assert key1.canonical_key == key2.canonical_key
    assert key2.canonical_key == key3.canonical_key
    assert key1.canonical_key == "HTTP:GET:http://127.0.0.1:8080/admin"


def test_port_scan_normalization():
    key1 = ActionIdentity.generate_canonical_key("nmap", {"target": "127.0.0.1", "ports": "80,443,8080"}, "127.0.0.1")
    key2 = ActionIdentity.generate_canonical_key("port_scan", {"target": "127.0.0.1", "ports": "8080,80,443"}, "127.0.0.1")

    assert key1.canonical_key == key2.canonical_key
    assert "SCAN:80,443,8080" in key1.canonical_key
