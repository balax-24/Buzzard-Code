"""
Phase 15 Tests: Semantic Action Identity & Normalization.
Verifies stable canonical identities across tools, parameter orderings, and command styles.
"""

from intelligence.action_identity import ActionIdentity, SemanticActionKey


def test_http_url_and_method_normalization():
    k1 = ActionIdentity.generate_canonical_key(
        tool_name="http_request",
        parameters={"url": "http://127.0.0.1:8080/api/v1/users?b=2&a=1", "method": "get"},
    )
    k2 = ActionIdentity.generate_canonical_key(
        tool_name="curl",
        parameters={"cmd": "curl -X GET 'http://127.0.0.1:8080/api/v1/users?a=1&b=2'"},
    )
    k3 = ActionIdentity.generate_canonical_key(
        tool_name="http_client",
        parameters={"endpoint": "http://127.0.0.1:8080/api/v1/users?b=2&a=1", "method": "GET"},
    )

    assert k1.canonical_key == k2.canonical_key == k3.canonical_key
    assert k1.action_type == "HTTP:GET"
    assert "a=1&b=2" in k1.endpoint


def test_port_scan_normalization():
    k1 = ActionIdentity.generate_canonical_key(
        tool_name="nmap",
        parameters={"target": "127.0.0.1", "ports": "80,443,8080"},
    )
    k2 = ActionIdentity.generate_canonical_key(
        tool_name="port_scan",
        parameters={"host": "127.0.0.1", "ports": "80,443,8080"},
    )
    assert k1.canonical_key == k2.canonical_key
    assert k1.action_type == "SCAN"


def test_browser_action_normalization():
    k1 = ActionIdentity.generate_canonical_key(
        tool_name="browser_navigate",
        parameters={"url": "http://127.0.0.1:8080/admin/settings/"},
    )
    k2 = ActionIdentity.generate_canonical_key(
        tool_name="browser_navigate",
        parameters={"url": "http://127.0.0.1:8080/admin/settings"},
    )
    assert k1.canonical_key == k2.canonical_key
    assert k1.action_type == "BROWSER:NAVIGATE"


def test_context_signature_generation():
    sig1 = ActionIdentity.create_context_signature(capabilities=["AUTHENTICATED", "FILE_READ"])
    sig2 = ActionIdentity.create_context_signature(capabilities=["FILE_READ", "AUTHENTICATED"])
    sig3 = ActionIdentity.create_context_signature(capabilities=["ADMIN_PRIVILEGE"])

    assert sig1 == sig2
    assert sig1 != sig3


def test_is_semantically_equivalent():
    a1 = ("http_request", {"url": "http://target/admin", "method": "POST", "body": "x=1"})
    a2 = ("http_client", {"url": "http://target/admin/", "method": "post", "data": "x=1"})
    assert ActionIdentity.is_semantically_equivalent(a1, a2) is True
