import pytest
from security_agent.benchmark.phase17_bench import MultiHostSyntheticLab, PrivilegeLevel

def test_multihost_initial_reachability():
    lab = MultiHostSyntheticLab()
    assert "192.168.1.10" in lab.discovered_hosts
    assert "192.168.1.20" not in lab.discovered_hosts
    assert "192.168.1.30" not in lab.discovered_hosts
    assert "192.168.1.40" not in lab.discovered_hosts

def test_multihost_progressive_discovery():
    lab = MultiHostSyntheticLab()
    # Step 1: Probe Host A
    resp, delta, use_class, _ = lab.execute_tool("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", set(), {})
    assert "192.168.1.20" in lab.discovered_hosts
    assert lab.current_privilege == PrivilegeLevel.AUTHENTICATED

    # Step 2: Probe Host B with auth
    resp2, delta2, use_class2, _ = lab.execute_tool("http_request", {"url": "http://192.168.1.20:8443/admin"}, "192.168.1.20", {"AUTHENTICATED"}, {"jwt": lab.credentials_vault["cred_jwt_admin"].value})
    assert "192.168.1.30" in lab.discovered_hosts
    assert lab.current_privilege == PrivilegeLevel.ADMIN

    # Step 3: Probe Host C with admin
    resp3, delta3, use_class3, _ = lab.execute_tool("http_request", {"url": "http://192.168.1.30:8000/files"}, "192.168.1.30", {"ADMIN", "HOST_C_REACHABLE"}, {})
    assert "192.168.1.40" in lab.discovered_hosts

    # Step 4: Access Host D Vault
    resp4, delta4, use_class4, _ = lab.execute_tool("http_request", {"url": "http://192.168.1.40:8200/v1/secret/master"}, "192.168.1.40", {"COMMAND_EXECUTION", "SSH_KEY_ACQUIRED"}, {})
    assert "FLAG{PHASE17_MASTER_VAULT_ROOT_COMPROMISE}" in resp4["master_secret"]
