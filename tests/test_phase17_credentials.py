import pytest
from benchmark.phase17_bench import Phase17Credential, PrivilegeLevel

def test_credential_lifecycle_and_scope():
    cred = Phase17Credential(
        credential_id="cred_jwt_1",
        credential_type="jwt",
        value="ey...",
        target_scope="192.168.1.20",
        associated_identity="admin",
        privilege_level=PrivilegeLevel.ADMIN,
        source_evidence_id="EVI-AUTH",
        is_validated=False,
    )
    assert not cred.is_validated
    assert cred.target_scope == "192.168.1.20"

    # Validation
    cred.is_validated = True
    assert cred.is_validated
