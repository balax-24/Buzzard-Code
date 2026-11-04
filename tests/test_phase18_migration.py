import pytest
from security_agent.persistence.migration import SchemaMigrator, CURRENT_SCHEMA_VERSION

def test_schema_migration_from_v1_0():
    legacy_payload = {
        "schema_version": "1.0",
        "engagement_id": "eng-legacy",
        "assessment_state": {"target": "10.0.0.1", "scope": ["10.0.0.1"]},
    }
    migrated = SchemaMigrator.migrate_payload(legacy_payload, target_version=CURRENT_SCHEMA_VERSION)
    assert migrated["schema_version"] == "1.1"
    assert "credentials" in migrated
    assert "sessions" in migrated
    assert "budget" in migrated
    assert migrated["engagement_id"] == "eng-legacy"
