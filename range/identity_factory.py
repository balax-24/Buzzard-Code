"""
Identity Factory and Persona Management.

Generates multi-tenant test personas, API keys, and authorization headers
to automate horizontal and vertical privilege escalation testing.
See plan section 64 and Phase G.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import uuid


@dataclass
class TestPersona:
    id: str
    role: str  # 'admin', 'editor', 'viewer', 'unauthenticated'
    username: str
    auth_header: Dict[str, str] = field(default_factory=dict)
    tenant_id: str = "tenant-001"


class IdentityFactory:
    """
    Produces consistent persona sets for RBAC matrix testing.
    """
    def create_persona_suite(self, base_tenant: str = "tenant-100") -> Dict[str, TestPersona]:
        return {
            "admin": TestPersona(
                id=f"usr-{uuid.uuid4().hex[:6]}",
                role="admin",
                username="sec_admin_test",
                auth_header={"Authorization": "Bearer test-jwt-admin-token-xyz"},
                tenant_id=base_tenant
            ),
            "user_a": TestPersona(
                id=f"usr-{uuid.uuid4().hex[:6]}",
                role="user",
                username="alice_regular",
                auth_header={"Authorization": "Bearer test-jwt-alice-token-xyz"},
                tenant_id=base_tenant
            ),
            "user_b": TestPersona(
                id=f"usr-{uuid.uuid4().hex[:6]}",
                role="user",
                username="bob_competitor",
                auth_header={"Authorization": "Bearer test-jwt-bob-token-xyz"},
                tenant_id="tenant-999"  # Cross-tenant IDOR check
            ),
            "guest": TestPersona(
                id="usr-anonymous",
                role="unauthenticated",
                username="anonymous_guest",
                auth_header={},
                tenant_id=""
            )
        }
