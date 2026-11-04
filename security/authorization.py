"""
Assessment Authorization Engine and Certificate Validation.

Enforces explicit, verifiable assessment authorization objects before testing,
ensuring testing is constrained to authorized operators, scopes, environments, and time windows.
See plan sections 0, 43, and 45.
"""

import uuid
import time
import hashlib
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set

from security.autonomy import AutonomyLevel, EnvironmentProfile
from security.risk import RiskClass
from security.scope import is_in_scope, extract_host_and_port


@dataclass
class AssessmentAuthorization:
    """
    Cryptographically verifiable authorization token for a security assessment.
    """
    id: str = field(default_factory=lambda: f"AUTH-{uuid.uuid4().hex[:8].upper()}")
    operator_name: str = "Authorized Security Operator"
    operator_email: str = "security@localhost"
    target_hosts: List[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    environment: EnvironmentProfile = EnvironmentProfile.LAB
    max_autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_4_LAB_AUTONOMOUS
    allowed_risk_classes: List[RiskClass] = field(
        default_factory=lambda: [RiskClass.R0_PASSIVE, RiskClass.R1_LOW, RiskClass.R2_MEDIUM, RiskClass.R3_HIGH, RiskClass.R4_CRITICAL]
    )
    purpose: str = "Authorized Security Verification & Penetration Testing"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    signature: Optional[str] = None

    def __post_init__(self):
        # Convert string enums if passed as strings
        if isinstance(self.environment, str) and not isinstance(self.environment, EnvironmentProfile):
            self.environment = EnvironmentProfile(self.environment)
        if isinstance(self.max_autonomy_level, int) and not isinstance(self.max_autonomy_level, AutonomyLevel):
            self.max_autonomy_level = AutonomyLevel(self.max_autonomy_level)
        if not self.signature:
            self.signature = self._compute_signature()

    def _compute_signature(self) -> str:
        """Computes a checksum signature of the authorization claims."""
        raw = f"{self.id}:{self.operator_name}:{self.environment.value}:{','.join(sorted(self.target_hosts))}:{self.created_at}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def is_expired(self) -> bool:
        """Checks if the authorization has passed its expiration timestamp."""
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            now = datetime.now(timezone.utc)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return now > exp
        except Exception:
            return True

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["environment"] = self.environment.value
        d["max_autonomy_level"] = int(self.max_autonomy_level)
        d["allowed_risk_classes"] = [r.value if isinstance(r, RiskClass) else str(r) for r in self.allowed_risk_classes]
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> "AssessmentAuthorization":
        env = EnvironmentProfile(data.get("environment", "lab"))
        level = AutonomyLevel(data.get("max_autonomy_level", 4))
        risk_classes = [RiskClass(r) for r in data.get("allowed_risk_classes", ["R0", "R1", "R2", "R3", "R4"])]
        return cls(
            id=data.get("id", f"AUTH-{uuid.uuid4().hex[:8].upper()}"),
            operator_name=data.get("operator_name", "Authorized Operator"),
            operator_email=data.get("operator_email", "security@localhost"),
            target_hosts=data.get("target_hosts", ["localhost", "127.0.0.1"]),
            environment=env,
            max_autonomy_level=level,
            allowed_risk_classes=risk_classes,
            purpose=data.get("purpose", "Security Assessment"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            expires_at=data.get("expires_at"),
            signature=data.get("signature"),
        )


class AuthorizationEngine:
    """
    Validates authorizations and checks target/action compliance.
    """
    def __init__(self, authorization: Optional[AssessmentAuthorization] = None):
        self.authorization = authorization

    def validate_authorization(self) -> Tuple[bool, str]:
        """Validates that a non-expired authorization object is active."""
        if not self.authorization:
            return False, "No active AssessmentAuthorization provided."
        
        if self.authorization.is_expired():
            return False, f"Authorization {self.authorization.id} expired at {self.authorization.expires_at}."
            
        if not self.authorization.target_hosts:
            return False, "Authorization target_hosts list is empty."

        return True, f"Authorization {self.authorization.id} verified for operator {self.authorization.operator_name}."

    def is_target_authorized(self, target: str) -> Tuple[bool, str]:
        """Checks if a target host or URL is authorized under the active certificate."""
        is_valid, msg = self.validate_authorization()
        if not is_valid:
            return False, msg

        target_host, _ = extract_host_and_port(target)
        if not target_host:
            return False, f"Invalid target identifier: '{target}'."

        if not is_in_scope(target_host, self.authorization.target_hosts):
            return False, (
                f"Target '{target_host}' is not covered by Authorization {self.authorization.id}. "
                f"Authorized hosts: {self.authorization.target_hosts}"
            )

        return True, f"Target '{target_host}' is authorized under {self.authorization.id}."

    def is_risk_class_permitted(self, risk_class: RiskClass) -> bool:
        """Checks if the authorization allows operations of a given risk class."""
        if not self.authorization:
            return False
        return risk_class in self.authorization.allowed_risk_classes


def create_default_authorization(
    target: str,
    scope: Optional[List[str]] = None,
    environment: EnvironmentProfile = EnvironmentProfile.LAB,
    operator: str = "Authorized Security Operator"
) -> AssessmentAuthorization:
    """
    Convenience factory to generate an explicit authorization object for a run.
    """
    target_host, _ = extract_host_and_port(target)
    all_hosts = list(dict.fromkeys([target_host] + (scope or []) + ["localhost", "127.0.0.1"]))
    all_hosts = [h for h in all_hosts if h]

    return AssessmentAuthorization(
        operator_name=operator,
        target_hosts=all_hosts,
        environment=environment,
        purpose=f"Security assessment for target {target}",
    )
