"""
Explicit Security Assessment State Machine & Canonical Context.
Guides autonomous progression through structured methodology:
DISCOVERY -> IDENTIFICATION -> TARGETED_ENUMERATION -> VERIFICATION -> REPORT

Authoritative source of truth for:
1. Canonical Service State (ServiceRecord: host, port, protocol, service, version, state, confidence)
2. Canonical HTTP State (HTTPEndpointRecord: DISCOVERED, RESPONDS, REFUSED, TIMEOUT, UNREACHABLE)
3. Candidate Action Pre-Execution Validation (Schema, Target Compatibility, Evidence Justification)
4. Evidence Contradiction Detection (Rejects claims contrary to verified evidence)
5. Action Metadata Logging ("Why this tool?" audit trail)
6. Deterministic Service Routing (IPP -> IPP probes, HTTP -> Web tools)
"""

from __future__ import annotations

import re
import json
import time
import uuid
import hashlib
import urllib.parse
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set


from security_agent.state.session_store import (
    SessionStore,
    Session,
    Cookie,
    BearerToken,
    CSRFToken,
    AuthenticationState,
    SessionVerificationStatus,
)


class CapabilityType(str, Enum):
    """Explicit capability levels and privileges."""
    UNAUTHENTICATED   = "UNAUTHENTICATED"    # Baseline unauthenticated access
    AUTHENTICATED     = "AUTHENTICATED"      # Valid session / token / credential
    USER_ACCESS       = "USER_ACCESS"        # Low-privilege user access
    ADMIN_ACCESS      = "ADMIN_ACCESS"       # Administrative / root privileges
    FILE_READ         = "FILE_READ"          # Arbitrary or sensitive file read (LFI, traversal)
    FILE_WRITE        = "FILE_WRITE"         # Arbitrary file write / upload
    COMMAND_EXECUTION = "COMMAND_EXECUTION"  # OS command execution / shell access (RCE)
    DATABASE_READ     = "DATABASE_READ"      # Read access to database
    DATABASE_ACCESS   = "DATABASE_ACCESS"    # Direct SQL or DB query execution
    SECRET_ACCESS     = "SECRET_ACCESS"      # Access to keys, secrets, tokens, or credential stores
    NETWORK_ACCESS    = "NETWORK_ACCESS"     # Network access / reachability
    NETWORK_PIVOT     = "NETWORK_PIVOT"      # Internal network route / proxy reachability
    CLOUD_ACCESS      = "CLOUD_ACCESS"       # Cloud metadata / IAM credentials


class CapabilityState(str, Enum):
    """Lifecycle state of an operational capability."""
    UNACQUIRED = "UNACQUIRED"
    CANDIDATE  = "CANDIDATE"
    ACQUIRED   = "ACQUIRED"
    VERIFIED   = "VERIFIED"
    LOST       = "LOST"
    REVOKED    = "REVOKED"


@dataclass
class Capability:
    """
    A verified operational capability acquired during an assessment.
    """
    capability_id: str
    capability_type: CapabilityType
    source_evidence_ids: List[str] = field(default_factory=list)
    acquisition_action: str = ""
    target_scope: str = ""
    timestamp: float = field(default_factory=time.time)
    verified: bool = True
    state: CapabilityState = CapabilityState.VERIFIED
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def type(self) -> CapabilityType:
        return self.capability_type

    @property
    def scope(self) -> str:
        return self.target_scope

    @property
    def evidence_ids(self) -> List[str]:
        return self.source_evidence_ids

    @property
    def verification_status(self) -> str:
        return "VERIFIED" if self.verified else "UNVERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "capability_type": (
                self.capability_type.value
                if hasattr(self.capability_type, "value")
                else str(self.capability_type)
            ),
            "type": (
                self.capability_type.value
                if hasattr(self.capability_type, "value")
                else str(self.capability_type)
            ),
            "source_evidence_ids": list(self.source_evidence_ids),
            "evidence_ids": list(self.source_evidence_ids),
            "acquisition_action": self.acquisition_action,
            "target_scope": self.target_scope,
            "scope": self.target_scope,
            "timestamp": self.timestamp,
            "verified": self.verified,
            "state": self.state.value if hasattr(self.state, "value") else str(self.state),
            "verification_status": self.verification_status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Capability:
        cap_type_raw = data.get("capability_type") or data.get("type", CapabilityType.UNAUTHENTICATED.value)
        try:
            cap_type = CapabilityType(cap_type_raw)
        except ValueError:
            cap_type = CapabilityType.UNAUTHENTICATED

        state_raw = data.get("state", CapabilityState.VERIFIED.value)
        try:
            cap_state = CapabilityState(state_raw)
        except ValueError:
            cap_state = CapabilityState.VERIFIED

        return cls(
            capability_id=data["capability_id"],
            capability_type=cap_type,
            source_evidence_ids=data.get("source_evidence_ids") or data.get("evidence_ids", []),
            acquisition_action=data.get("acquisition_action", ""),
            target_scope=data.get("target_scope") or data.get("scope", ""),
            timestamp=data.get("timestamp", time.time()),
            verified=data.get("verified", True),
            state=cap_state,
            metadata=data.get("metadata", {}),
        )


class AssessmentPhase(str, Enum):
    # Canonical 16-step lifecycle
    ASSESSMENT_START = "ASSESSMENT_START"
    SCOPE_VALIDATED = "SCOPE_VALIDATED"
    DISCOVERY = "DISCOVERY"
    IDENTIFICATION = "IDENTIFICATION"
    SURFACE_ENUMERATION = "SURFACE_ENUMERATION"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    PRECONDITION_EVALUATION = "PRECONDITION_EVALUATION"
    VALIDATION = "VALIDATION"
    CAPABILITY_ACQUISITION = "CAPABILITY_ACQUISITION"
    GRAPH_EXPANSION = "GRAPH_EXPANSION"
    RECURSIVE_INVESTIGATION = "RECURSIVE_INVESTIGATION"
    INDEPENDENT_VERIFICATION = "INDEPENDENT_VERIFICATION"
    FINDING_CORRELATION = "FINDING_CORRELATION"
    OBJECTIVE_EVALUATION = "OBJECTIVE_EVALUATION"
    REPORT = "REPORT"
    TERMINAL = "TERMINAL"

    # Backwards-compatible lifecycle / setup aliases
    INITIALIZING = "INITIALIZING"
    INITIALIZE = "INITIALIZE"
    AUTHORIZATION_CHECK = "AUTHORIZATION_CHECK"
    SCOPE_VALIDATION = "SCOPE_VALIDATION"
    SCOPE = "SCOPE"

    # Recon / Discovery aliases
    ASSET_DISCOVERY = "ASSET_DISCOVERY"
    RECON = "DISCOVERY"
    PASSIVE_RECON = "PASSIVE_RECON"

    # Identification / Modeling aliases
    APPLICATION_MODELING = "APPLICATION_MODELING"
    ANALYZE = "IDENTIFICATION"
    THREAT_MODELING = "THREAT_MODELING"
    ATTACK_SURFACE_MAPPING = "ATTACK_SURFACE_MAPPING"

    # Enumeration aliases
    ENUMERATION = "ENUMERATION"
    TARGETED_ENUMERATION = "TARGETED_ENUMERATION"

    # Hypothesis aliases
    HYPOTHESIS = "HYPOTHESIS"
    TEST = "TARGETED_ENUMERATION"
    ACTIVE_TESTING = "ACTIVE_TESTING"
    PRECONDITION = "PRECONDITION"

    # Exploitation / Validation aliases
    EXPLOITATION = "EXPLOITATION"

    # Verification aliases
    VERIFICATION = "VERIFICATION"
    VERIFY = "VERIFICATION"
    ATTACK_PATH_ANALYSIS = "ATTACK_PATH_ANALYSIS"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"

    # Post-Exploitation aliases
    POST_EXPLOITATION = "POST_EXPLOITATION"

    # Reporting aliases
    REPORTING = "REPORTING"
    DOCUMENT = "REPORT"
    REMEDIATION = "REMEDIATION"
    RETEST = "RETEST"

    # Terminal & Flow control aliases
    COMPLETED = "COMPLETED"
    COMPLETE = "COMPLETE"
    PAUSED = "PAUSED"
    FAILED = "FAILED"


class ObjectiveStatus(str, Enum):
    """Explicit objective completion and verification lifecycle states."""
    OBJECTIVE_UNREACHED = "OBJECTIVE_UNREACHED"
    OBJECTIVE_ACHIEVED_UNVERIFIED = "OBJECTIVE_ACHIEVED_UNVERIFIED"
    OBJECTIVE_VERIFIED = "OBJECTIVE_VERIFIED"
    SURFACE_EXHAUSTED = "SURFACE_EXHAUSTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    STALE = "STALE"
    OBJECTIVE_FAILED = "OBJECTIVE_FAILED"


# Valid objective transitions — only forward moves are allowed.
_VALID_OBJECTIVE_TRANSITIONS: Dict[str, Set[str]] = {
    "OBJECTIVE_UNREACHED": {"OBJECTIVE_ACHIEVED_UNVERIFIED", "BUDGET_EXHAUSTED", "SURFACE_EXHAUSTED", "STALE", "OBJECTIVE_FAILED"},
    "OBJECTIVE_ACHIEVED_UNVERIFIED": {"OBJECTIVE_VERIFIED", "BUDGET_EXHAUSTED", "OBJECTIVE_FAILED"},
    "OBJECTIVE_FAILED": {"OBJECTIVE_ACHIEVED_UNVERIFIED"},  # allow retry
    # terminal states
    "OBJECTIVE_VERIFIED": set(),
    "BUDGET_EXHAUSTED": set(),
    "SURFACE_EXHAUSTED": {"OBJECTIVE_ACHIEVED_UNVERIFIED"},  # new surface can re-open
    "STALE": {"OBJECTIVE_ACHIEVED_UNVERIFIED"},
}


@dataclass
class VerificationPredicates:
    """Configurable predicates that control how the generic engine recognises
    proof-of-compromise, validation tools, and session credentials.

    Lab/CTF scenarios supply concrete values; the AgentLoop never hardcodes
    scenario-specific strings.
    """
    # Strings whose presence in raw tool output indicate proof of compromise.
    proof_markers: List[str] = field(default_factory=lambda: [
        "FLAG{", "FLAG-", "PROOF-", "root:x:0:0",
    ])

    # Strings indicating authenticated, elevated session, or confirmed vulnerability.
    session_indicators: List[str] = field(default_factory=lambda: [
        "Admin Dashboard", "Admin Panel",
        "Welcome, Administrator", "ROLE: ADMIN", "Authorized Session",
        "authentication bypass", "sql syntax", "You have an error in your SQL",
        "ORA-", "pg_query",
    ])

    # Tool names (or substrings within tool names / args) that are
    # considered "validation" actions.
    validation_tool_names: List[str] = field(default_factory=lambda: [
        "http.request", "sqlmap_attack", "curl_probe",
    ])
    validation_tool_keywords: List[str] = field(default_factory=lambda: [
        "exploit", "attack",
    ])
    validation_arg_keywords: List[str] = field(default_factory=lambda: [
        "login", "admin",
    ])

    # Regex for extracting session tokens from tool output.
    session_token_pattern: str = r"session=([a-zA-Z0-9_-]+)"
    default_session_cookie: str = "session=admin"

    # Fallback finding template used when proof markers are found but
    # no hypothesis-linked finding has been recorded yet.
    fallback_finding_title: str = "Verified Objective Achievement"
    fallback_finding_description: str = (
        "Automated validation confirmed objective completion with proof marker in response."
    )

    # Configurable verification endpoints to test when elevated privilege / validation occurs.
    verification_endpoints: List[Dict[str, str]] = field(default_factory=lambda: [
        {
            "path": "/admin",
            "reason": "Independently verify administrative dashboard access on {url} with authenticated session.",
            "expected_proof": "ADMIN_STATE / Admin Dashboard / FLAG-ALPHA-AUTH-BYPASS"
        },
        {
            "path": "/flag",
            "reason": "Independently verify elevated privilege by retrieving benchmark flag on {url}.",
            "expected_proof": "FLAG{auth_bypass_sqli_verified} / FLAG-ALPHA-AUTH-BYPASS"
        },
        {
            "path": "/dashboard",
            "reason": "Verify user dashboard and authorization level on {url}.",
            "expected_proof": "Authorized Session State / Welcome Admin"
        },
    ])

    def is_validation_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Return True if the tool+args combination qualifies as a validation action."""
        if tool_name in self.validation_tool_names:
            return True
        args_str = str(tool_args)
        if any(kw in tool_name for kw in self.validation_tool_keywords):
            return True
        if any(kw in args_str for kw in self.validation_arg_keywords):
            return True
        return False

    matches_validation_tool = is_validation_tool

    def has_proof_marker(self, raw_output: str) -> bool:
        """Return True if *any* configured proof marker appears in raw output."""
        return any(m in raw_output for m in self.proof_markers)

    def matches_proof(self, raw_output: str) -> Optional[str]:
        """Return the first matching proof marker found in raw output, or None."""
        if not raw_output:
            return None
        for m in self.proof_markers:
            if m in raw_output:
                return m
        return None

    def extract_session_token(self, raw_output: str) -> Optional[str]:
        """Extract a session token from raw output, or return None."""
        if not raw_output or not self.session_token_pattern:
            return None
        m = __import__("re").search(self.session_token_pattern, raw_output)
        if m:
            token = m.group(1) if m.groups() else m.group(0)
            if not token.startswith("session=") and "session" in self.session_token_pattern:
                return f"session={token}"
            return token
        return None


# Valid forward transitions (phase -> set of valid next phases)
VALID_TRANSITIONS: Dict[AssessmentPhase, Set[AssessmentPhase]] = {
    AssessmentPhase.ASSESSMENT_START: {
        AssessmentPhase.SCOPE_VALIDATED,
        AssessmentPhase.SCOPE_VALIDATION,
        AssessmentPhase.SCOPE,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.INITIALIZING,
        AssessmentPhase.INITIALIZE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.SCOPE_VALIDATED: {
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.SURFACE_ENUMERATION,
        AssessmentPhase.PASSIVE_RECON,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.SURFACE_ENUMERATION: {
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.PRECONDITION_EVALUATION,
        AssessmentPhase.VALIDATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.HYPOTHESIS_GENERATION: {
        AssessmentPhase.PRECONDITION_EVALUATION,
        AssessmentPhase.VALIDATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.SURFACE_ENUMERATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.PRECONDITION_EVALUATION: {
        AssessmentPhase.VALIDATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.VALIDATION: {
        AssessmentPhase.CAPABILITY_ACQUISITION,
        AssessmentPhase.GRAPH_EXPANSION,
        AssessmentPhase.RECURSIVE_INVESTIGATION,
        AssessmentPhase.INDEPENDENT_VERIFICATION,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.CAPABILITY_ACQUISITION: {
        AssessmentPhase.GRAPH_EXPANSION,
        AssessmentPhase.RECURSIVE_INVESTIGATION,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.INDEPENDENT_VERIFICATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.GRAPH_EXPANSION: {
        AssessmentPhase.RECURSIVE_INVESTIGATION,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.PRECONDITION_EVALUATION,
        AssessmentPhase.VALIDATION,
        AssessmentPhase.INDEPENDENT_VERIFICATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.RECURSIVE_INVESTIGATION: {
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.PRECONDITION_EVALUATION,
        AssessmentPhase.VALIDATION,
        AssessmentPhase.CAPABILITY_ACQUISITION,
        AssessmentPhase.GRAPH_EXPANSION,
        AssessmentPhase.INDEPENDENT_VERIFICATION,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.INDEPENDENT_VERIFICATION: {
        AssessmentPhase.OBJECTIVE_EVALUATION,
        AssessmentPhase.FINDING_CORRELATION,
        AssessmentPhase.REPORT,
        AssessmentPhase.REPORTING,
        AssessmentPhase.TERMINAL,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.OBJECTIVE_EVALUATION: {
        AssessmentPhase.REPORT,
        AssessmentPhase.REPORTING,
        AssessmentPhase.TERMINAL,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.TERMINAL: set(),
    AssessmentPhase.INITIALIZING: {
        AssessmentPhase.AUTHORIZATION_CHECK,
        AssessmentPhase.SCOPE_VALIDATION,
        AssessmentPhase.SCOPE,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.INITIALIZE: {
        AssessmentPhase.SCOPE,
        AssessmentPhase.SCOPE_VALIDATION,
        AssessmentPhase.AUTHORIZATION_CHECK,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.AUTHORIZATION_CHECK: {
        AssessmentPhase.SCOPE_VALIDATION,
        AssessmentPhase.SCOPE,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.SCOPE_VALIDATION: {
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.PASSIVE_RECON,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.SCOPE: {
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.PASSIVE_RECON,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.ASSET_DISCOVERY: {
        AssessmentPhase.PASSIVE_RECON,
        AssessmentPhase.APPLICATION_MODELING,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.DISCOVERY: {
        AssessmentPhase.PASSIVE_RECON,
        AssessmentPhase.APPLICATION_MODELING,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.PASSIVE_RECON: {
        AssessmentPhase.APPLICATION_MODELING,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.APPLICATION_MODELING: {
        AssessmentPhase.THREAT_MODELING,
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.IDENTIFICATION: {
        AssessmentPhase.THREAT_MODELING,
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ASSET_DISCOVERY,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.THREAT_MODELING: {
        AssessmentPhase.ATTACK_SURFACE_MAPPING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.ATTACK_SURFACE_MAPPING: {
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.ENUMERATION: {
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.TARGETED_ENUMERATION: {
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ATTACK_PATH_ANALYSIS,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.HYPOTHESIS: {
        AssessmentPhase.PRECONDITION,
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.PRECONDITION: {
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.HYPOTHESIS_GENERATION: {
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.EXPLOITATION: {
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.POST_EXPLOITATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.ACTIVE_TESTING: {
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.ATTACK_PATH_ANALYSIS,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.VERIFICATION: {
        AssessmentPhase.POST_EXPLOITATION,
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.ATTACK_PATH_ANALYSIS,
        AssessmentPhase.RISK_ASSESSMENT,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.HYPOTHESIS_GENERATION,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.IDENTIFICATION,
        AssessmentPhase.DISCOVERY,
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.POST_EXPLOITATION: {
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.EXPLOITATION,
        AssessmentPhase.HYPOTHESIS,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.ATTACK_PATH_ANALYSIS: {
        AssessmentPhase.RISK_ASSESSMENT,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.RISK_ASSESSMENT: {
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.REMEDIATION,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.REPORTING: {
        AssessmentPhase.REMEDIATION,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.REPORT: {
        AssessmentPhase.REMEDIATION,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.REMEDIATION: {
        AssessmentPhase.RETEST,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.RETEST: {
        AssessmentPhase.ACTIVE_TESTING,
        AssessmentPhase.TARGETED_ENUMERATION,
        AssessmentPhase.VERIFICATION,
        AssessmentPhase.REPORTING,
        AssessmentPhase.REPORT,
        AssessmentPhase.COMPLETED,
        AssessmentPhase.COMPLETE,
        AssessmentPhase.FAILED,
        AssessmentPhase.PAUSED,
    },
    AssessmentPhase.COMPLETED: set(),
    AssessmentPhase.COMPLETE: set(),
    AssessmentPhase.PAUSED: set(),
    AssessmentPhase.FAILED: set(),
}

for _p in AssessmentPhase:
    if _p not in (AssessmentPhase.COMPLETED, AssessmentPhase.COMPLETE, AssessmentPhase.PAUSED, AssessmentPhase.FAILED):
        if _p in VALID_TRANSITIONS:
            VALID_TRANSITIONS[_p].add(AssessmentPhase.PAUSED)
            VALID_TRANSITIONS[_p].add(AssessmentPhase.FAILED)
        else:
            VALID_TRANSITIONS[_p] = {AssessmentPhase.PAUSED, AssessmentPhase.FAILED}


def _default_objective(phase: AssessmentPhase) -> str:
    """Default human-readable objective for each phase."""
    objectives = {
        AssessmentPhase.INITIALIZING: "Initializing assessment",
        AssessmentPhase.INITIALIZE: "Initializing assessment",
        AssessmentPhase.AUTHORIZATION_CHECK: "Verifying assessment authorization",
        AssessmentPhase.SCOPE_VALIDATION: "Validating target scope",
        AssessmentPhase.SCOPE: "Defining and validating scope",
        AssessmentPhase.ASSET_DISCOVERY: "Discovering target assets",
        AssessmentPhase.DISCOVERY: "Discovering network surface and services",
        AssessmentPhase.PASSIVE_RECON: "Performing passive reconnaissance",
        AssessmentPhase.APPLICATION_MODELING: "Building application model",
        AssessmentPhase.IDENTIFICATION: "Identifying technologies and vulnerabilities",
        AssessmentPhase.THREAT_MODELING: "Analyzing threat landscape",
        AssessmentPhase.ATTACK_SURFACE_MAPPING: "Mapping attack surface",
        AssessmentPhase.ENUMERATION: "Enumerating discovered service endpoints and capabilities",
        AssessmentPhase.TARGETED_ENUMERATION: "Executing targeted enumeration",
        AssessmentPhase.HYPOTHESIS: "Formulating specific vulnerability hypotheses",
        AssessmentPhase.HYPOTHESIS_GENERATION: "Generating security hypotheses",
        AssessmentPhase.ACTIVE_TESTING: "Executing active security tests",
        AssessmentPhase.EXPLOITATION: "Validating vulnerability hypothesis via authorized proof of concept",
        AssessmentPhase.VERIFICATION: "Verifying candidate findings and proof of compromise",
        AssessmentPhase.POST_EXPLOITATION: "Gathering post-exploitation proof of compromise",
        AssessmentPhase.ATTACK_PATH_ANALYSIS: "Analyzing attack paths",
        AssessmentPhase.RISK_ASSESSMENT: "Assessing risk levels",
        AssessmentPhase.REPORTING: "Generating assessment report",
        AssessmentPhase.REPORT: "Compiling security report",
        AssessmentPhase.REMEDIATION: "Providing remediation guidance",
        AssessmentPhase.RETEST: "Retesting after remediation",
        AssessmentPhase.COMPLETED: "Assessment complete",
        AssessmentPhase.COMPLETE: "Assessment complete",
        AssessmentPhase.PAUSED: "Assessment paused",
        AssessmentPhase.FAILED: "Assessment failed",
    }
    return objectives.get(phase, str(phase.value))



class ServiceState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class HTTPState(str, Enum):
    DISCOVERED = "DISCOVERED"
    RESPONDS = "RESPONDS"
    REFUSED = "REFUSED"
    TIMEOUT = "TIMEOUT"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"


class FailureClassification(str, Enum):
    TIMEOUT = "TIMEOUT"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NETWORK_ERROR = "NETWORK_ERROR"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TARGET_NOT_SUPPORTED = "TARGET_NOT_SUPPORTED"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    WAF_BLOCKED = "WAF_BLOCKED"
    TOOL_FAILURE = "TOOL_FAILURE"
    PARSER_ERROR = "PARSER_ERROR"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    PRECONDITION_UNMET = "PRECONDITION_UNMET"
    NONE = "NONE"


def classify_failure(raw_output: str, exit_code: int = 0) -> FailureClassification:
    """Classifies tool execution error into standardized failure types."""
    lowered = (raw_output or "").lower()

    if exit_code == 124 or "timed out" in lowered or "timeout" in lowered:
        return FailureClassification.TIMEOUT
    if exit_code == 127 or "not found" in lowered or "command not found" in lowered:
        return FailureClassification.DEPENDENCY_MISSING
    if exit_code == 126 or "policy denied" in lowered or "permission denied" in lowered:
        return FailureClassification.PERMISSION_ERROR
    if any(k in lowered for k in ("401 unauthorized", "authorization required", "www-authenticate")):
        return FailureClassification.AUTH_REQUIRED
    if any(k in lowered for k in ("waf", "cloudflare", "blocked by waf", "request blocked", "403 forbidden")):
        return FailureClassification.WAF_BLOCKED
    if any(k in lowered for k in ("err_connection_refused", "connection refused", "failed to connect")):
        return FailureClassification.CONNECTION_REFUSED
    if "target_not_supported" in lowered or "not supported by evidence" in lowered:
        return FailureClassification.TARGET_NOT_SUPPORTED
    if exit_code == 2 or any(k in lowered for k in ("invalid option", "unrecognized option", "parameter is required", "required parameter", "missing required")):
        return FailureClassification.INVALID_ARGUMENT
    if any(k in lowered for k in ("host unreachable", "network is unreachable", "could not resolve host", "name resolution")):
        return FailureClassification.NETWORK_ERROR
    if exit_code != 0 or "failed" in lowered or "error:" in lowered or "stderr:" in lowered:
        return FailureClassification.TOOL_FAILURE
    return FailureClassification.NONE


class HypothesisStatus(str, Enum):
    # Canonical lifecycle states
    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    REFUTED = "REFUTED"
    FAILED = "FAILED"
    ABANDONED = "ABANDONED"
    SUPERSEDED = "SUPERSEDED"

    # Backwards-compatible aliases
    UNTESTED = "PROPOSED"
    TESTING = "ACTIVE"
    EXPLOITING = "VALIDATING"
    VERIFIED = "VALIDATED"
    REJECTED = "ABANDONED"


class CandidateStatus(str, Enum):
    """Lifecycle state of an action candidate."""
    PROPOSED = "PROPOSED"
    PRECONDITIONS_EVALUATING = "PRECONDITIONS_EVALUATING"
    PRECONDITIONS_MET = "PRECONDITIONS_MET"
    PRECONDITIONS_FAILED = "PRECONDITIONS_FAILED"
    SCHEDULED = "SCHEDULED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class VulnerabilityHypothesis:
    """
    Concrete vulnerability hypothesis grounded in verified attack-surface evidence.
    """
    id: str
    target: str
    service: str
    port: int
    vulnerability_type: str  # e.g. "sqli", "command_injection", "path_traversal", "auth_bypass", "rce", "service_exploit"
    rationale: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    suggested_tools: List[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    attempt_count: int = 0
    verified: bool = False
    proof_of_compromise: str = ""
    capability_context: str = ""
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    @property
    def identity(self) -> str:
        """Stable hypothesis identity."""
        return f"{self.target}::{self.service}::{self.port}::{self.vulnerability_type}::{self.capability_context}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "service": self.service,
            "port": self.port,
            "vulnerability_type": self.vulnerability_type,
            "rationale": self.rationale,
            "evidence_ids": list(self.evidence_ids),
            "suggested_tools": list(self.suggested_tools),
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "attempt_count": self.attempt_count,
            "verified": self.verified,
            "proof_of_compromise": self.proof_of_compromise,
            "capability_context": self.capability_context,
            "identity": self.identity,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityHypothesis":
        st_val = data.get("status", "ACTIVE")
        try:
            status_enum = HypothesisStatus(st_val) if st_val in HypothesisStatus._value2member_map_ else HypothesisStatus.ACTIVE
        except Exception:
            status_enum = HypothesisStatus.ACTIVE
        return cls(
            id=data.get("id", ""),
            target=data.get("target", ""),
            service=data.get("service", ""),
            port=int(data.get("port", 0)),
            vulnerability_type=data.get("vulnerability_type", ""),
            rationale=data.get("rationale", ""),
            evidence_ids=list(data.get("evidence_ids", [])),
            suggested_tools=list(data.get("suggested_tools", [])),
            status=status_enum,
            attempt_count=int(data.get("attempt_count", 0)),
            verified=bool(data.get("verified", False)),
            proof_of_compromise=str(data.get("proof_of_compromise", "") or ""),
            capability_context=str(data.get("capability_context", "") or ""),
            created_at=str(data.get("created_at", "") or time.strftime("%Y-%m-%d %H:%M:%S")),
        )


class ExploitStatus(str, Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    VERIFIED = "VERIFIED"


@dataclass
class ExploitationRecord:
    """
    Audit record of an exploitation action attempt in authorized security labs.
    """
    hypothesis_id: str
    tool_name: str
    target: str
    port: int
    arguments: Dict[str, Any] = field(default_factory=dict)
    status: ExploitStatus = ExploitStatus.PENDING
    failure_reason: str = ""
    evidence_id: str = ""
    verified: bool = False
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "port": self.port,
            "arguments": {k: str(v) for k, v in self.arguments.items()},
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "failure_reason": self.failure_reason,
            "evidence_id": self.evidence_id,
            "verified": self.verified,
            "timestamp": self.timestamp,
        }


@dataclass
class ExploitPrecondition:
    """Preconditions required before an exploitation action may be scheduled."""
    require_open_port: bool = True
    require_http_state_responds: bool = False
    require_service_match: Optional[str] = None
    require_evidence_ids: List[str] = field(default_factory=list)
    require_endpoint_path: Optional[str] = None
    disallow_if_failed_before: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "require_open_port": self.require_open_port,
            "require_http_state_responds": self.require_http_state_responds,
            "require_service_match": self.require_service_match,
            "require_evidence_ids": list(self.require_evidence_ids),
            "require_endpoint_path": self.require_endpoint_path,
            "disallow_if_failed_before": self.disallow_if_failed_before,
        }


@dataclass
class ExploitCandidate:
    """
    Explicit precondition and planning object for an authorized lab exploitation action.
    Represents the full pre-execution contract:
    Hypothesis -> Evidence sufficient -> Required conditions satisfied -> Correct tool -> Execute -> Verify.
    """
    target: str
    service: str
    port: int
    vulnerability_hypothesis: VulnerabilityHypothesis
    evidence_ids: List[str] = field(default_factory=list)
    required_conditions: ExploitPrecondition = field(default_factory=ExploitPrecondition)
    confidence: float = 1.0
    allowed_tool: str = "http.request"
    tool_arguments: Dict[str, Any] = field(default_factory=dict)
    verification_plan: str = "Inspect response for proof of compromise (FLAG{...}, admin session, or command output)."
    candidate_id: str = field(default_factory=lambda: f"CAND-{uuid.uuid4().hex[:8]}")
    status: CandidateStatus = CandidateStatus.PROPOSED

    @property
    def hypothesis_id(self) -> str:
        return self.vulnerability_hypothesis.id if self.vulnerability_hypothesis else ""

    def evaluate_preconditions(self, state: "AssessmentState") -> Tuple[bool, str]:
        """
        Authoritatively checks whether all required conditions and evidence are satisfied
        in canonical AssessmentState before execution is permitted.
        """
        self.status = CandidateStatus.PRECONDITIONS_EVALUATING
        clean_host = self.target.split("://")[-1].split("/")[0].split(":")[0]

        # 1. Target scope authorization
        is_valid, msg, _ = TargetValidator.validate_target(self.target, state.context)
        if not is_valid:
            self.status = CandidateStatus.PRECONDITIONS_FAILED
            return False, f"Target out of scope or invalid: {msg}"

        # 2. Port open check
        if self.required_conditions.require_open_port:
            open_ports = state.get_open_ports(clean_host)
            if state.has_discovered_ports(clean_host) and open_ports and self.port not in open_ports:
                self.status = CandidateStatus.PRECONDITIONS_FAILED
                return False, f"Required condition failed: Port {self.port} is not open on {clean_host}. Verified ports: {open_ports}."

        # 3. HTTP state responds check
        if self.required_conditions.require_http_state_responds:
            ep_key = f"{clean_host}:{self.port}"
            if ep_key in state.http_endpoints:
                if state.http_endpoints[ep_key].state not in (HTTPState.RESPONDS, HTTPState.UNKNOWN):
                    self.status = CandidateStatus.PRECONDITIONS_FAILED
                    return False, f"Required condition failed: HTTP endpoint on {clean_host}:{self.port} is in state {state.http_endpoints[ep_key].state.value}."

        # 4. Service match check
        if self.required_conditions.require_service_match:
            srv = state.get_service(clean_host, self.port)
            if srv and self.required_conditions.require_service_match.lower() not in srv.service.lower():
                self.status = CandidateStatus.PRECONDITIONS_FAILED
                return False, f"Required condition failed: Service '{srv.service}' does not match required '{self.required_conditions.require_service_match}'."

        # 5. Evidence grounding check
        if self.required_conditions.require_evidence_ids:
            missing_evidence = [eid for eid in self.required_conditions.require_evidence_ids if not eid]
            if missing_evidence:
                self.status = CandidateStatus.PRECONDITIONS_FAILED
                return False, f"Required condition failed: Missing required evidence IDs {missing_evidence}."

        # 6. Repetitive failure check
        if self.required_conditions.disallow_if_failed_before:
            call_sig = f"{self.allowed_tool}:{json.dumps(self.tool_arguments, sort_keys=True)}"
            if call_sig in state.attempted_action_keys or any(a.get("action_sig") == call_sig for a in state.failed_actions):
                self.status = CandidateStatus.PRECONDITIONS_FAILED
                return False, f"Required condition failed: Identical exploit execution previously failed."

        self.status = CandidateStatus.PRECONDITIONS_MET
        return True, "All exploit preconditions satisfied."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "target": self.target,
            "service": self.service,
            "port": self.port,
            "vulnerability_hypothesis": self.vulnerability_hypothesis.to_dict(),
            "evidence_ids": list(self.evidence_ids),
            "required_conditions": self.required_conditions.to_dict(),
            "confidence": self.confidence,
            "allowed_tool": self.allowed_tool,
            "tool_arguments": {k: str(v) for k, v in self.tool_arguments.items()},
            "verification_plan": self.verification_plan,
        }



@dataclass(frozen=True)

class AssessmentContext:
    """Canonical, immutable assessment context."""
    target: str = "localhost"
    scope: Tuple[str, ...] = ("localhost", "127.0.0.1")
    objective: str = "Assess the exposed services and produce a report"
    target_known: bool = True
    objective_known: bool = True
    scope_known: bool = True
    predicates: Optional["VerificationPredicates"] = None

    def format_summary(self) -> str:
        scope_str = ", ".join(self.scope)
        return (
            f"=== CANONICAL ASSESSMENT CONTEXT ===\n"
            f"Target: {self.target}\n"
            f"Scope: {scope_str}\n"
            f"Objective: {self.objective}\n"
            f"Status: Target, Scope, and Objective are locked and authorized. NEVER ask the user to clarify or re-state them."
        )


@dataclass
class ServiceRecord:
    """
    Canonical record of a network service on a host.
    Strictly differentiates verified versions from unproven inferences.
    """
    host: str
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    version: str = "UNKNOWN"
    state: ServiceState = ServiceState.OPEN
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 1.0
    verification_status: VerificationStatus = VerificationStatus.INFERRED
    http_state: HTTPState = HTTPState.UNKNOWN
    banner: str = ""
    notes: List[str] = field(default_factory=list)
    investigated: bool = False

    def is_http_compatible(self) -> bool:
        srv = self.service.lower()
        if any(h in srv for h in ("http", "https", "web", "ssl/http", "ws", "ipp")):
            return True
        if self.port in (80, 443, 8080, 8443, 8000, 8384, 8888, 3000, 5000, 9000, 11434, 631):
            return True
        return False

    def is_http(self) -> bool:
        return self.is_http_compatible()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "state": self.state.value if hasattr(self.state, "value") else str(self.state),
            "evidence_ids": self.evidence_ids,
            "confidence": self.confidence,
            "verification_status": self.verification_status.value if hasattr(self.verification_status, "value") else str(self.verification_status),
            "http_state": self.http_state.value if hasattr(self.http_state, "value") else str(self.http_state),
            "banner": self.banner,
            "investigated": self.investigated
        }


@dataclass
class HTTPEndpointRecord:
    """
    Canonical record of an HTTP endpoint and its verified reachability state.
    """
    url: str
    host: str
    port: int
    path: str = "/"
    method: str = "GET"
    state: HTTPState = HTTPState.UNKNOWN
    status_code: Optional[int] = None
    title: str = ""
    server_header: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    last_tested: float = field(default_factory=time.time)
    requires_auth: bool = False

    def is_online(self) -> bool:
        return self.state == HTTPState.RESPONDS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "state": self.state.value if hasattr(self.state, "value") else str(self.state),
            "status_code": self.status_code,
            "title": self.title,
            "server_header": self.server_header,
            "evidence_ids": self.evidence_ids
        }


@dataclass
class ActionMetadata:
    """Auditable metadata explaining why an action was selected and on what evidence basis."""
    tool: str
    target: str
    reason: str
    evidence_basis: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))
    duration: float = 0.0
    status: str = "SUCCESS"  # SUCCESS or FAILED
    error_type: str = "none"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "evidence_basis": self.evidence_basis,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "status": self.status,
            "error_type": self.error_type
        }


@dataclass
class StateTransition:
    from_phase: AssessmentPhase
    to_phase: AssessmentPhase
    reason: str
    tool: Optional[str] = None


class TargetValidationResult(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED_PLACEHOLDER = "BLOCKED_PLACEHOLDER"
    BLOCKED_OUT_OF_SCOPE = "BLOCKED_OUT_OF_SCOPE"
    BLOCKED_UNSUPPORTED = "BLOCKED_UNSUPPORTED"


@dataclass
class TargetDriftRecord:
    canonical_target: str
    requested_target: str
    tool_name: str
    validation_result: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canonical_target": self.canonical_target,
            "requested_target": self.requested_target,
            "tool_name": self.tool_name,
            "validation_result": self.validation_result,
            "timestamp": self.timestamp
        }


KNOWN_PLACEHOLDERS = {
    "<target>", "<TARGET>", "<target_url>", "<TARGET_URL>", "<host>", "<HOST>",
    "<target_ip>", "<TARGET_IP>", "<ip>", "<IP>", "<url>", "<URL>", "<target.com>",
    "target", "TARGET", "example.com", "target.example.com", "localhost.example",
    "your_target", "victim.com", "target.com", "target_ip", "TARGET_HOST",
    "target-host", "example.org", "example.net", "test.com", "my_target", "some_target"
}


class TargetValidator:
    """
    Authoritative validator for candidate target strings.
    Strictly forbids placeholder arguments and unauthorized target drift.
    """
    @classmethod
    def validate_target(
        cls,
        requested_target: str,
        context: AssessmentContext
    ) -> Tuple[bool, str, TargetValidationResult]:
        """
        Validates candidate target against immutable AssessmentContext:
        1. Rejects placeholders (<target>, target.com, example.com)
        2. Blocks out-of-scope targets
        3. Permits valid authorized targets
        """
        raw_str = (requested_target or "").strip()
        if not raw_str:
            return (True, "No target parameter specified", TargetValidationResult.ALLOWED)

        lowered = raw_str.lower()

        # 1. Placeholder Check
        if (
            lowered in KNOWN_PLACEHOLDERS
            or (raw_str.startswith("<") and raw_str.endswith(">"))
            or lowered.startswith("<target")
            or lowered.startswith("<host")
        ):
            if raw_str not in context.scope and lowered not in [s.lower() for s in context.scope]:
                msg = (
                    f"ACTION BLOCKED\n\n"
                    f"Requested target:\n{raw_str}\n\n"
                    f"Canonical target:\n{context.target}\n\n"
                    f"Reason:\nINVALID_TARGET_PLACEHOLDER\n\n"
                    f"Guidance:\nDo not use placeholder strings like '{raw_str}'. Target is locked to canonical target '{context.target}'."
                )
                return (False, msg, TargetValidationResult.BLOCKED_PLACEHOLDER)

        # 2. Extract host component
        clean_host = raw_str.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
        if not clean_host:
            return (True, "Local parameter", TargetValidationResult.ALLOWED)

        # Check if host component is a known placeholder
        if clean_host in KNOWN_PLACEHOLDERS:
            if clean_host not in [s.lower() for s in context.scope]:
                msg = (
                    f"ACTION BLOCKED\n\n"
                    f"Requested target:\n{raw_str}\n\n"
                    f"Canonical target:\n{context.target}\n\n"
                    f"Reason:\nINVALID_TARGET_PLACEHOLDER\n\n"
                    f"Guidance:\nDo not use placeholder host '{clean_host}'. Target is locked to canonical target '{context.target}'."
                )
                return (False, msg, TargetValidationResult.BLOCKED_PLACEHOLDER)

        # 3. Authorized Scope Check
        auth_scopes = set()
        for s in context.scope:
            h = s.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
            auth_scopes.add(h)
            auth_scopes.add(s.strip().lower())

        canon_h = context.target.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
        auth_scopes.add(canon_h)
        auth_scopes.add(context.target.strip().lower())

        if clean_host not in auth_scopes:
            msg = (
                f"ACTION BLOCKED\n\n"
                f"Requested target:\n{raw_str}\n\n"
                f"Canonical target:\n{context.target}\n\n"
                f"Reason:\nTARGET_OUT_OF_SCOPE\n\n"
                f"Guidance:\nTarget '{clean_host}' is outside the authorized scope: {list(context.scope)}. Target is locked to canonical target '{context.target}'."
            )
            return (False, msg, TargetValidationResult.BLOCKED_OUT_OF_SCOPE)

        return (True, "Target authorized within scope", TargetValidationResult.ALLOWED)


class CandidateActionValidator:
    """
    Validates candidate actions before execution:
    1. Target Authorization & Placeholder Rejection
    2. Schema & Required Arguments Validation
    3. Action Eligibility Layer (Prevents tools targeting undiscovered/unverified ports)
    4. Evidence Justification
    """
    DISCOVERY_TOOLS = {
        "nmap_scan", "ping_host", "scan_ports", "service_inventory",
        "dns_query", "dns_lookup", "dns_reverse_lookup", "whois_lookup",
        "subdomain_enum", "terminal_execute", "terminal.execute",
        "file_identify", "grep", "glob", "file_metadata", "static_analysis",
        "complete", "finish_task", "record_command", "save_artifact", "create_report",
        "audit_android_manifest", "audit_mobile_storage", "audit_api_spec", "remediate",
        # New canonical discovery suites
        "dns_records", "reverse_dns", "resolve_hostname", "scan_common_ports",
        "service_detect", "grab_banner", "route_trace", "arp_discovery", "subnet_discovery",
        "dns_mx_check", "dns_txt_check", "dns_spf_check", "dns_dkim_check", "dns_dmarc_check",
        "dnssec_check", "zone_transfer_check", "asn_lookup", "ip_info", "domain_info",
        "email_pattern_check", "technology_detect", "tls_version_check", "tls_cipher_check",
        "certificate_inspect", "certificate_expiry", "certificate_chain", "certificate_hostname"
    }

    TARGETED_HTTP_TOOLS = {
        "http.request", "http_request", "browser.open", "browser.goto", "whatweb_scan",
        "nikto_scan", "gobuster", "gobuster_dir", "ffuf_fuzz", "sqlmap_attack",
        "dirb_scan", "wpscan", "brute_force_http", "check_headers",
        "evaluate_security_headers", "check_cors_configuration", "cors_check",
        "probe_parameter_injection", "dir_bruteforce", "api_discovery",
        "ssrf_scan", "lfi_scan", "sqli_scan", "xss_scan", "cmd_injection_scan",
        "vuln_scan", "http_method_map", "http_login_brute", "http_probe",
        "http_methods", "redirect_check", "robots_check", "security_txt_check",
        "tech_fingerprint", "cookie_audit", "directory_probe", "web_endpoint_probe"
    }

    EXPLOITATION_TOOLS = {
        "sqlmap_attack", "brute_force_http", "http_login_brute",
        "generic_service_brute", "ssh_brute", "ftp_brute", "smtp_brute",
        "pop3_brute", "imap_brute", "telnet_brute", "payload_generate",
        "reverse_shell_payload", "cmd_injection_scan", "sqli_scan",
        "lfi_scan", "xss_scan", "ssrf_scan"
    }

    TARGET_PARAM_KEYS = ("host", "target", "url", "domain", "ip", "base_url", "cidr", "ip_or_asn")


    LOCAL_ONLY_TOOLS = {
        "calculator", "get_time", "finish_task", "complete", "lab_echo", "lab_probe",
        "python_executor", "crack_hash", "crack_zip", "crack_file", "wordlist_gen",
        "hash_identify", "hash_generate", "jwt_decode", "jwt_crack", "crypto_analyze",
        "decode_obfuscation", "web_search", "file_identify", "file_metadata",
        "strings_extract", "static_analysis", "scan_source_secrets", "secret_scan",
        "audit_configurations", "audit_mobile_storage", "audit_android_manifest",
        "audit_api_spec", "openapi_parse", "cloud_scan", "cloud_iam", "iac_scan",
        "k8s_scan", "cve_scan", "code_audit", "edit_file", "glob", "grep",
        "file.read", "file.write", "file.list", "file.search", "log_finding",
        "log_evidence", "record_command", "save_artifact", "create_report",
        "knowledge_dump", "select_next",
        # New local inspection and analysis suites
        "process_list", "listening_ports", "network_interfaces", "routing_table",
        "system_info", "environment_info", "file_hash", "directory_inventory",
        "permissions_check", "hash_compare", "file_type", "metadata_extract",
        "entropy_check", "archive_inspect", "pe_inspect", "elf_inspect", "yara_scan",
        "log_search", "log_summary", "ioc_extract", "ioc_match", "indicator_normalize",
        "hash_lookup", "ip_reputation", "domain_reputation", "url_reputation",
        "file_read", "file_write", "file_search", "directory_list"
    }

    @classmethod
    def validate_candidate(
        cls,
        tool_name: str,
        args: Dict[str, Any],
        state: "AssessmentState"
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates candidate tool and parameters against current AssessmentState.
        Returns (is_valid, rationale_or_error, normalized_args).
        """
        norm_args = dict(args or {})

        # 1. Target Authorization & Placeholder Rejection
        if tool_name not in cls.LOCAL_ONLY_TOOLS:
            req_target = ""
            for k in cls.TARGET_PARAM_KEYS:
                if norm_args.get(k):
                    req_target = str(norm_args[k]).strip()
                    break

            if req_target:
                is_valid_target, target_msg, val_res = TargetValidator.validate_target(
                    requested_target=req_target,
                    context=state.context
                )
                if not is_valid_target:
                    # Record target drift in canonical state
                    state.record_target_drift(
                        requested_target=req_target,
                        tool_name=tool_name,
                        validation_result=val_res.value
                    )
                    return (False, target_msg, norm_args)

        # 2. Schema & Parameter Validation
        if tool_name == "scan_ports":
            ports = norm_args.get("ports")
            if not ports or str(ports).strip() in ("", "none", "null"):
                return (
                    False,
                    'ACTION REJECTED: Tool "scan_ports" requires parameter "ports" (e.g. "22,80,443" or "1-50").',
                    norm_args
                )
            if not norm_args.get("host"):
                norm_args["host"] = state.context.target

        elif tool_name == "grab_banner":
            port = norm_args.get("port")
            if not port:
                uninv = [s.port for s in state.get_uninvestigated_services()]
                if uninv:
                    norm_args["port"] = uninv[0]
                else:
                    return (
                        False,
                        'ACTION REJECTED: Tool "grab_banner" requires parameter "port".',
                        norm_args
                    )
            if not norm_args.get("host"):
                norm_args["host"] = state.context.target

        elif tool_name in ("nmap_scan", "ping_host", "service_inventory", "ssl_check", "dns_lookup"):
            if not norm_args.get("host"):
                raw_h = norm_args.get("target") or norm_args.get("url") or norm_args.get("param_name") or state.context.target
                norm_args["host"] = str(raw_h).split("://")[-1].split("/")[0].split(":")[0]

        # 3. Action Eligibility Layer: Target Justification & Evidence Check for Web Tools
        if tool_name in cls.TARGETED_HTTP_TOOLS:
            url_or_target = str(norm_args.get("url") or norm_args.get("target") or norm_args.get("host") or state.context.target)
            target_host = url_or_target.split("://")[-1].split("/")[0].split(":")[0]

            # Extract targeted port
            port = 80
            if "https://" in url_or_target:
                port = 443
            if ":" in url_or_target.split("://")[-1].split("/")[0]:
                try:
                    port = int(url_or_target.split("://")[-1].split("/")[0].split(":")[1])
                except Exception:
                    pass

            # Check if this port was recorded as CLOSED / REFUSED
            srv = state.get_service(target_host, port)
            if srv and (srv.state in (ServiceState.CLOSED, ServiceState.UNAVAILABLE) or srv.http_state == HTTPState.REFUSED):
                return (
                    False,
                    f"ACTION BLOCKED\n\n"
                    f"Requested tool:\n{tool_name}\n\n"
                    f"Target:\n{target_host}:{port}\n\n"
                    f"Reason:\nHTTP_SERVICE_NOT_ESTABLISHED\n\n"
                    f"Evidence:\nHTTP connection to {target_host}:{port} was previously REFUSED. Port {port} is offline.\n\n"
                    f"Guidance:\nExecute service discovery (nmap_scan / service_inventory) to discover open services before calling web tools.",
                    norm_args
                )

            # Check if previous probe recorded CONNECTION_REFUSED against this specific port/endpoint
            for action in state.failed_actions:
                if action.get("failure_type") in (FailureClassification.CONNECTION_REFUSED, "CONNECTION_REFUSED"):
                    act_args = action.get("args") or {}
                    act_u = str(act_args.get("url") or action.get("target") or "")
                    act_p = 80
                    if ":" in act_u.split("://")[-1].split("/")[0]:
                        try:
                            act_p = int(act_u.split("://")[-1].split("/")[0].split(":")[1])
                        except Exception:
                            pass
                    elif "https://" in act_u:
                        act_p = 443
                    if port == act_p and (target_host in act_u or target_host == str(action.get("target"))):
                        # But if this port was later discovered OPEN, allow it
                        if srv and srv.state == ServiceState.OPEN:
                            continue
                        return (
                            False,
                            f"ACTION BLOCKED\n\n"
                            f"Requested tool:\n{tool_name}\n\n"
                            f"Target:\n{target_host}:{port}\n\n"
                            f"Reason:\nHTTP_SERVICE_NOT_ESTABLISHED\n\n"
                            f"Evidence:\nHTTP connection to {target_host}:{port} was previously REFUSED.\n\n"
                            f"Guidance:\nExecute service discovery (nmap_scan / service_inventory) to find verified open services.",
                            norm_args
                        )

            # If ports have been discovered on this host, ensure this port was actually verified open
            open_ports = state.get_open_ports(target_host)
            if state.has_discovered_ports(target_host):
                if port not in open_ports:
                    return (
                        False,
                        f"ACTION BLOCKED\n\n"
                        f"Requested tool:\n{tool_name}\n\n"
                        f"Target:\n{target_host}:{port}\n\n"
                        f"Reason:\nTARGET_NOT_SUPPORTED_BY_EVIDENCE (HTTP_SERVICE_NOT_ESTABLISHED)\n\n"
                        f"Evidence:\nPort {port} has not been verified open on {target_host}. Verified open ports: {open_ports}.\n\n"
                        f"Guidance:\nTarget only verified open ports. Do not target closed or undiscovered ports.",
                        norm_args
                    )

                # Check service compatibility
                if srv and srv.service.lower() not in ("unknown", "http", "https", "web", "ipp", "ssl/http") and not srv.is_http_compatible():
                    return (
                        False,
                        f"ACTION BLOCKED\n\n"
                        f"Requested tool:\n{tool_name}\n\n"
                        f"Target:\n{target_host}:{port}\n\n"
                        f"Reason:\nNOT_ELIGIBLE\n\n"
                        f"Evidence:\nPort {port} is identified as non-HTTP service '{srv.service}'.\n\n"
                        f"Guidance:\nUse service-specific tools for '{srv.service}' rather than generic HTTP tools.",
                        norm_args
                    )

        # 4. Action Eligibility Layer: Evidence & Scope Justification for Exploitation Tools
        if tool_name in cls.EXPLOITATION_TOOLS:
            url_or_target = str(norm_args.get("url") or norm_args.get("target") or norm_args.get("host") or state.context.target)
            target_host = url_or_target.split("://")[-1].split("/")[0].split(":")[0]

            port = 80
            if "https://" in url_or_target:
                port = 443
            elif ":" in url_or_target.split("://")[-1].split("/")[0]:
                try:
                    port = int(url_or_target.split("://")[-1].split("/")[0].split(":")[1])
                except Exception:
                    pass
            elif norm_args.get("port"):
                try:
                    port = int(norm_args["port"])
                except Exception:
                    pass

            # Check if any ports have been discovered on this host
            if not state.has_discovered_ports(target_host) and not state.services:
                return (
                    False,
                    f"ACTION BLOCKED\n\n"
                    f"Requested tool:\n{tool_name}\n\n"
                    f"Target:\n{target_host}\n\n"
                    f"Reason:\nEXPLOITATION_REQUIRES_EVIDENCE\n\n"
                    f"Evidence:\nNo open ports or services have been discovered on {target_host}.\n\n"
                    f"Guidance:\nPerform DISCOVERY (e.g. nmap_scan) to identify exposed services before attempting exploitation.",
                    norm_args
                )

            # Targeted port must be verified open if ports are mapped
            open_ports = state.get_open_ports(target_host)
            if state.has_discovered_ports(target_host) and open_ports and port not in open_ports:
                return (
                    False,
                    f"ACTION BLOCKED\n\n"
                    f"Requested tool:\n{tool_name}\n\n"
                    f"Target:\n{target_host}:{port}\n\n"
                    f"Reason:\nTARGET_PORT_NOT_OPEN\n\n"
                    f"Evidence:\nPort {port} is not verified open on {target_host}. Verified open ports: {open_ports}.\n\n"
                    f"Guidance:\nTarget only verified open services.",
                    norm_args
                )

            # Prevent identical repetitive attempts
            call_sig = f"{tool_name}:{json.dumps(norm_args, sort_keys=True)}"
            if call_sig in state.attempted_action_keys or any(a.get("action_sig") == call_sig for a in state.failed_actions):
                return (
                    False,
                    f"ACTION BLOCKED\n\n"
                    f"Requested tool:\n{tool_name}\n\n"
                    f"Reason:\nDUPLICATE_EXPLOIT_ATTEMPT\n\n"
                    f"Evidence:\nAn identical exploit action has already been executed.\n\n"
                    f"Guidance:\nFormulate an alternative exploit hypothesis or adjust parameters.",
                    norm_args
                )

        return (True, "Candidate action validated successfully against AssessmentState", norm_args)



@dataclass
class AssessmentState:
    """
    Authoritative canonical assessment state storing ground-truth facts,
    verified service inventory, HTTP endpoint states, lifecycle phases, and action tracking.
    """
    context: AssessmentContext = field(default_factory=AssessmentContext)
    current_phase: AssessmentPhase = AssessmentPhase.INITIALIZING
    previous_phase: Optional[AssessmentPhase] = None
    current_objective: str = "Initializing assessment"
    hypothesis_count: int = 0
    tested_count: int = 0
    verified_count: int = 0
    rejected_count: int = 0
    pending_count: int = 0
    phase_history: List[str] = field(default_factory=list)
    history: List[StateTransition] = field(default_factory=list)
    tool_failure_counts: Dict[str, int] = field(default_factory=dict)
    failed_actions: List[Dict[str, Any]] = field(default_factory=list)
    attempted_action_keys: Set[str] = field(default_factory=set)
    services: Dict[str, ServiceRecord] = field(default_factory=dict) # key: "host:port/protocol"
    http_endpoints: Dict[str, HTTPEndpointRecord] = field(default_factory=dict) # key: url or "host:port"
    forms: Dict[str, Any] = field(default_factory=dict) # key: form_id or action
    websockets: Dict[str, Any] = field(default_factory=dict) # key: url
    dom_snapshots: Dict[str, Any] = field(default_factory=dict) # key: snapshot_id
    hypotheses: Dict[str, VulnerabilityHypothesis] = field(default_factory=dict) # key: hypothesis id
    exploitation_records: List[ExploitationRecord] = field(default_factory=list)
    pending_actions: List[Dict[str, Any]] = field(default_factory=list)
    completed_actions: List[Dict[str, Any]] = field(default_factory=list)
    blocked_actions: List[Dict[str, Any]] = field(default_factory=list)
    action_metadata_log: List[ActionMetadata] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    credentials: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    information_gain_history: List[Dict[str, Any]] = field(default_factory=list)
    blocked_targets: Set[str] = field(default_factory=set)
    target_drift_log: List[TargetDriftRecord] = field(default_factory=list)
    contradictions: List[Dict[str, Any]] = field(default_factory=list)
    scan_status: str = "pending"  # "pending", "in_progress", "complete", "incomplete", "timeout"
    max_tool_retries: int = 2
    state_version: int = 1

    # Explicit Objective and Verification Tracking
    objective_status: ObjectiveStatus = ObjectiveStatus.OBJECTIVE_UNREACHED
    validation_attempted: bool = False
    validation_tool_success: bool = False
    objective_achieved: bool = False
    verification_started: bool = False
    verification_success: bool = False
    report_generated: bool = False
    time_to_validation: Optional[float] = None
    time_to_verification: Optional[float] = None
    time_to_objective: Optional[float] = None
    tools_to_objective: Optional[int] = None

    # Phase 6F Actionable Verification Candidates & Metrics
    verification_candidates: List[Dict[str, Any]] = field(default_factory=list)
    verification_selected: int = 0
    verification_attempts: int = 0
    session_credentials: Dict[str, str] = field(default_factory=dict)
    session_store: Any = None
    last_validation_output: str = ""
    proof_markers: List[str] = field(default_factory=list)
    objective_history: List[Dict[str, Any]] = field(default_factory=list)
    predicates: "VerificationPredicates" = field(default_factory=lambda: VerificationPredicates())

    def __post_init__(self):
        if self.context and getattr(self.context, "predicates", None):
            self.predicates = self.context.predicates


    # Phase 10 Decision Attribution & Autonomy Metrics
    decision_records: List[Any] = field(default_factory=list)
    autonomy_mode: str = "ASSISTED"
    completion_mode: str = "TARGETED"
    operational_mode: str = "ASSESSMENT"
    hypotheses_considered: int = 0
    hypotheses_selected: int = 0
    hypotheses_refuted: int = 0
    hypotheses_abandoned: int = 0
    hypotheses_reopened: int = 0

    def set_operational_mode(self, mode: str) -> None:
        """Sets the operational mode (CHAT, RESEARCH, ASSESSMENT)."""
        val = str(mode).strip().upper()
        if val in ("ASSESSMENT", "SECURITY_ASSESSMENT"):
            self.operational_mode = "ASSESSMENT"
        elif val == "RESEARCH":
            self.operational_mode = "RESEARCH"
        elif val == "CHAT":
            self.operational_mode = "CHAT"
        else:
            self.operational_mode = val

    def guard_operational_mode(self, operation: str) -> None:
        """Enforces strict operational mode isolation on assessment state mutations."""
        mode = getattr(self, "operational_mode", "ASSESSMENT")
        if mode == "CHAT":
            from security_agent.agent.mode_isolation import ModeIsolationViolation
            raise ModeIsolationViolation(
                f"Operational mode is CHAT: assessment state mutation '{operation}' is forbidden."
            )
        if mode == "RESEARCH":
            if operation in ("record_finding", "record_capability", "record_evidence"):
                from security_agent.agent.mode_isolation import ModeIsolationViolation
                raise ModeIsolationViolation(
                    f"Operational mode is RESEARCH: assessment mutation '{operation}' is forbidden. "
                    "Research outputs cannot mutate active assessment state."
                )

    def record_decision(self, decision: Any) -> None:
        """Appends an auditable decision record to state history."""
        self.decision_records.append(decision)
        self.state_version += 1

    @property
    def validation_success(self) -> bool:
        return self.validation_tool_success

    @validation_success.setter
    def validation_success(self, val: bool) -> None:
        self.validation_tool_success = val


    @property
    def phase(self) -> AssessmentPhase:
        """Compatibility property for current_phase."""
        return self.current_phase

    @phase.setter
    def phase(self, val: AssessmentPhase) -> None:
        self.current_phase = val

    def record_target_drift(self, requested_target: str, tool_name: str, validation_result: str) -> None:
        """Records an attempted target drift and stores in audit log."""
        self.blocked_targets.add(requested_target)
        drift = TargetDriftRecord(
            canonical_target=self.context.target,
            requested_target=requested_target,
            tool_name=tool_name,
            validation_result=validation_result
        )
        self.target_drift_log.append(drift)
        self.state_version += 1

    def is_in_scope(self, target: str) -> bool:
        """Validates whether target is authorized under assessment context scope."""
        if not target:
            return False
        if not self.context.scope:
            return True
        try:
            from security_agent.security.scope import is_in_scope
            return is_in_scope(target, self.context.scope)
        except Exception:
            clean_tgt = target.split("://")[-1].split("/")[0].split(":")[0].lower()
            return any(clean_tgt in s.lower() for s in self.context.scope)

    def _service_key(self, host: str, port: int, protocol: str = "tcp") -> str:
        clean_host = host.split("://")[-1].split("/")[0].split(":")[0]
        return f"{clean_host}:{port}/{protocol.lower()}"

    def transition(
        self,
        to_phase: AssessmentPhase,
        reason: str = "",
        tool: Optional[str] = None,
        objective: str = ""
    ) -> bool:
        """
        Attempt to transition to a new methodology phase.
        Returns True if the transition is valid and was applied, False otherwise.
        """
        self.guard_operational_mode("transition_phase")

        # Handle same-phase noop
        if to_phase == self.current_phase:
            if reason or objective:
                self.current_objective = objective or reason
            return True

        # Check valid forward transitions matrix if defined
        valid_next = VALID_TRANSITIONS.get(self.current_phase)
        if valid_next is not None and to_phase not in valid_next:
            return False

        self.previous_phase = self.current_phase
        self.current_phase = to_phase
        obj_text = objective or reason or _default_objective(to_phase)
        self.current_objective = obj_text

        transition_obj = StateTransition(
            from_phase=self.previous_phase,
            to_phase=to_phase,
            reason=reason or obj_text,
            tool=tool
        )
        self.history.append(transition_obj)
        self.phase_history.append(to_phase.value)
        self.state_version += 1
        return True

    def pause(self) -> bool:
        """Pause the assessment, remembering current phase for resume."""
        if self.current_phase in (AssessmentPhase.COMPLETED, AssessmentPhase.COMPLETE, AssessmentPhase.FAILED):
            return False
        self.previous_phase = self.current_phase
        self.current_phase = AssessmentPhase.PAUSED
        self.current_objective = "Assessment paused"
        self.phase_history.append(AssessmentPhase.PAUSED.value)
        self.state_version += 1
        return True

    def resume(self) -> bool:
        """Resume from pause, restoring the previous phase."""
        if self.current_phase != AssessmentPhase.PAUSED or self.previous_phase is None:
            return False
        self.current_phase = self.previous_phase
        self.previous_phase = None
        self.current_objective = _default_objective(self.current_phase)
        self.phase_history.append(self.current_phase.value)
        self.state_version += 1
        return True

    def record_service(
        self,
        host: str,
        port: int,
        service: str = "unknown",
        protocol: str = "tcp",
        version: str = "UNKNOWN",
        state: ServiceState = ServiceState.OPEN,
        evidence_id: str = "",
        banner: str = "",
        confidence: float = 1.0,
        verification_status: VerificationStatus = VerificationStatus.INFERRED
    ) -> ServiceRecord:
        """Adds or updates a canonical service record."""
        key = self._service_key(host, port, protocol)
        clean_host = host.split("://")[-1].split("/")[0].split(":")[0]

        if key in self.services:
            rec = self.services[key]
            rec.service = service if service != "unknown" else rec.service
            if version and version != "UNKNOWN":
                rec.version = version
                rec.verification_status = verification_status
            rec.state = state
            if evidence_id and evidence_id not in rec.evidence_ids:
                rec.evidence_ids.append(evidence_id)
            if banner:
                rec.banner = banner
        else:
            rec = ServiceRecord(
                host=clean_host,
                port=port,
                protocol=protocol,
                service=service,
                version=version,
                state=state,
                evidence_ids=[evidence_id] if evidence_id else [],
                confidence=confidence,
                verification_status=verification_status,
                banner=banner
            )
            self.services[key] = rec

        self.state_version += 1
        self._update_action_queues()
        return rec

    def update_service_version(
        self,
        host: str,
        port: int,
        version: str,
        evidence_id: str = "",
        verified: bool = True
    ) -> None:
        """Updates the verified version of a service with proof."""
        key = self._service_key(host, port)
        if key in self.services:
            self.services[key].version = version
            self.services[key].verification_status = VerificationStatus.VERIFIED if verified else VerificationStatus.INFERRED
            if evidence_id and evidence_id not in self.services[key].evidence_ids:
                self.services[key].evidence_ids.append(evidence_id)
            self.state_version += 1

    def record_http_probe(
        self,
        url: str,
        state: HTTPState,
        status_code: Optional[int] = None,
        title: str = "",
        server_header: str = "",
        evidence_id: str = ""
    ) -> HTTPEndpointRecord:
        """Records the canonical reachability of an HTTP endpoint."""
        target_host = url.split("://")[-1].split("/")[0].split(":")[0]
        port = 443 if "https://" in url else 80
        if ":" in url.split("://")[-1].split("/")[0]:
            try:
                port = int(url.split("://")[-1].split("/")[0].split(":")[1])
            except Exception:
                pass

        path = "/" + url.split("://")[-1].split("/", 1)[1] if "/" in url.split("://")[-1] else "/"
        ep_key = url if path != "/" else f"{target_host}:{port}"
        alt_key = f"{target_host}:{port}{path}" if path != "/" else url

        existing_key = None
        if ep_key in self.http_endpoints:
            existing_key = ep_key
        elif alt_key in self.http_endpoints:
            existing_key = alt_key

        if existing_key is not None:
            ep = self.http_endpoints[existing_key]
            ep.state = state
            ep.status_code = status_code
            ep.title = title or ep.title
            ep.server_header = server_header or ep.server_header
            if evidence_id and evidence_id not in ep.evidence_ids:
                ep.evidence_ids.append(evidence_id)
        else:
            ep = HTTPEndpointRecord(
                url=url,
                host=target_host,
                port=port,
                path=path,
                state=state,
                status_code=status_code,
                title=title,
                server_header=server_header,
                evidence_ids=[evidence_id] if evidence_id else []
            )
            self.http_endpoints[ep_key] = ep
            if alt_key != ep_key:
                self.http_endpoints[alt_key] = ep

        # Synchronize with ServiceRecord
        skey = self._service_key(target_host, port)
        if skey in self.services:
            self.services[skey].http_state = state
            if state == HTTPState.RESPONDS:
                self.services[skey].state = ServiceState.OPEN
            elif state in (HTTPState.REFUSED, HTTPState.UNREACHABLE):
                self.services[skey].state = ServiceState.CLOSED
        elif state == HTTPState.RESPONDS:
            self.record_service(
                host=target_host,
                port=port,
                service="http" if port != 443 else "https",
                state=ServiceState.OPEN,
                evidence_id=evidence_id,
                verification_status=VerificationStatus.VERIFIED
            )

        self.state_version += 1
        return ep

    def get_service(self, host: str, port: int, protocol: str = "tcp") -> Optional[ServiceRecord]:
        return self.services.get(self._service_key(host, port, protocol))

    def has_discovered_ports(self, host: str = "") -> bool:
        return len(self.get_open_ports(host)) > 0

    def get_open_ports(self, host: str = "") -> List[int]:
        clean_host = host.split("://")[-1].split("/")[0].split(":")[0] if host else ""
        ports = []
        for key, s in self.services.items():
            if s.state == ServiceState.OPEN:
                if not clean_host or s.host == clean_host:
                    ports.append(s.port)
        return sorted(list(set(ports)))

    def get_uninvestigated_services(self) -> List[ServiceRecord]:
        return [s for s in self.services.values() if s.state == ServiceState.OPEN and not s.investigated]

    def record_contradiction(self, contradiction: Dict[str, Any]) -> None:
        """Records a detected technical contradiction between evidence pieces."""
        self.contradictions.append(contradiction)
        self.state_version += 1

    def add_capability(self, name: str, description: str = "", source_evidence_id: str = "") -> None:
        """Adds or updates an acquired operational capability."""
        if name not in self.capabilities:
            try:
                from security_agent.intelligence.capability_model import Capability
                self.capabilities[name] = Capability(name=name, description=description, source_evidence_id=source_evidence_id)
            except Exception:
                self.capabilities[name] = {"name": name, "description": description, "source_evidence_id": source_evidence_id}
        self.state_version += 1

    def get_attack_surface_snapshot(self) -> Any:
        """
        Returns a derived AttackSurfaceSnapshot from this canonical AssessmentState.
        Eliminates independent storage and enforces single-source-of-truth.
        """
        from security_agent.intelligence.evidence_parser import AttackSurfaceSnapshot, DiscoveredService, DiscoveredEndpoint

        target_host = self.context.target
        services = []
        for s in self.services.values():
            services.append(DiscoveredService(
                port=s.port,
                protocol=s.protocol,
                state="open" if s.state == ServiceState.OPEN else "closed",
                service=s.service,
                version=s.version if s.version != "UNKNOWN" else "",
                host=s.host,
                investigated=s.investigated
            ))

        endpoints = []
        for ep in self.http_endpoints.values():
            endpoints.append(DiscoveredEndpoint(
                path=ep.url,
                status_code=ep.status_code or 200,
                url=ep.url
            ))

        return AttackSurfaceSnapshot(
            target=target_host,
            services=services,
            endpoints=endpoints,
            scan_state=self.scan_status
        )

    def add_evidence(
        self,
        raw_data: Any,
        source_tool: str = "unknown",
        target: str = "127.0.0.1",
        evidence_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Stores a ground-truth evidence item and returns its evidence_id."""
        self.guard_operational_mode("record_evidence")
        if isinstance(raw_data, dict):
            d = raw_data
            eid = d.get("id") or d.get("evidence_id") or evidence_id or f"evi-{uuid.uuid4().hex[:8]}"
            data = str(d.get("data") or d.get("raw_data") or d)
            tool = d.get("source_tool") or d.get("type") or source_tool
            tgt = d.get("target") or target
            meta = d.get("metadata") or metadata or {}
            self.evidence[eid] = {
                "evidence_id": eid,
                "raw_data": data,
                "source_tool": tool,
                "target": tgt,
                "metadata": meta,
                "timestamp": time.time(),
            }
            return eid

        eid = evidence_id or f"evi-{uuid.uuid4().hex[:8]}"
        self.evidence[eid] = {
            "evidence_id": eid,
            "raw_data": raw_data,
            "source_tool": source_tool,
            "target": target,
            "metadata": metadata or {},
            "timestamp": time.time(),
        }
        return eid

    def record_evidence(self, *args, **kwargs) -> str:
        """Stores a ground-truth evidence item supporting keyword aliases."""
        if kwargs:
            if "raw_evidence" in kwargs and "raw_data" not in kwargs:
                kwargs["raw_data"] = kwargs.pop("raw_evidence")
            if "tool_name" in kwargs and "source_tool" not in kwargs:
                kwargs["source_tool"] = kwargs.pop("tool_name")
            if "description" in kwargs:
                desc = kwargs.pop("description")
                meta = kwargs.setdefault("metadata", {})
                if isinstance(meta, dict):
                    meta["description"] = desc
        return self.add_evidence(*args, **kwargs)


    def get_all_evidence_ids(self) -> Set[str]:
        """Returns all evidence IDs collected across services, endpoints, and hypotheses."""
        ids: Set[str] = set(self.evidence.keys())
        for s in self.services.values():
            ids.update(s.evidence_ids)
        for ep in self.http_endpoints.values():
            ids.update(ep.evidence_ids)
        for hyp in self.hypotheses.values():
            ids.update(hyp.evidence_ids)
        for cap in self.capabilities.values():
            ids.update(cap.source_evidence_ids)
        finding_list = self.findings.values() if isinstance(self.findings, dict) else self.findings
        for f in finding_list:
            fe = getattr(f, "evidence", []) or (f.get("evidence", []) if isinstance(f, dict) else [])
            ids.update(fe)
        return ids

    def generate_verification_candidates(self) -> List[Dict[str, Any]]:
        """
        Generates deterministic, actionable verification candidates after validation success.
        Each candidate contains: tool, target, arguments, validation_evidence_ids, reason, expected_proof, priority=CRITICAL.
        """
        candidates: List[Dict[str, Any]] = []

        # Collect validation evidence IDs
        val_evidence_ids: List[str] = []
        for hyp in self.hypotheses.values():
            if hyp.evidence_ids:
                val_evidence_ids.extend(hyp.evidence_ids)
        if not val_evidence_ids:
            val_evidence_ids = list(self.get_all_evidence_ids())

        # Determine target host and web ports
        target_clean = self.context.target.split("://")[-1].split("/")[0]
        target_host = target_clean.split(":")[0] or "127.0.0.1"
        target_port_str = target_clean.split(":")[-1] if ":" in target_clean else ""
        context_port = int(target_port_str) if target_port_str.isdigit() else None

        web_ports = [s.port for s in self.services.values() if s.is_http_compatible() and s.state == ServiceState.OPEN]
        if context_port and context_port not in web_ports:
            web_ports.append(context_port)
        if not web_ports:
            web_ports = [8080]

        predicates = getattr(self, "predicates", None) or VerificationPredicates()
        cookies_header = self.session_credentials.get("Cookie", predicates.default_session_cookie)
        if "session=" not in cookies_header and self.last_validation_output:
            extracted = predicates.extract_session_token(self.last_validation_output)
            if extracted:
                cookies_header = extracted
                self.session_credentials["Cookie"] = cookies_header

        for port in web_ports:
            scheme = "https" if port == 443 else "http"
            base_url = f"{scheme}://{target_host}:{port}"

            for ep_cfg in predicates.verification_endpoints:
                path = ep_cfg.get("path", "")
                target_url = f"{base_url}{path}"
                candidates.append({
                    "priority": "CRITICAL",
                    "tool": "http.request",
                    "target": target_url,
                    "args": {
                        "method": "GET",
                        "url": target_url,
                        "headers": {"Cookie": cookies_header}
                    },
                    "validation_evidence_ids": list(set(val_evidence_ids)),
                    "reason": ep_cfg.get("reason", "Verify access on {url}.").format(url=target_url),
                    "expected_proof": ep_cfg.get("expected_proof", "Proof marker in response")
                })

        self.verification_candidates = candidates
        return candidates

    def _update_action_queues(self) -> None:
        """Updates pending, completed, and blocked action queues."""
        self.pending_actions.clear()

        # 1. Critical Priority: Verification Actions if validation succeeded
        if self.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED or self.current_phase == AssessmentPhase.VERIFICATION:
            ver_candidates = self.generate_verification_candidates()
            for vc in ver_candidates:
                self.pending_actions.append(vc)
            return

        # 2. Service Discovery & Fingerprinting Actions
        for s in self.services.values():
            if s.state == ServiceState.OPEN:
                if not s.investigated:
                    if s.service.lower() in ("ipp", "cups") or s.port == 631:
                        self.pending_actions.append({
                            "priority": "HIGH",
                            "tool": "grab_banner",
                            "args": {"host": s.host, "port": s.port},
                            "reason": f"Port {s.port} is IPP. Grab banner and inspect IPP attributes.",
                            "evidence_basis": f"DISCOVERY-{s.port}"
                        })
                    elif s.is_http_compatible():
                        scheme = "https" if s.port == 443 else "http"
                        self.pending_actions.append({
                            "priority": "HIGH",
                            "tool": "whatweb_scan",
                            "args": {"url": f"{scheme}://{s.host}:{s.port}/"},
                            "reason": f"Port {s.port} supports HTTP. Fingerprint web technologies.",
                            "evidence_basis": f"DISCOVERY-{s.port}"
                        })
                    else:
                        self.pending_actions.append({
                            "priority": "MEDIUM",
                            "tool": "grab_banner",
                            "args": {"host": s.host, "port": s.port},
                            "reason": f"Investigate service banner on port {s.port}.",
                            "evidence_basis": f"DISCOVERY-{s.port}"
                        })

        # 3. Exploit / Validation Candidates
        candidates = self.generate_exploit_candidates()
        for candidate in candidates:
            is_eligible, _ = candidate.evaluate_preconditions(self)
            if is_eligible:
                hyp = candidate.vulnerability_hypothesis
                self.pending_actions.append({
                    "priority": "HIGH",
                    "tool": candidate.allowed_tool,
                    "args": candidate.tool_arguments,
                    "reason": f"Validate hypothesis {hyp.id} ({hyp.vulnerability_type}) on port {candidate.port}.",
                    "evidence_basis": f"HYPOTHESIS-{hyp.id}"
                })

    def get_deterministic_next_action(self) -> Optional[Dict[str, Any]]:
        """
        Returns a deterministic next action when unambiguous, skipping expensive LLM calls.
        """
        for item in self.pending_actions:
            tool = item["tool"]
            args = item["args"]
            key = self.compute_action_key(tool, args, args.get("host", ""))
            if key not in self.attempted_action_keys:
                return item
        return None

    def check_evidence_contradiction(self, claim: str) -> Tuple[bool, str]:
        """
        Compares a proposed claim/finding against canonical verified evidence.
        Returns (is_contradicted, explanation).
        """
        lowered = claim.lower()

        # Check HTTP / Website reachability contradictions
        if any(w in lowered for w in ("website is online", "website is responsive", "online and responsive", "http service is active", "web server is running")):
            refused_endpoints = [ep for ep in self.http_endpoints.values() if ep.state in (HTTPState.REFUSED, HTTPState.UNREACHABLE, HTTPState.TIMEOUT)]
            online_endpoints = [ep for ep in self.http_endpoints.values() if ep.state == HTTPState.RESPONDS]

            if refused_endpoints and not online_endpoints:
                return (
                    True,
                    f"Evidence contradiction detected. Claim: '{claim.strip()}'. "
                    f"Evidence: HTTP probes returned CONNECTION REFUSED / UNREACHABLE ({[e.url for e in refused_endpoints]}). Claim discarded."
                )

        # Check unverified product versions
        cups_match = re.search(r"cups\s+([0-9]+\.[0-9]+)", lowered)
        if cups_match:
            claimed_ver = cups_match.group(0)
            verified = False
            for s in self.services.values():
                if "cups" in s.version.lower() and s.verification_status == VerificationStatus.VERIFIED:
                    verified = True
            if not verified:
                return (
                    True,
                    f"Evidence contradiction detected. Claim: '{claimed_ver}'. "
                    f"Evidence: Service version is UNKNOWN (no banner/version detected). Claim discarded."
                )

        return (False, "")

    def compute_action_key(self, tool_name: str, args: Dict[str, Any], target: str = "") -> str:
        """Computes deterministic hash key with state-version scoping."""
        norm_args = {k: v for k, v in args.items() if v is not None and v != ""}
        payload = f"{tool_name}:{target}:{json.dumps(norm_args, sort_keys=True)}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def is_action_blocked(self, tool_name: str, args: Dict[str, Any], target: str = "") -> Tuple[bool, str]:
        """Checks if an identical action previously failed."""
        key = self.compute_action_key(tool_name, args, target)
        for failed in self.failed_actions:
            if failed["action_key"] == key:
                ftype = failed.get("failure_type", "FAILURE")
                return (
                    True,
                    f"Action '{tool_name}' with identical parameters already failed with {ftype}. "
                    f"Identical retry is BLOCKED. Select an alternative tool or modify parameters."
                )
        return (False, "")

    def record_action_attempt(
        self,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        target: str = "",
        success: bool = True,
        failure_type: FailureClassification = FailureClassification.NONE,
        output_snippet: str = "",
        reason: str = "",
        evidence_basis: str = "",
        duration: float = 0.0,
        **kwargs: Any,
    ) -> None:
        """Records action attempt, updates metadata log, and triggers deterministic recovery rules."""
        if "failure_reason" in kwargs and failure_type == FailureClassification.NONE:
            failure_type = kwargs["failure_reason"]
        if args is None:
            args = {}
        elif isinstance(args, str) and not target:
            target = args
            args = {}
        key = self.compute_action_key(tool_name, args, target)
        self.attempted_action_keys.add(key)

        # Log auditable action metadata ("Why this tool?")
        err_type_str = failure_type.value if hasattr(failure_type, "value") else str(failure_type or "")
        meta = ActionMetadata(
            tool=tool_name,
            target=target or str(args.get("host") or args.get("url") or self.context.target),
            reason=reason or f"Assessment execution for {tool_name}",
            evidence_basis=evidence_basis or "Methodology Pipeline",
            duration=duration,
            status="SUCCESS" if success else "FAILED",
            error_type=err_type_str
        )
        self.action_metadata_log.append(meta)

        if success:
            self.tool_failure_counts[tool_name] = 0
            self.completed_actions.append({"tool": tool_name, "args": args, "target": target})
        else:
            self.tool_failure_counts[tool_name] = self.tool_failure_counts.get(tool_name, 0) + 1
            self.failed_actions.append({
                "action_key": key,
                "tool": tool_name,
                "args": args,
                "target": target,
                "failure_type": err_type_str,
                "output_snippet": output_snippet[:200]
            })
            self.blocked_actions.append({"tool": tool_name, "args": args, "reason": err_type_str})

            # Deterministic Recovery Rule: CONNECTION_REFUSED on web/HTTP probes
            if failure_type == FailureClassification.CONNECTION_REFUSED or err_type_str == "CONNECTION_REFUSED":
                port = 80
                if isinstance(args, dict):
                    u = str(args.get("url") or args.get("target") or args.get("host") or "")
                    if ":" in u.split("://")[-1].split("/")[0]:
                        try:
                            port = int(u.split("://")[-1].split("/")[0].split(":")[1])
                        except Exception:
                            pass
                    elif "https://" in u:
                        port = 443

                clean_host = target.split("://")[-1].split("/")[0].split(":")[0] if target else self.context.target
                skey = self._service_key(clean_host, port)
                if skey in self.services:
                    self.services[skey].state = ServiceState.CLOSED
                    self.services[skey].http_state = HTTPState.REFUSED
                else:
                    self.services[skey] = ServiceRecord(
                        host=clean_host,
                        port=port,
                        service="http" if port in (80, 8080, 443) else "unknown",
                        state=ServiceState.CLOSED,
                        http_state=HTTPState.REFUSED,
                        confidence=1.0,
                        verification_status=VerificationStatus.VERIFIED
                    )

                # Register in http_endpoints as REFUSED
                ep_key = f"{clean_host}:{port}"
                if ep_key in self.http_endpoints:
                    self.http_endpoints[ep_key].state = HTTPState.REFUSED
                else:
                    self.http_endpoints[ep_key] = HTTPEndpointRecord(
                        url=f"http://{clean_host}:{port}/",
                        host=clean_host,
                        port=port,
                        state=HTTPState.REFUSED
                    )

                # Transition to DISCOVERY phase & fast-path port discovery
                self.current_phase = AssessmentPhase.DISCOVERY
                disc_action = {
                    "priority": "HIGH",
                    "tool": "nmap_scan",
                    "args": {"host": self.context.target, "ports": "1-10000"},
                    "reason": f"Port {port} refused connection on {clean_host}. Recovering by running port discovery on canonical target {self.context.target}.",
                    "evidence_basis": "RECOVERY-CONNECTION_REFUSED"
                }
                # Insert at the beginning of pending actions
                if not any(a.get("tool") == "nmap_scan" and a.get("args", {}).get("host") == self.context.target for a in self.pending_actions):
                    self.pending_actions.insert(0, disc_action)

        self.state_version += 1

    @property
    def action_history(self) -> List[Dict[str, Any]]:
        """Returns unified chronological record of completed and failed actions."""
        return list(self.completed_actions) + list(self.failed_actions)

    def format_planner_status(self) -> str:
        """
        Formats authoritative status context for injection into LLM turns.
        """
        scope_str = ", ".join(self.context.scope) if self.context.scope else "127.0.0.1, localhost"

        open_srvs = []
        for s in self.services.values():
            if s.state == ServiceState.OPEN:
                ver_str = f" ({s.version})" if s.version and s.version != "UNKNOWN" else ""
                open_srvs.append(f"{s.port}/{s.protocol} ({s.service}{ver_str})")

        unverified = []
        for ep in self.http_endpoints.values():
            if ep.state in (HTTPState.REFUSED, HTTPState.UNREACHABLE, HTTPState.TIMEOUT):
                unverified.append(f"{ep.port}/tcp (http - {ep.state.value})")
        for s in self.services.values():
            if s.state in (ServiceState.CLOSED, ServiceState.FILTERED, ServiceState.UNAVAILABLE):
                unverified.append(f"{s.port}/{s.protocol} ({s.service} - {s.state.value})")

        blocked_targets = list(self.blocked_targets) if self.blocked_targets else ["None"]

        # Formulate active hypotheses
        active_hyps = self.get_active_hypotheses()
        hyps_lines = []
        for h in active_hyps:
            status_str = "VERIFIED" if h.verified else "UNVALIDATED"
            hyps_lines.append(f"  • [{h.id}] {h.vulnerability_type} on {h.target}:{h.port} ({status_str}) | Evidence: {', '.join(h.evidence_ids) if h.evidence_ids else 'None'}")

        # Eligible Exploit Candidates
        candidates = self.generate_exploit_candidates()
        eligible = [c for c in candidates if c.evaluate_preconditions(self)[0]]
        candidates_lines = []
        for c in eligible:
            candidates_lines.append(f"  • Tool: {c.allowed_tool} | Target: {c.target} | Port: {c.port} | Hypothesis: {c.hypothesis_id} | Preconditions: PASSED")

        # Pending Actions
        pending_lines = []
        for pa in self.pending_actions:
            pending_lines.append(f"  • [{pa.get('priority', 'INFO')}] {pa.get('tool')}: {pa.get('reason')}")

        # Verified Findings
        findings_lines = []
        for f in self.findings:
            f_title = f.get("title", "Finding")
            e_ids = ", ".join(f.get("evidence_ids", [])) or "None"
            findings_lines.append(f"  • {f_title} [Evidence: {e_ids}]")

        # Acquired Capabilities & Unlocked Surfaces
        capabilities_lines = []
        for cap in self.capabilities.values():
            unlocked = cap.metadata.get("unlocked_endpoints", [])
            unlocked_str = f" | Unlocks: {', '.join(unlocked)}" if unlocked else ""
            capabilities_lines.append(
                f"  • [{cap.capability_id}] {cap.capability_type.value} (Verified: {cap.verified}){unlocked_str} [Evidence: {', '.join(cap.source_evidence_ids)}]"
            )

        # Check if Verification is required
        verification_block = ""
        verification_lines = []
        if self.objective_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED or self.current_phase == AssessmentPhase.VERIFICATION:
            if not self.verification_candidates:
                self.generate_verification_candidates()
            predicates = getattr(self, "predicates", None) or VerificationPredicates()
            top_ver = self.verification_candidates[0] if self.verification_candidates else None
            top_ver_str = f"{top_ver['tool']} → {top_ver.get('target', top_ver.get('args', {}).get('url', ''))}" if top_ver else "http.request"
            top_ver_proof = top_ver.get("expected_proof", " / ".join(predicates.proof_markers[:2])) if top_ver else "Proof of compromise"
            val_out_snippet = self.last_validation_output.strip()[:200] if self.last_validation_output else predicates.default_session_cookie

            verification_block = (
                "=== VERIFICATION REQUIRED ===\n"
                "Validation succeeded:\n"
                f"  {val_out_snippet}\n\n"
                "Objective status:\n"
                f"  {self.objective_status.value}\n\n"
                "You must perform independent verification before reporting success.\n\n"
                f"Highest-priority verification action:\n"
                f"  {top_ver_str}\n\n"
                f"Expected evidence:\n"
                f"  {top_ver_proof}\n"
                "=============================\n\n"
            )
            for vc in self.verification_candidates:
                verification_lines.append(f"  • [{vc.get('priority', 'CRITICAL')}] Tool: {vc['tool']} | Target: {vc.get('target', vc.get('args', {}).get('url', ''))} | Reason: {vc.get('reason', '')}")

        lines = [
            f"{verification_block}=== CANONICAL ASSESSMENT PLANNER CONTEXT ===",
            f"CANONICAL TARGET:\n{self.context.target}",
            "",
            f"AUTHORIZED SCOPE:\n{scope_str}",
            "",
            f"OBJECTIVE STATUS:\n{self.objective_status.value}",
            "",
            f"DISCOVERED SERVICES:\n{', '.join(open_srvs) if open_srvs else 'None yet (Discovery Required)'}",
            "",
            f"ACQUIRED CAPABILITIES:\n{chr(10).join(capabilities_lines) if capabilities_lines else 'None acquired yet'}",
            "",
            f"ACTIVE VULNERABILITY HYPOTHESES:\n{chr(10).join(hyps_lines) if hyps_lines else 'None formulated yet'}",
            "",
            f"ELIGIBLE EXPLOIT CANDIDATES:\n{chr(10).join(candidates_lines) if candidates_lines else 'None ready'}",
            "",
            f"VERIFICATION ACTIONS:\n{chr(10).join(verification_lines) if verification_lines else 'None pending'}",
            "",
            f"VERIFIED FINDINGS:\n{chr(10).join(findings_lines) if findings_lines else 'None verified yet'}",
            "",
            f"PENDING RECOMMENDED ACTIONS:\n{chr(10).join(pending_lines) if pending_lines else 'None pending'}",
            "",
            f"UNVERIFIED / REFUSED:\n{', '.join(sorted(list(set(unverified)))) if unverified else 'None'}",
            "",
            f"BLOCKED TARGETS:\n{', '.join(sorted(list(set(blocked_targets))))}",
            "",
            f"CURRENT PHASE:\n{self.current_phase.value}",
            "============================================"
        ]
        return "\n".join(lines)

    def get_compact_state_summary(self) -> str:
        """Returns structured compact summary of canonical assessment state for LLM prompt."""
        lines = [
            f"**Current Phase:** {self.current_phase.value}",
            f"**Target:** {self.context.target} (Scope: {', '.join(self.context.scope)})",
            f"**Objective:** {self.context.objective}",
            f"**Scan Status:** {self.scan_status.upper()}"
        ]

        open_ports = self.get_open_ports()
        if open_ports:
            lines.append(f"**Verified Open Ports ({len(open_ports)}):** {', '.join(map(str, open_ports))}")
            for key, s in self.services.items():
                if s.state == ServiceState.OPEN:
                    ver_str = f" [Version: {s.version} ({s.verification_status.value})]" if s.version != "UNKNOWN" else " [Version: UNKNOWN]"
                    lines.append(f"  • `{s.port}/{s.protocol}`: {s.service}{ver_str}")
        else:
            lines.append(f"**Verified Open Ports:** None confirmed yet.")

        # HTTP Endpoint States
        if self.http_endpoints:
            lines.append(f"**HTTP Endpoints Verified:**")
            for url, ep in list(self.http_endpoints.items())[:4]:
                lines.append(f"  • {url} -> {ep.state.value} (Status: {ep.status_code or 'None'})")

        if self.failed_actions:
            lines.append(f"**Failed Actions ({len(self.failed_actions)} blocked from identical retry):**")
            for fa in self.failed_actions[-3:]:
                lines.append(f"  • {fa['tool']} -> {fa['failure_type']}")

        if self.pending_actions:
            lines.append(f"**Recommended Pending Actions:**")
            for pa in self.pending_actions[:2]:
                lines.append(f"  • [{pa['priority']}] {pa['tool']} ({pa['reason']})")

        return "\n".join(lines)

    def record_hypothesis(
        self,
        target: str,
        service: str,
        port: int,
        vulnerability_type: str,
        rationale: str = "",
        evidence_ids: Optional[List[str]] = None,
        suggested_tools: Optional[List[str]] = None,
        hypothesis_id: Optional[str] = None
    ) -> VulnerabilityHypothesis:
        """Records a new concrete vulnerability hypothesis grounded in evidence."""
        h_id = hypothesis_id or f"HYP-{vulnerability_type.upper()}-{port}-{len(self.hypotheses) + 1:03d}"
        hyp = VulnerabilityHypothesis(
            id=h_id,
            target=target,
            service=service,
            port=port,
            vulnerability_type=vulnerability_type,
            rationale=rationale,
            evidence_ids=list(evidence_ids or []),
            suggested_tools=list(suggested_tools or []),
            status=HypothesisStatus.UNTESTED
        )
        self.hypotheses[h_id] = hyp
        self.hypothesis_count = len(self.hypotheses)
        self.state_version += 1
        return hyp

    def get_hypotheses(self, status: Optional[HypothesisStatus] = None) -> List[VulnerabilityHypothesis]:
        """Returns all recorded vulnerability hypotheses or filtered by status."""
        if status is None:
            return list(self.hypotheses.values())
        return [h for h in self.hypotheses.values() if h.status == status]

    def get_active_hypotheses(self) -> List[VulnerabilityHypothesis]:
        """Returns hypotheses currently eligible for testing or exploitation."""
        return [
            h for h in self.hypotheses.values()
            if h.status in (HypothesisStatus.UNTESTED, HypothesisStatus.TESTING, HypothesisStatus.EXPLOITING)
        ]

    def get_verified_hypotheses(self) -> List[VulnerabilityHypothesis]:
        """Returns all verified vulnerability hypotheses."""
        return [h for h in self.hypotheses.values() if h.verified or h.status == HypothesisStatus.VERIFIED]

    def derive_hypotheses_from_evidence(self) -> List[VulnerabilityHypothesis]:
        """
        Derives concrete vulnerability hypotheses from verified attack surface services and endpoints.
        """
        derived: List[VulnerabilityHypothesis] = []
        target_host = self.context.target.split("://")[-1].split("/")[0].split(":")[0]

        for s_key, srv in self.services.items():
            if srv.state != ServiceState.OPEN:
                continue

            # HTTP services with endpoints
            if srv.is_http() or srv.port in (80, 443, 8080, 8000, 5000, 3000, 8384):
                matching_endpoints = [
                    ep for ep in self.http_endpoints.values()
                    if str(srv.port) in ep.url or target_host in ep.url
                ]

                # Check for login/auth endpoints -> Auth testing / SQLi
                auth_eps = [ep for ep in matching_endpoints if any(k in ep.url.lower() for k in ["login", "auth", "admin", "signin", "session"])]
                if auth_eps or srv.port in (80, 8080, 8000):
                    h_id = f"HYP-SQLI-AUTH-{srv.port}"
                    if h_id not in self.hypotheses:
                        hyp = self.record_hypothesis(
                            target=f"http://{target_host}:{srv.port}",
                            service=srv.service,
                            port=srv.port,
                            vulnerability_type="auth_bypass_sqli",
                            rationale=f"Web service on port {srv.port} may have authentication endpoints vulnerable to SQLi or credential bypass",
                            evidence_ids=list(srv.evidence_ids) if srv.evidence_ids else [],
                            suggested_tools=["http.request", "sqlmap_attack", "brute_force_http"],
                            hypothesis_id=h_id
                        )
                        derived.append(hyp)

                # Check for file/param endpoints -> Path Traversal / LFI
                file_eps = [ep for ep in matching_endpoints if any(k in ep.url.lower() for k in ["file", "view", "page", "doc", "path", "read"])]
                if file_eps:
                    h_id = f"HYP-PATH-TRAVERSAL-{srv.port}"
                    if h_id not in self.hypotheses:
                        hyp = self.record_hypothesis(
                            target=f"http://{target_host}:{srv.port}",
                            service=srv.service,
                            port=srv.port,
                            vulnerability_type="path_traversal",
                            rationale=f"Endpoints on port {srv.port} accept file/page parameters susceptible to directory traversal",
                            evidence_ids=list(srv.evidence_ids) if srv.evidence_ids else [],
                            suggested_tools=["web_fetch", "http.request", "lfi_scan"],
                            hypothesis_id=h_id
                        )
                        derived.append(hyp)

                # Check for ping/cmd endpoints -> Command Injection
                cmd_eps = [ep for ep in matching_endpoints if any(k in ep.url.lower() for k in ["ping", "exec", "cmd", "run", "system", "tools"])]
                if cmd_eps:
                    h_id = f"HYP-CMD-INJECTION-{srv.port}"
                    if h_id not in self.hypotheses:
                        hyp = self.record_hypothesis(
                            target=f"http://{target_host}:{srv.port}",
                            service=srv.service,
                            port=srv.port,
                            vulnerability_type="command_injection",
                            rationale=f"Endpoints on port {srv.port} execute system commands or ping utilities",
                            evidence_ids=list(srv.evidence_ids) if srv.evidence_ids else [],
                            suggested_tools=["http.request"],
                            hypothesis_id=h_id
                        )
                        derived.append(hyp)

            # Non-HTTP services (e.g. SSH, FTP, Telnet, etc.)
            elif srv.service in ("ssh", "ftp", "telnet", "smtp", "pop3", "imap"):
                h_id = f"HYP-SERVICE-AUTH-{srv.port}"
                if h_id not in self.hypotheses:
                    hyp = self.record_hypothesis(
                        target=f"{target_host}:{srv.port}",
                        service=srv.service,
                        port=srv.port,
                        vulnerability_type="service_authentication",
                        rationale=f"Service {srv.service} on port {srv.port} requires authentication testing",
                        evidence_ids=list(srv.evidence_ids) if srv.evidence_ids else [],
                        suggested_tools=[f"{srv.service}_brute", "generic_service_brute"],
                        hypothesis_id=h_id
                    )
                    derived.append(hyp)

        return derived

    def generate_exploit_candidates(self) -> List[ExploitCandidate]:
        """
        Derives structured ExploitCandidate objects from all active vulnerability hypotheses
        and verified attack surface evidence.
        """
        candidates: List[ExploitCandidate] = []
        for hyp in self.get_active_hypotheses():
            # Build precondition
            precondition = ExploitPrecondition(
                require_open_port=True,
                require_http_state_responds=hyp.port in (80, 443, 8080, 8000, 5000, 3000),
                require_service_match=hyp.service if hyp.service != "unknown" else None,
                require_evidence_ids=list(hyp.evidence_ids),
                disallow_if_failed_before=True
            )

            # Determine best tool and args
            tool_name = hyp.suggested_tools[0] if hyp.suggested_tools else "http.request"
            tool_args: Dict[str, Any] = {}
            plan = "Inspect response for concrete proof of compromise."

            if hyp.vulnerability_type in ("auth_bypass_sqli", "sqli"):
                if tool_name == "sqlmap_attack":
                    tool_args = {"url": f"{hyp.target}/login", "data": "username=admin&password=x", "flag": "--batch"}
                    plan = "Verify SQL injection dump and extracted credentials."
                else:
                    tool_name = "http.request"
                    tool_args = {"method": "POST", "url": f"{hyp.target}/login", "body": "username=admin'--&password=x"}
                    plan = "Verify authentication bypass (redirect to admin dashboard, session cookie, or flag)."
            elif hyp.vulnerability_type == "path_traversal":
                tool_name = hyp.suggested_tools[0] if hyp.suggested_tools else "web_fetch"
                tool_args = {"url": f"{hyp.target}/view?file=../../../../../../../../etc/passwd"}
                plan = "Verify file contents (root:x:0:0 in response body or sensitive system config)."
            elif hyp.vulnerability_type == "command_injection":
                tool_name = hyp.suggested_tools[0] if hyp.suggested_tools else "http.request"
                tool_args = {"method": "POST", "url": f"{hyp.target}/ping", "body": "host=127.0.0.1;id"}
                plan = "Verify command execution output (uid=... gid=... or system id)."
            elif "brute" in tool_name:
                tool_args = {"url": hyp.target, "usernames": "admin", "passwords": "admin,admin123,password"}
                plan = "Verify valid credential discovery in brute force output."
            else:
                tool_args = {"url": hyp.target}

            candidate = ExploitCandidate(
                target=hyp.target,
                service=hyp.service,
                port=hyp.port,
                vulnerability_hypothesis=hyp,
                evidence_ids=list(hyp.evidence_ids),
                required_conditions=precondition,
                confidence=0.9 if hyp.evidence_ids else 0.7,
                allowed_tool=tool_name,
                tool_arguments=tool_args,
                verification_plan=plan
            )
            candidates.append(candidate)

        return candidates

    def get_eligible_exploit_candidate(self, exclude_hypothesis_id: Optional[str] = None) -> Optional[ExploitCandidate]:
        """
        Evaluates preconditions across all candidates and returns the first fully satisfied ExploitCandidate.
        """
        candidates = self.generate_exploit_candidates()
        for cand in candidates:
            if exclude_hypothesis_id and cand.vulnerability_hypothesis.id == exclude_hypothesis_id:
                continue
            is_valid, _ = cand.evaluate_preconditions(self)
            if is_valid:
                return cand
        return None

    def can_transition_to_exploitation(self) -> Tuple[bool, str, Optional[ExploitCandidate]]:
        """
        Determines whether EXPLOITATION phase is justified based on canonical state
        and explicit ExploitCandidate precondition evaluation.
        Returns (is_justified, rationale, eligible_candidate).
        """
        open_srvs = [s for s in self.services.values() if s.state == ServiceState.OPEN]
        if not open_srvs:
            return (False, "No open services discovered on target. Perform DISCOVERY first.", None)

        candidate = self.get_eligible_exploit_candidate()
        if candidate:
            hyp = candidate.vulnerability_hypothesis
            return (
                True,
                f"Candidate '{candidate.allowed_tool}' for hypothesis '{hyp.id}' ({hyp.vulnerability_type}) on port {candidate.port} satisfies all preconditions.",
                candidate
            )

        return (
            False,
            "Open services exist on target but lack technical evidence or precondition satisfaction justifying exploitation. Proceed with IDENTIFICATION or ENUMERATION.",
            None
        )

    def record_exploit_attempt(
        self,
        hypothesis_id: str,
        tool_name: str,
        target: str,
        port: int,
        arguments: Dict[str, Any],
        status: ExploitStatus,
        failure_reason: str = "",
        evidence_id: str = "",
        verified: bool = False
    ) -> ExploitationRecord:
        """Records an exploitation action outcome and updates hypothesis lifecycle."""
        rec = ExploitationRecord(
            hypothesis_id=hypothesis_id,
            tool_name=tool_name,
            target=target,
            port=port,
            arguments=arguments,
            status=status,
            failure_reason=failure_reason,
            evidence_id=evidence_id,
            verified=verified
        )
        self.exploitation_records.append(rec)
        if hypothesis_id in self.hypotheses:
            h = self.hypotheses[hypothesis_id]
            h.attempt_count += 1
            if status == ExploitStatus.SUCCESS or verified:
                h.status = HypothesisStatus.VERIFIED
                h.verified = True
            elif status == ExploitStatus.FAILED:
                if h.attempt_count >= 2:
                    h.status = HypothesisStatus.REFUTED
            elif status == ExploitStatus.BLOCKED:
                h.status = HypothesisStatus.ABANDONED
        self.state_version += 1
        return rec

    def verify_exploit_success(self, hypothesis_id: str, proof: str, evidence_id: str = "") -> bool:
        """Marks hypothesis as strictly verified with proof of compromise."""
        if hypothesis_id in self.hypotheses:
            h = self.hypotheses[hypothesis_id]
            h.verified = True
            h.status = HypothesisStatus.VERIFIED
            h.proof_of_compromise = proof
            if evidence_id and evidence_id not in h.evidence_ids:
                h.evidence_ids.append(evidence_id)
            self.verified_count += 1
            self.state_version += 1
            return True
        return False

    def advance_objective(
        self,
        new_status: "ObjectiveStatus",
        *,
        reason: str = "",
        elapsed_seconds: Optional[float] = None,
        iteration: Optional[int] = None,
        proof: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> bool:
        """Centralized objective-status transition with validation.

        Returns True if the transition was applied, False if it was rejected
        (e.g. an invalid forward move or re-entering a terminal state).

        This is the *only* method that should mutate ``self.objective_status``
        in runtime code.  Persistence/deserialization code may set the field
        directly when restoring from a checkpoint.
        """
        current = self.objective_status.value if hasattr(self.objective_status, "value") else str(self.objective_status)
        target = new_status.value if hasattr(new_status, "value") else str(new_status)

        # Idempotent: if already at the target status, silently succeed
        if current == target:
            return True

        allowed = _VALID_OBJECTIVE_TRANSITIONS.get(current, set())
        if target not in allowed:
            return False

        # If transitioning to OBJECTIVE_VERIFIED: require actual verification/evidence conditions
        if target == ObjectiveStatus.OBJECTIVE_VERIFIED.value:
            if proof and proof not in self.proof_markers:
                self.proof_markers.append(proof)

            has_proof = bool(proof) or bool(self.proof_markers)
            has_verified_finding = any(
                (f.get("verified") is True or f.get("verification_status") == "VERIFIED")
                for f in self.findings
                if isinstance(f, dict)
            )
            has_verified_hyp = any(h.verified for h in self.hypotheses.values())
            has_verified_cap = any(c.verified for c in self.capabilities.values())
            has_verif_flag = getattr(self, "verification_success", False)
            has_evidence = bool(evidence_ids) and any(eid in self.evidence for eid in evidence_ids)

            if not (has_proof or has_verified_finding or has_verified_hyp or has_verified_cap or has_verif_flag or has_evidence):
                return False

        self.objective_status = new_status
        self.state_version += 1

        self.objective_history.append({
            "from_status": current,
            "to_status": target,
            "reason": reason,
            "timestamp": time.time(),
            "elapsed_seconds": elapsed_seconds,
            "iteration": iteration,
        })

        # Record timing metadata when reaching key milestones
        if new_status == ObjectiveStatus.OBJECTIVE_ACHIEVED_UNVERIFIED:
            self.validation_attempted = True
            self.validation_tool_success = True
            if self.time_to_validation is None and elapsed_seconds is not None:
                self.time_to_validation = round(elapsed_seconds, 2)
        elif new_status == ObjectiveStatus.OBJECTIVE_VERIFIED:
            self.objective_achieved = True
            self.verification_started = True
            self.verification_success = True
            if elapsed_seconds is not None:
                if self.time_to_verification is None:
                    self.time_to_verification = round(elapsed_seconds, 2)
                if self.time_to_objective is None:
                    self.time_to_objective = round(elapsed_seconds, 2)
            if iteration is not None and self.tools_to_objective is None:
                self.tools_to_objective = iteration

        return True

    def record_finding(
        self,
        title: Any,
        severity: str = "HIGH",
        description: str = "",
        evidence_ids: Optional[List[str]] = None,
        proof: str = "",
        finding_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Records a verified finding in assessment state."""
        self.guard_operational_mode("record_finding")
        if isinstance(title, dict):
            d = title
            finding_id = d.get("id", finding_id)
            severity = d.get("severity", severity)
            description = d.get("description", description)
            evidence_ids = d.get("evidence_ids", evidence_ids)
            proof = d.get("proof", proof)
            verified = d.get("verified", True)
            verification_status = d.get("verification_status", "VERIFIED")
            title = d.get("title") or d.get("name") or "Untitled Finding"
        else:
            verified = True
            verification_status = "VERIFIED"

        f_id = finding_id or f"FIND-{len(self.findings) + 1:03d}"
        sev_str = severity.value if hasattr(severity, "value") else str(severity).upper()
        evi_list = list(evidence_ids or [])
        # Findings without evidence cannot be considered verified —
        # this prevents hallucinated findings from bypassing the verifier.
        if not evi_list:
            verified = False
            verification_status = "UNVERIFIED"
        finding = {
            "id": f_id,
            "finding_id": f_id,
            "title": str(title),
            "severity": sev_str,
            "description": description,
            "evidence_ids": evi_list,
            "proof": proof,
            "verified": verified,
            "verification_status": verification_status,
        }
        self.findings.append(finding)
        self.findings_count = len(self.findings)
        self.state_version += 1
        return finding

    def record_capability(
        self,
        *args: Any,
        capability_type: Optional[CapabilityType | str] = None,
        source_evidence_ids: Optional[List[str]] = None,
        acquisition_action: str = "",
        target_scope: str = "",
        verified: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        capability_id: Optional[str] = None,
        cap_type: Optional[CapabilityType | str] = None,
        evidence_id: Optional[str] = None,
        host: Optional[str] = None,
        **kwargs: Any,
    ) -> Capability:
        """
        Records a verified capability in assessment state.
        Only verified capabilities may unlock new attack graph nodes and edges.
        Supports both (capability_type, evidence_ids, ...) and (capability_id, capability_type, scope, ...) signatures.
        """
        self.guard_operational_mode("record_capability")
        # Disambiguate positional arguments if provided
        if args:
            first = args[0]
            # Determine whether first positional argument is capability_id or capability_type
            first_is_enum = isinstance(first, CapabilityType)
            first_matches_enum = False
            if isinstance(first, str):
                try:
                    CapabilityType(first.upper())
                    first_matches_enum = True
                except ValueError:
                    first_matches_enum = False

            # If second positional arg is provided and is a CapabilityType
            second_is_type = False
            if len(args) > 1:
                second = args[1]
                if isinstance(second, CapabilityType):
                    second_is_type = True
                elif isinstance(second, str):
                    try:
                        CapabilityType(second.upper())
                        second_is_type = True
                    except ValueError:
                        second_is_type = False

            if second_is_type or (not first_is_enum and not first_matches_enum and isinstance(first, str)):
                # Pattern: (capability_id, capability_type, [target_scope], ...)
                capability_id = str(first)
                if len(args) > 1:
                    capability_type = args[1]
                if len(args) > 2 and isinstance(args[2], str):
                    target_scope = args[2]
                if len(args) > 3 and isinstance(args[3], list):
                    source_evidence_ids = args[3]
            else:
                # Pattern: (capability_type, [source_evidence_ids], [acquisition_action], [target_scope])
                capability_type = first
                if len(args) > 1 and isinstance(args[1], list):
                    source_evidence_ids = args[1]
                if len(args) > 2 and isinstance(args[2], str):
                    acquisition_action = args[2]
                if len(args) > 3 and isinstance(args[3], str):
                    target_scope = args[3]

        effective_cap_type = capability_type or cap_type or CapabilityType.UNAUTHENTICATED
        if isinstance(effective_cap_type, str):
            try:
                cap_type_enum = CapabilityType(effective_cap_type.upper())
            except ValueError:
                cap_type_enum = CapabilityType.UNAUTHENTICATED
        else:
            cap_type_enum = effective_cap_type

        ev_ids = list(source_evidence_ids or [])
        if evidence_id and evidence_id not in ev_ids:
            ev_ids.append(evidence_id)

        meta = dict(metadata or {})
        if host:
            meta["host"] = host
        meta.update(kwargs)

        cap_id = capability_id or f"CAP-{cap_type_enum.value[:4]}-{len(self.capabilities) + 1:03d}"

        # Idempotent preservation: if already recorded, update evidence/metadata without losing state
        if cap_id in self.capabilities:
            existing = self.capabilities[cap_id]
            for eid in ev_ids:
                if eid not in existing.source_evidence_ids:
                    existing.source_evidence_ids.append(eid)
            existing.metadata.update(meta)
            if target_scope and not existing.target_scope:
                existing.target_scope = target_scope
            self.state_version += 1
            return existing

        cap = Capability(
            capability_id=cap_id,
            capability_type=cap_type_enum,
            source_evidence_ids=ev_ids,
            acquisition_action=acquisition_action,
            target_scope=target_scope or host or self.context.target,
            timestamp=time.time(),
            verified=verified,
            metadata=meta,
        )
        self.capabilities[cap_id] = cap
        self.state_version += 1
        return cap

    def has_capability(
        self,
        capability_type: CapabilityType | str,
        target_scope: Optional[str] = None,
        verified_only: bool = True,
    ) -> bool:
        """Returns True if the assessment state contains the requested capability."""
        if isinstance(capability_type, str):
            try:
                cap_type_enum = CapabilityType(capability_type.upper())
            except ValueError:
                cap_type_enum = None
        else:
            cap_type_enum = capability_type

        for cap in self.capabilities.values():
            if verified_only and not cap.verified:
                continue
            if cap_type_enum is not None and cap.capability_type != cap_type_enum:
                continue
            if target_scope and cap.target_scope and target_scope not in cap.target_scope and cap.target_scope not in target_scope:
                continue
            return True
        return False

    def get_capabilities(
        self,
        capability_type: Optional[CapabilityType | str] = None,
        target_scope: Optional[str] = None,
        verified_only: bool = True,
    ) -> List[Capability]:
        """Returns a list of matching capabilities."""
        if isinstance(capability_type, str):
            try:
                cap_type_enum = CapabilityType(capability_type.upper())
            except ValueError:
                cap_type_enum = None
        else:
            cap_type_enum = capability_type

        matches = []
        for cap in self.capabilities.values():
            if verified_only and not cap.verified:
                continue
            if cap_type_enum is not None and cap.capability_type != cap_type_enum:
                continue
            if target_scope and cap.target_scope and target_scope not in cap.target_scope and cap.target_scope not in target_scope:
                continue
            matches.append(cap)
        return matches

    def get_session_store(self) -> SessionStore:
        """Returns or lazily initializes the authoritative SessionStore."""
        if self.session_store is None:
            scope_list = list(self.context.scope) if (self.context and self.context.scope) else ["localhost", "127.0.0.1"]
            self.session_store = SessionStore(default_scope=scope_list)
        return self.session_store

    def get_request_auth_context(self, target_url: str, role: str = "default") -> Dict[str, Any]:
        """Resolves active session headers, cookies, and CSRF token for a target request."""
        return self.get_session_store().get_request_auth_context(target_url, role=role)

    def record_discovered_endpoint(
        self,
        url: str,
        host: str,
        port: int,
        path: str = "/",
        state: HTTPState = HTTPState.UNKNOWN,
        status_code: Optional[int] = None,
        evidence_id: Optional[str] = None,
        auth_context: Optional[str] = None,
        title: str = "",
        server_header: str = "",
    ) -> HTTPEndpointRecord:
        """Records a discovered endpoint and triggers contextual hypothesis derivation."""
        clean_host = host.split("://")[-1].split("/")[0].split(":")[0]
        ep_key = f"{clean_host}:{port}{path}" if path != "/" else f"{clean_host}:{port}"

        if ep_key in self.http_endpoints:
            ep = self.http_endpoints[ep_key]
            if status_code is not None:
                ep.status_code = status_code
            if state != HTTPState.UNKNOWN:
                ep.state = state
            if evidence_id and evidence_id not in ep.evidence_ids:
                ep.evidence_ids.append(evidence_id)
        else:
            evidence_ids = [evidence_id] if evidence_id else []
            ep = HTTPEndpointRecord(
                url=url,
                host=clean_host,
                port=port,
                path=path,
                state=state,
                status_code=status_code,
                title=title,
                server_header=server_header,
                evidence_ids=evidence_ids
            )
            self.http_endpoints[ep_key] = ep
            self.state_version += 1

            # Derive new hypotheses for newly discovered endpoints
            self.derive_hypotheses_from_evidence()

        return ep

    def ingest_session_http_response(
        self,
        target_url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        evidence_id: Optional[str] = None,
        role: str = "default",
    ) -> Tuple[Session, List[Dict[str, Any]]]:
        """
        Parses Set-Cookie, Bearer tokens, CSRF tokens, and response links from HTTP responses.
        Propagates verified authentication state to Capabilities and registers newly discovered endpoints.
        """
        store = self.get_session_store()
        session, discovered_eps = store.update_from_http_response(
            target_url=target_url,
            status_code=status_code,
            headers=headers,
            body=body,
            evidence_id=evidence_id,
            role=role
        )

        parsed = urllib.parse.urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = parsed.netloc.split(":")[0] if parsed.netloc else "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # If session is authenticated, record or update AUTHENTICATED capability
        if session.is_authenticated():
            cap_meta = {
                "session_id": session.session_id,
                "role": session.role,
                "target_origin": session.target_origin,
                "unlocked_endpoints": [ep["url"] for ep in discovered_eps],
            }
            # Backwards compatibility with session_credentials
            cookie_hdr = session.get_cookie_header(host, parsed.path or "/", is_https=(parsed.scheme == "https"))
            if cookie_hdr:
                self.session_credentials["Cookie"] = cookie_hdr

            # Grant AUTHENTICATED capability
            self.record_capability(
                capability_type=CapabilityType.AUTHENTICATED,
                source_evidence_ids=session.source_evidence_ids,
                acquisition_action=f"HTTP_LOGIN_{port}",
                target_scope=session.target_origin,
                verified=(session.verification_status == SessionVerificationStatus.VERIFIED or "session=" in body or "Welcome" in body or status_code in (200, 302)),
                metadata=cap_meta
            )

        # Register newly discovered endpoints
        for dep in discovered_eps:
            dep_url = dep["url"]
            dep_parsed = urllib.parse.urlparse(dep_url)
            dep_host = dep_parsed.netloc.split(":")[0] if dep_parsed.netloc else host
            dep_port = dep_parsed.port or port
            dep_path = dep_parsed.path or "/"

            self.record_discovered_endpoint(
                url=dep_url,
                host=dep_host,
                port=dep_port,
                path=dep_path,
                evidence_id=evidence_id,
                auth_context=dep.get("auth_context")
            )

        return session, discovered_eps

    def get_surface_snapshot(self, graph: Optional[Any] = None) -> Dict[str, int]:
        """Returns a numeric snapshot of current attack surface, evidence, and knowledge state."""
        return {
            "services": len(self.services),
            "http_endpoints": len(self.http_endpoints),
            "findings": len(self.findings),
            "capabilities": len(self.capabilities),
            "hypotheses": len(self.hypotheses),
            "graph_nodes": len(graph.nodes) if graph and hasattr(graph, "nodes") else 0,
            "graph_edges": len(graph.edges) if graph and hasattr(graph, "edges") else 0,
            "evidence_ids": (
                sum(len(s.evidence_ids) for s in self.services.values())
                + sum(len(ep.evidence_ids) for ep in self.http_endpoints.values())
                + sum(len(f.get("evidence_ids", [])) for f in self.findings)
                + sum(len(c.source_evidence_ids) for c in self.capabilities.values())
            ),
        }

    def calculate_information_gain(
        self,
        prev_snapshot: Dict[str, int],
        curr_snapshot: Dict[str, int],
    ) -> float:
        """Calculates weighted information gain between two state snapshots."""
        weights = {
            "findings": 5.0,
            "capabilities": 4.0,
            "services": 2.0,
            "http_endpoints": 2.0,
            "graph_nodes": 1.0,
            "graph_edges": 1.0,
            "evidence_ids": 1.5,
            "hypotheses": 0.5,
        }
        gain = 0.0
        for key, weight in weights.items():
            delta = max(0, curr_snapshot.get(key, 0) - prev_snapshot.get(key, 0))
            gain += delta * weight
        return gain

    def record_information_gain(
        self,
        prev_snapshot: Dict[str, int],
        curr_snapshot: Dict[str, int],
        action_name: str = "",
    ) -> float:
        """Computes and appends an information gain record to history."""
        gain = self.calculate_information_gain(prev_snapshot, curr_snapshot)
        self.information_gain_history.append({
            "action": action_name,
            "gain": gain,
            "timestamp": time.time(),
            "snapshot": dict(curr_snapshot),
        })
        return gain

    def record_discovered_form(self, form_record: Any) -> None:
        """Stores or updates a discovered form on the application surface."""
        f_id = getattr(form_record, "form_id", "") or getattr(form_record, "action", str(uuid.uuid4()))
        self.forms[f_id] = form_record
        f_action = getattr(form_record, "action", "")
        if f_action:
            parsed = urllib.parse.urlparse(f_action if "://" in f_action else f"http://{f_action}")
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            self.record_discovered_endpoint(
                url=f_action,
                host=host,
                port=port,
                path=path,
                evidence_id=getattr(form_record, "evidence_ids", [None])[0] if getattr(form_record, "evidence_ids", None) else None
            )

    def record_discovered_websocket(self, ws_endpoint: Any) -> None:
        """Stores or updates a discovered WebSocket endpoint."""
        ws_url = getattr(ws_endpoint, "url", "")
        if ws_url:
            self.websockets[ws_url] = ws_endpoint

    def record_dom_snapshot(self, snapshot: Any) -> None:
        """Stores a DOM snapshot and records its underlying surfaces."""
        s_id = getattr(snapshot, "snapshot_id", "")
        if s_id:
            self.dom_snapshots[s_id] = snapshot
        for f in getattr(snapshot, "forms", []):
            self.record_discovered_form(f)
        for w in getattr(snapshot, "websockets", []):
            self.record_discovered_websocket(w)
        for api in getattr(snapshot, "api_candidates", []):
            a_url = getattr(api, "url", "")
            if a_url:
                parsed = urllib.parse.urlparse(a_url if "://" in a_url else f"http://{a_url}")
                host = parsed.hostname or "127.0.0.1"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                path = parsed.path or "/"
                self.record_discovered_endpoint(
                    url=a_url,
                    host=host,
                    port=port,
                    path=path,
                    evidence_id=getattr(api, "evidence_ids", [None])[0] if getattr(api, "evidence_ids", None) else None
                )
        for link in getattr(snapshot, "links", []):
            l_href = getattr(link, "href", "")
            if l_href and not l_href.startswith(("#", "javascript:", "mailto:", "tel:")):
                parsed = urllib.parse.urlparse(l_href if "://" in l_href else f"http://{l_href}")
                host = parsed.hostname or "127.0.0.1"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                path = parsed.path or "/"
                self.record_discovered_endpoint(
                    url=l_href,
                    host=host,
                    port=port,
                    path=path,
                    evidence_id=getattr(link, "evidence_ids", [None])[0] if getattr(link, "evidence_ids", None) else None
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.current_phase.value,
            "current_phase": self.current_phase.value,
            "previous_phase": self.previous_phase.value if self.previous_phase else None,
            "current_objective": self.current_objective,
            "hypothesis_count": self.hypothesis_count,
            "tested_count": self.tested_count,
            "verified_count": self.verified_count,
            "rejected_count": self.rejected_count,
            "pending_count": self.pending_count,
            "phase_history": self.phase_history,
            "target": self.context.target,
            "scope": list(self.context.scope),
            "objective": self.context.objective,
            "open_ports": self.get_open_ports(),
            "services": [s.to_dict() for s in self.services.values()],
            "http_endpoints": [ep.to_dict() for ep in self.http_endpoints.values()],
            "hypotheses": [h.to_dict() for h in self.hypotheses.values()],
            "capabilities": [c.to_dict() for c in self.capabilities.values()],
            "exploitation_records": [e.to_dict() for e in self.exploitation_records],
            "findings": list(self.findings),
            "findings_count": len(self.findings),
            "failed_actions_count": len(self.failed_actions),
            "failed_actions": list(self.failed_actions),
            "attempted_action_keys": list(self.attempted_action_keys),
            "decision_records": [d.to_dict() for d in self.decision_records if hasattr(d, "to_dict")],
            "scan_status": self.scan_status,
            "state_version": self.state_version,
            "evidence": dict(self.evidence),
            "proof_markers": list(self.proof_markers),
            "contradictions": list(self.contradictions),
            "operational_mode": getattr(self, "operational_mode", "ASSESSMENT"),
            "objective_status": self.objective_status.value if isinstance(self.objective_status, Enum) else str(self.objective_status),
            "validation_attempted": self.validation_attempted,
            "validation_tool_success": self.validation_tool_success,
            "verification_started": self.verification_started,
            "verification_success": self.verification_success,
            "objective_achieved": self.objective_achieved,
            "objective_history": list(self.objective_history),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AssessmentState":
        phase_str = data.get("phase") or data.get("current_phase") or "INITIALIZING"
        try:
            phase_enum = AssessmentPhase(phase_str)
        except Exception:
            phase_enum = AssessmentPhase.INITIALIZING

        prev_phase_str = data.get("previous_phase")
        prev_phase_enum = None
        if prev_phase_str:
            try:
                prev_phase_enum = AssessmentPhase(prev_phase_str)
            except Exception:
                prev_phase_enum = None

        target = data.get("target", "localhost")
        raw_scope = data.get("scope", ["localhost", "127.0.0.1"])
        scope = tuple(raw_scope) if isinstance(raw_scope, (list, tuple, set)) else (str(raw_scope),)
        objective = data.get("objective", "Assess the exposed services and produce a report")
        context = AssessmentContext(target=target, scope=scope, objective=objective)

        state = cls(
            context=context,
            current_phase=phase_enum,
            previous_phase=prev_phase_enum,
            current_objective=data.get("current_objective", ""),
            hypothesis_count=data.get("hypothesis_count", 0),
            tested_count=data.get("tested_count", 0),
            verified_count=data.get("verified_count", 0),
            rejected_count=data.get("rejected_count", 0),
            pending_count=data.get("pending_count", 0),
            phase_history=data.get("phase_history", []),
            scan_status=data.get("scan_status", "pending"),
            state_version=data.get("state_version", 1),
        )

        # Restore services
        for s in data.get("services", []):
            if isinstance(s, dict):
                st_val = s.get("state", "OPEN")
                try:
                    s_state = ServiceState(st_val) if st_val in ServiceState._value2member_map_ else ServiceState.OPEN
                except Exception:
                    s_state = ServiceState.OPEN
                ver_st_val = s.get("verification_status", "INFERRED")
                try:
                    ver_status = VerificationStatus(ver_st_val) if ver_st_val in VerificationStatus._value2member_map_ else VerificationStatus.INFERRED
                except Exception:
                    ver_status = VerificationStatus.INFERRED
                state.record_service(
                    host=s.get("host", target),
                    port=int(s.get("port", 0)),
                    service=s.get("service", "unknown"),
                    protocol=s.get("protocol", "tcp"),
                    version=s.get("version", "UNKNOWN"),
                    state=s_state,
                    evidence_id=s.get("evidence_ids", [""])[0] if s.get("evidence_ids") else "",
                    banner=s.get("banner", ""),
                    confidence=float(s.get("confidence", 1.0)),
                    verification_status=ver_status
                )

        # Restore http endpoints
        for ep in data.get("http_endpoints", []):
            if isinstance(ep, dict):
                ep_st = ep.get("state", "RESPONDS")
                try:
                    h_state = HTTPState(ep_st) if ep_st in HTTPState._value2member_map_ else HTTPState.RESPONDS
                except Exception:
                    h_state = HTTPState.RESPONDS
                state.record_http_probe(
                    url=ep.get("url", ""),
                    state=h_state,
                    status_code=ep.get("status_code", 200),
                    title=ep.get("title", ""),
                    server_header=ep.get("server_header", ""),
                    evidence_id=ep.get("evidence_ids", [""])[0] if ep.get("evidence_ids") else ""
                )

        # Restore findings
        for f in data.get("findings", []):
            if isinstance(f, dict):
                state.findings.append(f)

        # Restore capabilities
        for cap_data in data.get("capabilities", []):
            if isinstance(cap_data, dict) and "capability_id" in cap_data:
                try:
                    cap = Capability.from_dict(cap_data)
                    state.capabilities[cap.capability_id] = cap
                except Exception:
                    pass

        # Restore evidence
        for eid, edata in data.get("evidence", {}).items():
            if isinstance(edata, dict):
                state.evidence[eid] = dict(edata)

        # Restore hypotheses
        for h_data in data.get("hypotheses", []):
            if isinstance(h_data, dict):
                try:
                    hyp = VulnerabilityHypothesis.from_dict(h_data)
                    state.hypotheses[hyp.id] = hyp
                except Exception:
                    pass

        # Restore verification/objective state
        state.proof_markers = list(data.get("proof_markers", []))
        state.contradictions = list(data.get("contradictions", []))
        state.operational_mode = data.get("operational_mode", "ASSESSMENT")
        obj_st = data.get("objective_status")
        if obj_st and obj_st in ObjectiveStatus._value2member_map_:
            state.objective_status = ObjectiveStatus(obj_st)
        state.validation_attempted = data.get("validation_attempted", False)
        state.validation_tool_success = data.get("validation_tool_success", False)
        state.verification_started = data.get("verification_started", False)
        state.verification_success = data.get("verification_success", False)
        state.objective_achieved = data.get("objective_achieved", False)
        state.objective_history = list(data.get("objective_history", []))

        # Restore action tracking and decision records
        state.attempted_action_keys = set(data.get("attempted_action_keys", []))
        state.failed_actions = list(data.get("failed_actions", []))
        try:
            from security_agent.intelligence.decision import DecisionRecord, DecisionSource
            for d in data.get("decision_records", []):
                if isinstance(d, dict):
                    src_val = d.get("source", "DETERMINISTIC")
                    src = DecisionSource(src_val) if src_val in DecisionSource._value2member_map_ else DecisionSource.DETERMINISTIC
                    d_copy = dict(d)
                    d_copy["source"] = src
                    state.decision_records.append(DecisionRecord(**d_copy))
        except Exception:
            pass

        return state



class AssessmentStateMachine:
    """
    State machine enforcing standard security methodology and adaptive recovery.
    """
    def __init__(self, max_tool_retries: int = 3):
        self.current_phase = AssessmentPhase.INITIALIZE
        self.history: List[StateTransition] = []
        self.tool_failure_counts: Dict[str, int] = {}
        self.max_tool_retries = max_tool_retries
        self.findings_count = 0
        self.verified_findings_count = 0

    def transition(self, to_phase: AssessmentPhase, reason: str, tool: Optional[str] = None) -> None:
        """Transitions to a new methodology phase."""
        transition_obj = StateTransition(
            from_phase=self.current_phase,
            to_phase=to_phase,
            reason=reason,
            tool=tool
        )
        self.history.append(transition_obj)
        self.current_phase = to_phase

    def record_tool_success(self, tool: str) -> None:
        """Resets failure count for a successful tool."""
        self.tool_failure_counts[tool] = 0

    def should_retry_tool(self, tool: str) -> bool:
        """Returns True if tool has not exceeded max retry threshold."""
        return self.tool_failure_counts.get(tool, 0) < self.max_tool_retries

    def record_tool_failure(self, tool: str, error: str) -> Tuple[str, AssessmentPhase]:
        """Records tool failure and recommends next action and phase."""
        count = self.tool_failure_counts.get(tool, 0) + 1
        self.tool_failure_counts[tool] = count

        if count < self.max_tool_retries:
            return (f"Retry attempt {count}/{self.max_tool_retries} with modified parameters", AssessmentPhase.TARGETED_ENUMERATION)
        else:
            self.transition(
                to_phase=AssessmentPhase.IDENTIFICATION,
                reason=f"Tool {tool} failed {count} times consecutively. Pivoting to alternative capability.",
                tool=tool
            )
            return (f"Tool {tool} unavailable after {count} attempts. Selecting an alternative available capability.", AssessmentPhase.IDENTIFICATION)

    def advance_methodology(self, action_type: str, has_findings: bool = False) -> AssessmentPhase:
        """Advances the security assessment lifecycle based on observable actions."""
        if self.current_phase == AssessmentPhase.INITIALIZE:
            self.transition(AssessmentPhase.SCOPE, "Scope verified and authorized target confirmed")
        elif self.current_phase == AssessmentPhase.SCOPE:
            self.transition(AssessmentPhase.DISCOVERY, "Beginning reconnaissance and surface discovery")
        elif self.current_phase == AssessmentPhase.DISCOVERY:
            if "port" in action_type or "dns" in action_type or "list" in action_type or "enum" in action_type:
                pass
            else:
                self.transition(AssessmentPhase.IDENTIFICATION, "Analyzing discovered surface for vulnerability vectors")
        elif self.current_phase == AssessmentPhase.IDENTIFICATION:
            self.transition(AssessmentPhase.TARGETED_ENUMERATION, "Formulating specific security test hypothesis")
        elif self.current_phase == AssessmentPhase.TARGETED_ENUMERATION:
            if has_findings:
                self.transition(AssessmentPhase.VERIFICATION, "Verifying reproducibility and impact of suspected flaw")
            else:
                self.transition(AssessmentPhase.IDENTIFICATION, "Evaluating test result and determining next surface")
        elif self.current_phase == AssessmentPhase.VERIFICATION:
            self.transition(AssessmentPhase.REPORT, "Documenting validated finding with reproduction evidence")
        elif self.current_phase == AssessmentPhase.REPORT:
            self.transition(AssessmentPhase.COMPLETE, "Assessment methodology completed")

        return self.current_phase
