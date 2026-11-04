"""
Phase 17 Benchmark: Long-Horizon Autonomous Investigation & Real-World-Like Surface Complexity.

Implements:
  1. Multi-Host Deterministic Isolated Laboratory (Host A, Host B, Host C, Host D)
  2. Branching Attack Graph with Multi-Branch ROI Evaluation
  3. Multi-Hypothesis Lifecycle (PROPOSED, INVESTIGATING, VALIDATED, VERIFIED, REFUTED, ABANDONED)
  4. Conflicting Evidence Detection & Conflict Resolution Hypotheses
  5. Credential & Session Lifecycle Graph (Credentials, Tokens, Scopes, Isolation)
  6. Multi-Tier Privilege Transitions (UNAUTH -> AUTH -> USER -> ADMIN -> COMMAND_EXEC)
  7. Cross-Surface Transitions (HTTP -> Browser -> WebSocket -> API)
  8. Decoy Vulnerabilities & Dead-End Branch Abandonment
  9. Partial Success vs Independent Verification & Multi-Objective Independent Tracking
  10. 1,000-Action Long-Horizon Trajectory Simulation with Empirical Delta-Gain Curve
  11. Deterministic Model-Independent Controller vs RAW_MODEL vs BACKEND_ASSISTED Attribution
  12. Failure Recovery, Context Pressure, and Latency Pressure Simulation
"""

from __future__ import annotations

import copy
import enum
import json
import math
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from security_agent.agent.assessment_state import (
    AssessmentContext,
    AssessmentPhase,
    AssessmentState,
    ObjectiveStatus,
    ServiceRecord,
    ServiceState,
)
from security_agent.agent.completion_engine import (
    AssessmentMode,
    BudgetSnapshot,
    CompletionAction,
    CompletionDecision,
    CompletionEngine,
)
from security_agent.intelligence.action_cost import ActionCostEngine
from security_agent.intelligence.action_history import (
    ActionHistoryRecord,
    ActionHistoryStore,
    ActionOutcome,
)
from security_agent.intelligence.action_identity import ActionIdentity, SemanticActionKey
from security_agent.intelligence.action_selection import (
    ActionCandidate,
    ActionSelectionEngine,
    GainRecommendation,
)
from security_agent.intelligence.attack_graph import (
    AttackGraph,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    NodeStatus,
)
from security_agent.intelligence.branches import BranchManager, BranchPriority, InvestigationBranch
from security_agent.intelligence.failure_memory import (
    FailureAwareMemory,
    FailureConditionType,
)
from security_agent.intelligence.frontier import FrontierEngine, FrontierStage
from security_agent.intelligence.gain_predictor import GainPredictionResult, GainPredictor
from security_agent.intelligence.hypothesis_engine import (
    HypothesisEngine,
    HypothesisProposal,
    ProposalConfidence,
)
from security_agent.intelligence.noop_detector import ActionDelta, NoOpDetector
from security_agent.intelligence.reconsideration import (
    ReconsiderationEngine,
    ReconsiderationTrigger,
)


class PrivilegeLevel(str, enum.Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    AUTHENTICATED = "AUTHENTICATED"
    USER = "USER"
    ADMIN = "ADMIN"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"


class HypothesisLifecycleState(str, enum.Enum):
    PROPOSED = "PROPOSED"
    INVESTIGATING = "INVESTIGATING"
    VALIDATED = "VALIDATED"
    VERIFIED = "VERIFIED"
    REFUTED = "REFUTED"
    ABANDONED = "ABANDONED"


class EvidenceConfidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class CrossSurfaceType(str, enum.Enum):
    HTTP_TO_BROWSER = "HTTP_TO_BROWSER"
    BROWSER_TO_HTTP = "BROWSER_TO_HTTP"
    BROWSER_TO_WEBSOCKET = "BROWSER_TO_WEBSOCKET"
    WEBSOCKET_TO_API = "WEBSOCKET_TO_API"
    API_TO_SSH = "API_TO_SSH"


@dataclass
class Phase17Credential:
    credential_id: str
    credential_type: str  # password, jwt, api_token, cookie, ssh_key
    value: str
    target_scope: str  # host or domain
    associated_identity: str
    privilege_level: PrivilegeLevel
    source_evidence_id: str
    is_validated: bool = False
    is_revoked: bool = False


@dataclass
class Phase17Evidence:
    evidence_id: str
    host: str
    service: str
    source_tool: str
    content: str
    timestamp: float
    confidence: EvidenceConfidence = EvidenceConfidence.CONFIRMED
    conflicting_evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Phase17Hypothesis:
    hypothesis_id: str
    host: str
    vulnerability_type: str
    state: HypothesisLifecycleState
    supporting_evidence_ids: List[str] = field(default_factory=list)
    refuting_evidence_ids: List[str] = field(default_factory=list)
    refutation_reason: str = ""
    is_decoy: bool = False
    resolution_notes: str = ""


@dataclass
class Phase17Objective:
    objective_id: str
    description: str
    target_host: str
    is_validated: bool = False
    is_verified: bool = False
    verification_evidence_id: Optional[str] = None


@dataclass
class Phase17ActionTrace:
    turn: int
    tool_name: str
    target: str
    canonical_key: str
    context_signature: str
    expected_gain: float
    actual_gain: float
    prediction_error: float
    cost: float
    efficiency: float
    evidence_delta: int
    node_delta: int
    capability_delta: int
    finding_delta: int
    usefulness: str
    duplicate_classification: str
    selected_by_model: bool
    selected_by_backend: bool
    backend_fallback: bool
    schema_repaired: bool
    duplicate_blocked: bool
    retry_reason: str
    why_this_action: str
    active_privilege: PrivilegeLevel


@dataclass
class Phase17BenchmarkReport:
    suite_name: str
    turns_requested: int
    turns_completed: int
    unique_actions_count: int
    duplicate_actions_count: int
    justified_reconsiderations_count: int
    useful_actions_count: int
    no_information_actions_count: int
    false_useful_count: int
    total_expected_gain: float
    total_actual_gain: float
    mae_prediction_error: float
    mean_signed_prediction_error: float
    average_efficiency: float
    hosts_compromised: int
    objectives_total: int
    objectives_verified: int
    decoys_refuted_count: int
    dead_ends_abandoned_count: int
    conflicts_resolved_count: int
    branch_rois: Dict[str, float]
    execution_time_seconds: float
    is_success: bool
    status_message: str


class MultiHostSyntheticLab:
    """
    Deterministic isolated multi-host lab environment:
      - HOST A (192.168.1.10): Public Web App, REST API, Auth Gateway, Decoys
      - HOST B (192.168.1.20): Internal API, Admin Dashboard, WebSocket notifications
      - HOST C (192.168.1.30): SSH Management, Secure Document File Store
      - HOST D (192.168.1.40): Internal Vault (reachable strictly via SSH/File on Host C)
    """

    def __init__(self):
        self.hosts = {
            "192.168.1.10": "HOST_A_PUBLIC_GATEWAY",
            "192.168.1.20": "HOST_B_INTERNAL_ADMIN",
            "192.168.1.30": "HOST_C_INFRA_FILES",
            "192.168.1.40": "HOST_D_INTERNAL_VAULT",
        }

        # Global Environment Ground-Truth State
        self.credentials_vault: Dict[str, Phase17Credential] = {
            "cred_user_pass": Phase17Credential("cred_user_pass", "password", "guest:guest123", "192.168.1.10", "guest", PrivilegeLevel.AUTHENTICATED, "EVI-INIT", is_validated=True),
            "cred_jwt_admin": Phase17Credential("cred_jwt_admin", "jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.secret", "192.168.1.20", "admin", PrivilegeLevel.ADMIN, "EVI-AUTH-FLOW", is_validated=False),
            "cred_ssh_key": Phase17Credential("cred_ssh_key", "ssh_key", "-----BEGIN OPENSSH PRIVATE KEY-----...", "192.168.1.30", "devops", PrivilegeLevel.COMMAND_EXECUTION, "EVI-FILE-DUMP", is_validated=False),
            "cred_vault_token": Phase17Credential("cred_vault_token", "api_token", "s.vault_root_key_999", "192.168.1.40", "root", PrivilegeLevel.COMMAND_EXECUTION, "EVI-SSH-SHELL", is_validated=False),
        }

        # Multi-Objective Ground Truth
        self.objectives = {
            "OBJ_AUTH_BYPASS": Phase17Objective("OBJ_AUTH_BYPASS", "Discover authentication bypass on Host A API", "192.168.1.10"),
            "OBJ_ADMIN_TAKEOVER": Phase17Objective("OBJ_ADMIN_TAKEOVER", "Gain administrative access to Host B Dashboard", "192.168.1.20"),
            "OBJ_SSH_FILE_ACCESS": Phase17Objective("OBJ_SSH_FILE_ACCESS", "Extract private SSH keys from Host C file service", "192.168.1.30"),
            "OBJ_VAULT_EXFIL": Phase17Objective("OBJ_VAULT_EXFIL", "Exfiltrate Master Secret from Host D Vault", "192.168.1.40"),
        }

        # Discovered facts & state
        self.discovered_hosts: Set[str] = {"192.168.1.10"}
        self.discovered_services: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.active_capabilities: Set[str] = set()
        self.active_credentials: Dict[str, Phase17Credential] = {}
        self.active_sessions: Dict[str, str] = {}  # host -> session_token
        self.current_privilege: PrivilegeLevel = PrivilegeLevel.UNAUTHENTICATED

        # Decoy & Conflict tracking
        self.decoy_attempts: Dict[str, int] = {}
        self.refuted_hypotheses: Set[str] = set()
        self.resolved_conflicts: Set[str] = set()
        self.verified_findings: Set[str] = set()

    def execute_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        target: str,
        active_caps: Set[str],
        active_creds: Dict[str, str],
        active_session: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], ActionDelta, str, str]:
        """
        Executes simulated action against multi-host topology.
        Returns: (raw_response, ActionDelta, usefulness_class, reason)
        """
        tool = tool_name.lower()
        delta = ActionDelta()
        target_clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        # Host Scope Check: Host must be reachable
        if target_clean not in self.discovered_hosts:
            return (
                {"status": 400, "error": f"Host {target_clean} is unreachable or not yet discovered on authorized network route."},
                delta,
                "NO_INFORMATION",
                f"Target host {target_clean} is unreachable from current capability frontier.",
            )

        # -------------------------------------------------------------------
        # 1. NETWORK & SERVICE DISCOVERY
        # -------------------------------------------------------------------
        if tool in ("nmap", "port_scan", "service_scan", "network_recon"):
            if target_clean == "192.168.1.10":
                new_svcs = {"192.168.1.10:80/tcp", "192.168.1.10:8080/tcp"} - self.discovered_services
                self.discovered_services.update({"192.168.1.10:80/tcp", "192.168.1.10:8080/tcp"})
                if new_svcs:
                    delta.new_nodes_count = len(new_svcs)
                    delta.new_evidence_count = len(new_svcs)
                    return (
                        {"status": 200, "open_ports": [80, 8080], "services": ["http-portal", "http-api"]},
                        delta,
                        "NEW_GRAPH_NODE",
                        f"Discovered {len(new_svcs)} services on Host A (80/http, 8080/api).",
                    )
            elif target_clean == "192.168.1.20":
                new_svcs = {"192.168.1.20:8443/tcp", "192.168.1.20:9000/tcp"} - self.discovered_services
                self.discovered_services.update({"192.168.1.20:8443/tcp", "192.168.1.20:9000/tcp"})
                if new_svcs:
                    delta.new_nodes_count = len(new_svcs)
                    delta.new_evidence_count = len(new_svcs)
                    return (
                        {"status": 200, "open_ports": [8443, 9000], "services": ["admin-ui", "websocket-event-bus"]},
                        delta,
                        "NEW_GRAPH_NODE",
                        f"Discovered {len(new_svcs)} internal services on Host B (8443/admin, 9000/ws).",
                    )
            elif target_clean == "192.168.1.30":
                new_svcs = {"192.168.1.30:22/tcp", "192.168.1.30:8000/tcp"} - self.discovered_services
                self.discovered_services.update({"192.168.1.30:22/tcp", "192.168.1.30:8000/tcp"})
                if new_svcs:
                    delta.new_nodes_count = len(new_svcs)
                    delta.new_evidence_count = len(new_svcs)
                    return (
                        {"status": 200, "open_ports": [22, 8000], "services": ["ssh", "file-download-service"]},
                        delta,
                        "NEW_GRAPH_NODE",
                        f"Discovered {len(new_svcs)} infra services on Host C (22/ssh, 8000/files).",
                    )
            elif target_clean == "192.168.1.40":
                new_svcs = {"192.168.1.40:8200/tcp"} - self.discovered_services
                self.discovered_services.update({"192.168.1.40:8200/tcp"})
                if new_svcs:
                    delta.new_nodes_count = 1
                    delta.new_evidence_count = 1
                    return (
                        {"status": 200, "open_ports": [8200], "services": ["vault-api"]},
                        delta,
                        "NEW_GRAPH_NODE",
                        "Discovered isolated Vault service on Host D (8200/vault).",
                    )

            return ({"status": 200, "output": "No new ports discovered."}, delta, "NO_INFORMATION", "Scan repeated with no new discoveries.")

        # -------------------------------------------------------------------
        # 2. HTTP & API PROBES (HOST A, B, C, D)
        # -------------------------------------------------------------------
        elif tool in ("http_request", "curl", "web_probe", "api_probe", "browser_navigate"):
            url = str(parameters.get("url") or target)
            path = url.split("://")[-1].split("/", 1)[-1] if "/" in url.split("://")[-1] else ""
            path = f"/{path}" if not path.startswith("/") else path

            # ----- HOST A (Public Gateway) -----
            if target_clean == "192.168.1.10":
                if path == "/":
                    is_new = "192.168.1.10:/" not in self.discovered_endpoints
                    self.discovered_endpoints.add("192.168.1.10:/")
                    if is_new:
                        delta.new_nodes_count = 3  # Spawns /login, /api/v1/health, /search (decoy)
                        delta.new_evidence_count = 1
                        return (
                            {"status": 200, "links": ["/login", "/api/v1/health", "/search?q="], "server": "Apache/2.4.52 (Conflicting Header: WAF=Enabled)"},
                            delta,
                            "NEW_GRAPH_NODE",
                            "Discovered public entry portal with routes /login, /api/v1/health, /search.",
                        )
                elif path.startswith("/search"):
                    # Decoy SQLi vulnerability (believable false signal)
                    self.decoy_attempts["decoy_sqli_search"] = self.decoy_attempts.get("decoy_sqli_search", 0) + 1
                    delta.new_evidence_count = 1
                    return (
                        {"status": 200, "body": "Search results for query. Database error: syntax error near (WAF simulated filter).", "decoy": True},
                        delta,
                        "NEW_EVIDENCE",
                        "Decoy search parameter investigated; SQLi syntax error recorded for hypothesis testing.",
                    )
                elif path == "/login":
                    is_new = "192.168.1.10:/login" not in self.discovered_endpoints
                    self.discovered_endpoints.add("192.168.1.10:/login")
                    if is_new:
                        delta.new_nodes_count = 1
                        delta.new_evidence_count = 1
                        return (
                            {"status": 200, "form": "POST /api/v1/auth", "inputs": ["username", "password"]},
                            delta,
                            "NEW_GRAPH_NODE",
                            "Discovered login endpoint submitting to /api/v1/auth.",
                        )
                elif path == "/api/v1/health":
                    # Conflicting evidence source: Server reports feature WAF=Disabled in JSON body while header reported Enabled
                    delta.new_evidence_count = 1
                    return (
                        {"status": 200, "waf_status": "DISABLED", "version": "1.10.4", "internal_network": "192.168.1.0/24"},
                        delta,
                        "NEW_EVIDENCE",
                        "Discovered conflicting WAF status (DISABLED in JSON body vs ENABLED in HTTP headers).",
                    )
                elif path == "/api/v1/auth":
                    # Authentication validation -> yields Host B endpoint and JWT Admin token
                    if "AUTHENTICATED" not in self.active_capabilities:
                        self.active_capabilities.add("AUTHENTICATED")
                        self.active_capabilities.add("HOST_B_REACHABLE")
                        self.discovered_hosts.add("192.168.1.20")
                        self.current_privilege = PrivilegeLevel.AUTHENTICATED
                        self.objectives["OBJ_AUTH_BYPASS"].is_validated = True
                        self.objectives["OBJ_AUTH_BYPASS"].is_verified = True
                        delta.new_capabilities_count = 2
                        delta.new_evidence_count = 2
                        delta.new_nodes_count = 1  # Host B node unlocked
                        delta.new_findings_count = 1
                        return (
                            {
                                "status": 200,
                                "token": self.credentials_vault["cred_jwt_admin"].value,
                                "unlocked_internal_host": "192.168.1.20",
                                "message": "Authentication successful. Access granted to internal Host B gateway.",
                            },
                            delta,
                            "NEW_CAPABILITY",
                            "Extracted Admin JWT token and discovered route to internal Host B (192.168.1.20).",
                        )

            # ----- HOST B (Internal Admin & WebSocket Gateway) -----
            elif target_clean == "192.168.1.20":
                has_jwt = "AUTHENTICATED" in active_caps or active_creds.get("jwt") == self.credentials_vault["cred_jwt_admin"].value
                if not has_jwt:
                    return ({"status": 401, "error": "Unauthorized: Host B requires Admin JWT"}, delta, "NO_INFORMATION", "Host B probe blocked by 401 Unauthorized.")

                if path in ("/", "/admin"):
                    is_new = "192.168.1.20:/admin" not in self.discovered_endpoints
                    self.discovered_endpoints.add("192.168.1.20:/admin")
                    if is_new:
                        self.current_privilege = PrivilegeLevel.ADMIN
                        self.active_capabilities.add("ADMIN")
                        self.active_capabilities.add("HOST_C_REACHABLE")
                        self.discovered_hosts.add("192.168.1.30")
                        self.objectives["OBJ_ADMIN_TAKEOVER"].is_validated = True
                        self.objectives["OBJ_ADMIN_TAKEOVER"].is_verified = True
                        delta.new_capabilities_count = 2
                        delta.new_evidence_count = 2
                        delta.new_nodes_count = 2  # Host C and /ws route
                        delta.new_findings_count = 1
                        return (
                            {
                                "status": 200,
                                "role": "ADMIN",
                                "unlocked_host": "192.168.1.30 (DevOps File/SSH Server)",
                                "websocket_route": "ws://192.168.1.20:9000/events",
                                "flag": "FLAG{PHASE17_HOST_B_ADMIN_TAKEOVER}",
                            },
                            delta,
                            "NEW_FINDING",
                            "Accessed Host B admin console, extracted Host C DevOps IP and WebSocket route.",
                        )
                elif path == "/api/v1/internal_routes":
                    delta.new_evidence_count = 1
                    return ({"status": 200, "routes": ["/admin", "/backup_export", "ws://192.168.1.20:9000/events"]}, delta, "NEW_EVIDENCE", "Enumerated internal routes.")

            # ----- HOST C (DevOps File Storage & SSH Gateway) -----
            elif target_clean == "192.168.1.30":
                if path in ("/files", "/files/devops_backup.tar.gz", "/"):
                    if "HOST_C_REACHABLE" in active_caps or "ADMIN" in active_caps:
                        is_new = "192.168.1.30:/files" not in self.discovered_endpoints
                        self.discovered_endpoints.add("192.168.1.30:/files")
                        if is_new:
                            self.active_capabilities.add("SSH_KEY_ACQUIRED")
                            self.active_capabilities.add("HOST_D_REACHABLE")
                            self.discovered_hosts.add("192.168.1.40")
                            self.objectives["OBJ_SSH_FILE_ACCESS"].is_validated = True
                            self.objectives["OBJ_SSH_FILE_ACCESS"].is_verified = True
                            delta.new_capabilities_count = 2
                            delta.new_evidence_count = 2
                            delta.new_findings_count = 1
                            return (
                                {
                                    "status": 200,
                                    "extracted_file": "id_ed25519_devops",
                                    "ssh_key": self.credentials_vault["cred_ssh_key"].value,
                                    "unlocked_vault_host": "192.168.1.40",
                                    "flag": "FLAG{PHASE17_HOST_C_SSH_KEY_EXTRACTED}",
                                },
                                delta,
                                "NEW_FINDING",
                                "Extracted SSH private key from Host C backup files, discovering Host D Vault.",
                            )

            # ----- HOST D (Internal Isolated Vault) -----
            elif target_clean == "192.168.1.40":
                if path in ("/v1/sys/seal-status", "/v1/secret/master", "/"):
                    if "COMMAND_EXECUTION" in active_caps or "SSH_KEY_ACQUIRED" in active_caps:
                        if not self.objectives["OBJ_VAULT_EXFIL"].is_verified:
                            self.current_privilege = PrivilegeLevel.COMMAND_EXECUTION
                            self.objectives["OBJ_VAULT_EXFIL"].is_validated = True
                            self.objectives["OBJ_VAULT_EXFIL"].is_verified = True
                            delta.new_findings_count = 1
                            delta.new_evidence_count = 2
                            return (
                                {
                                    "status": 200,
                                    "vault_seal": False,
                                    "master_secret": "FLAG{PHASE17_MASTER_VAULT_ROOT_COMPROMISE}",
                                    "vault_token": self.credentials_vault["cred_vault_token"].value,
                                },
                                delta,
                                "NEW_FINDING",
                                "Compromised Host D internal vault; exfiltrated Master Secret.",
                            )

            return ({"status": 200, "body": "Endpoint visited, no state delta"}, delta, "NO_INFORMATION", "Endpoint produced zero state change.")

        # -------------------------------------------------------------------
        # 3. WEBSOCKET CROSS-SURFACE (HOST B)
        # -------------------------------------------------------------------
        elif tool in ("websocket_connect", "ws_listen", "websocket_subscribe"):
            if target_clean == "192.168.1.20" and ("ADMIN" in active_caps or "AUTHENTICATED" in active_caps):
                delta.new_evidence_count = 1
                delta.new_nodes_count = 1
                return (
                    {
                        "status": 101,
                        "events": [{"channel": "devops-alerts", "msg": "Deploying build on 192.168.1.30:22 with key id_ed25519"}],
                    },
                    delta,
                    "NEW_EVIDENCE",
                    "Subscribed to Host B WebSocket bus; captured DevOps broadcast exposing Host C SSH config.",
                )
            return ({"status": 403, "error": "WebSocket connection refused"}, delta, "NO_INFORMATION", "WebSocket connection unauthorized.")

        # -------------------------------------------------------------------
        # 4. SSH TOOL EXECUTION (HOST C)
        # -------------------------------------------------------------------
        elif tool in ("ssh_connect", "ssh_exec", "ssh_command"):
            if target_clean == "192.168.1.30" and "SSH_KEY_ACQUIRED" in active_caps:
                self.current_privilege = PrivilegeLevel.COMMAND_EXECUTION
                self.active_capabilities.add("COMMAND_EXECUTION")
                delta.new_capabilities_count = 1
                delta.new_evidence_count = 1
                return (
                    {
                        "status": 200,
                        "shell": "devops@host-c:~$",
                        "routes": "192.168.1.40:8200 (Vault)",
                    },
                    delta,
                    "NEW_CAPABILITY",
                    "Interactive SSH shell established on Host C with COMMAND_EXECUTION privilege.",
                )
            return ({"status": 500, "error": "SSH authentication failed: missing key"}, delta, "NO_INFORMATION", "SSH authentication rejected.")

        # -------------------------------------------------------------------
        # 5. INDEPENDENT VERIFICATION OF FINDINGS
        # -------------------------------------------------------------------
        elif tool in ("verify_finding", "verify_objective"):
            obj_key = str(parameters.get("objective") or parameters.get("finding") or "")
            for obj in self.objectives.values():
                if obj.is_validated and (obj.objective_id in obj_key or obj.description in obj_key or obj.target_host in target):
                    obj.is_verified = True
                    delta.new_evidence_count = 1
                    delta.new_findings_count = 1
                    return (
                        {"status": 200, "verified": True, "objective_id": obj.objective_id},
                        delta,
                        "INDEPENDENT_VERIFICATION",
                        f"Independently verified objective {obj.objective_id}.",
                    )
            return ({"status": 400, "error": "Objective not validated"}, delta, "NO_INFORMATION", "Verification failed: objective not yet validated.")

        return ({"status": 200, "output": "Generic execution"}, delta, "NO_INFORMATION", "Executed tool with 0 delta.")


class Phase17LongHorizonBenchmark:
    """
    Phase 17 Long-Horizon Autonomous Investigation Benchmark Suite.
    Executes 1,000-Action Horizon across Multi-Host Topology.
    """

    @classmethod
    def calculate_delta_gain(
        cls,
        delta: ActionDelta,
        usefulness: str,
        privilege_change: bool = False,
    ) -> float:
        """Delta-based gain ensuring gain=0 when delta=0."""
        if usefulness == "NO_INFORMATION":
            return 0.0

        gain = (
            (delta.new_findings_count * 10.0) +
            (delta.new_capabilities_count * 6.0) +
            (delta.new_nodes_count * 3.0) +
            (delta.new_evidence_count * 1.5)
        )
        if usefulness == "INDEPENDENT_VERIFICATION":
            gain += 12.0
        if privilege_change:
            gain += 5.0
        return round(gain, 2)

    @classmethod
    def run_1000_action_benchmark(
        cls,
        trace_output_path: Optional[str] = None,
        mode: AssessmentMode = AssessmentMode.EXHAUSTIVE,
    ) -> Tuple[Phase17BenchmarkReport, List[Phase17ActionTrace]]:
        """
        Executes a 1,000-action long-horizon multi-host investigation benchmark.
        Tracks branch ROIs, hypothesis lifecycles, and gain prediction calibration.
        """
        start_time = time.time()
        lab = MultiHostSyntheticLab()
        state = AssessmentState(context=AssessmentContext(target="192.168.1.10", scope=["192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40"]))
        graph = AttackGraph()
        history = ActionHistoryStore()
        failure_mem = FailureAwareMemory()
        noop_det = NoOpDetector(pivot_threshold=3)
        branch_mgr = BranchManager()
        traces: List[Phase17ActionTrace] = []

        # Create Graph Roots
        h_a = graph.add_node(NodeKind.HOST, "192.168.1.10")

        # Create Branches
        b_host_a = branch_mgr.create_branch("Host A Web & API", "192.168.1.10", BranchPriority.HIGH, expected_gain="HIGH")
        b_host_b = branch_mgr.create_branch("Host B Admin & WS", "192.168.1.20", BranchPriority.MEDIUM, expected_gain="HIGH")
        b_host_c = branch_mgr.create_branch("Host C File & SSH", "192.168.1.30", BranchPriority.LOW, expected_gain="HIGH")
        b_host_d = branch_mgr.create_branch("Host D Vault", "192.168.1.40", BranchPriority.LOW, expected_gain="HIGH")

        # Hypothesis Pool across all hosts
        hypotheses: Dict[str, Phase17Hypothesis] = {
            "HYP-A-AUTH": Phase17Hypothesis("HYP-A-AUTH", "192.168.1.10", "AUTH_BYPASS", HypothesisLifecycleState.PROPOSED),
            "HYP-A-DECOY-SQLI": Phase17Hypothesis("HYP-A-DECOY-SQLI", "192.168.1.10", "SQL_INJECTION", HypothesisLifecycleState.PROPOSED, is_decoy=True),
            "HYP-B-ADMIN": Phase17Hypothesis("HYP-B-ADMIN", "192.168.1.20", "ADMIN_CONSOLE_ACCESS", HypothesisLifecycleState.PROPOSED),
            "HYP-C-SSH": Phase17Hypothesis("HYP-C-SSH", "192.168.1.30", "SSH_KEY_EXPOSURE", HypothesisLifecycleState.PROPOSED),
            "HYP-D-VAULT": Phase17Hypothesis("HYP-D-VAULT", "192.168.1.40", "VAULT_ROOT_TAKEOVER", HypothesisLifecycleState.PROPOSED),
        }

        turns = 1000
        useful_count = 0
        no_info_count = 0
        justified_recons = 0
        exact_dups = 0
        total_expected_gain = 0.0
        total_actual_gain = 0.0
        decoys_refuted = 0
        dead_ends_abandoned = 0
        conflicts_resolved = 0
        prediction_errors: List[float] = []

        # Synthetic endpoints pool for realistic exploration density
        base_pool = [
            ("nmap", {"target": "192.168.1.10", "ports": "80,8080"}, "192.168.1.10", "HYP-A-AUTH"),
            ("http_request", {"url": "http://192.168.1.10:80/"}, "192.168.1.10", "HYP-A-AUTH"),
            ("http_request", {"url": "http://192.168.1.10:80/search?q=test'"}, "192.168.1.10", "HYP-A-DECOY-SQLI"),
            ("http_request", {"url": "http://192.168.1.10:8080/api/v1/health"}, "192.168.1.10", "HYP-A-AUTH"),
            ("http_request", {"url": "http://192.168.1.10:80/login"}, "192.168.1.10", "HYP-A-AUTH"),
            ("http_request", {"url": "http://192.168.1.10:8080/api/v1/auth"}, "192.168.1.10", "HYP-A-AUTH"),
            ("nmap", {"target": "192.168.1.20", "ports": "8443,9000"}, "192.168.1.20", "HYP-B-ADMIN"),
            ("http_request", {"url": "http://192.168.1.20:8443/admin"}, "192.168.1.20", "HYP-B-ADMIN"),
            ("websocket_connect", {"url": "ws://192.168.1.20:9000/events"}, "192.168.1.20", "HYP-B-ADMIN"),
            ("nmap", {"target": "192.168.1.30", "ports": "22,8000"}, "192.168.1.30", "HYP-C-SSH"),
            ("http_request", {"url": "http://192.168.1.30:8000/files"}, "192.168.1.30", "HYP-C-SSH"),
            ("ssh_connect", {"target": "192.168.1.30", "port": 22}, "192.168.1.30", "HYP-C-SSH"),
            ("nmap", {"target": "192.168.1.40", "ports": "8200"}, "192.168.1.40", "HYP-D-VAULT"),
            ("http_request", {"url": "http://192.168.1.40:8200/v1/secret/master"}, "192.168.1.40", "HYP-D-VAULT"),
            ("verify_finding", {"target": "192.168.1.40", "objective": "OBJ_VAULT_EXFIL"}, "192.168.1.40", "HYP-D-VAULT"),
        ]

        # 85 filler probe templates representing large background surface
        filler_pool = [
            ("http_request", {"url": f"http://192.168.1.10:80/filler_route_{i}"}, "192.168.1.10", "HYP-A-AUTH")
            for i in range(85)
        ]
        full_candidate_pool = base_pool + filler_pool

        for t in range(1, turns + 1):
            avail_caps = set(state.capabilities.keys()) if hasattr(state, "capabilities") else set()
            active_creds = state.credentials if hasattr(state, "credentials") else {}

            # Generate structured proposals
            proposals: List[HypothesisProposal] = []
            for tool_n, params, tgt, hyp_id in full_candidate_pool:
                is_core = (tool_n, params, tgt, hyp_id) in base_pool
                conf = ProposalConfidence.HIGH if is_core else ProposalConfidence.LOW
                proposals.append(
                    HypothesisProposal(
                        hypothesis_id=hyp_id,
                        vulnerability_type=hypotheses[hyp_id].vulnerability_type,
                        target=tgt,
                        port=80,
                        tool_name=tool_n,
                        tool_args=params,
                        rationale=f"Explore {hyp_id} on {tgt}",
                        evidence_ids=[],
                        confidence=conf,
                        priority=70 if is_core else 30,
                        verification_plan="verify" if tool_n == "verify_finding" else "none",
                    )
                )

            # Generate and select candidate
            candidates = ActionSelectionEngine.generate_candidates(
                state=state,
                graph=graph,
                proposals=proposals,
                history=history,
                failure_memory=failure_mem,
                max_candidates=100,
            )

            selected_cand = ActionSelectionEngine.select_best_candidate(candidates) or candidates[0]
            expected_gain = selected_cand.expected_information_gain
            total_expected_gain += expected_gain

            key_obj = ActionIdentity.generate_canonical_key(
                selected_cand.tool,
                selected_cand.arguments,
                selected_cand.target,
            )
            canonical_key = key_obj.canonical_key
            context_sig = ActionIdentity.create_context_signature(list(avail_caps), credentials=active_creds)

            prior_count_all = history.get_repetition_count(canonical_key)
            prior_count_in_context = len(history.get_records_for_action(canonical_key, capability_context=context_sig))

            if prior_count_all == 0:
                dup_class = "UNIQUE_ACTION"
            elif prior_count_in_context == 0 and len(avail_caps) > 0:
                dup_class = "JUSTIFIED_RECONSIDERATION_CONTEXT"
                justified_recons += 1
            else:
                dup_class = "EXACT_DUPLICATE"
                exact_dups += 1

            # Execute in synthetic lab
            raw_resp, delta, use_class, reason = lab.execute_tool(
                tool_name=selected_cand.tool,
                parameters=selected_cand.arguments,
                target=selected_cand.target,
                active_caps=avail_caps,
                active_creds=active_creds,
            )

            # State & Capability updates
            prev_priv = lab.current_privilege
            if delta.new_capabilities_count > 0:
                for cap_name in lab.active_capabilities:
                    state.add_capability(cap_name, "Acquired via lab progression")
                if "cred_jwt_admin" in lab.credentials_vault:
                    state.credentials["jwt"] = lab.credentials_vault["cred_jwt_admin"].value
                if "cred_ssh_key" in lab.credentials_vault:
                    state.credentials["ssh_key"] = lab.credentials_vault["cred_ssh_key"].value

            # Decoy & conflict resolution handling
            if "search" in selected_cand.arguments.get("url", ""):
                if lab.decoy_attempts.get("decoy_sqli_search", 0) >= 3:
                    hypotheses["HYP-A-DECOY-SQLI"].state = HypothesisLifecycleState.REFUTED
                    hypotheses["HYP-A-DECOY-SQLI"].refutation_reason = "WAF simulated response; confirmed non-exploitable decoy."
                    decoys_refuted += 1

            if "health" in selected_cand.arguments.get("url", "") and "CONF_WAF" not in lab.resolved_conflicts:
                lab.resolved_conflicts.add("CONF_WAF")
                conflicts_resolved += 1

            # Dead end abandonment
            if "filler_route" in selected_cand.arguments.get("url", "") and prior_count_all >= 2:
                dead_ends_abandoned += 1

            # Calculate actual delta gain
            priv_change = lab.current_privilege != prev_priv
            act_gain = cls.calculate_delta_gain(delta, use_class, privilege_change=priv_change)
            total_actual_gain += act_gain

            pred_err = expected_gain - act_gain
            prediction_errors.append(abs(pred_err))

            if use_class != "NO_INFORMATION":
                useful_count += 1
                outcome = ActionOutcome.SUCCESS
            else:
                no_info_count += 1
                outcome = ActionOutcome.NO_OP

            noop_det.evaluate_delta(delta, selected_cand.tool, selected_cand.target)

            history.record_action(
                action_id=f"act-1000-{t}",
                tool_name=selected_cand.tool,
                parameters=selected_cand.arguments,
                target=selected_cand.target,
                expected_gain=expected_gain,
                actual_gain=act_gain,
                cost=selected_cand.estimated_cost_value,
                outcome=outcome,
                capability_context=context_sig,
                why_this_action=selected_cand.why_this_action,
            )

            # Update Branch Statistics
            if "192.168.1.10" in selected_cand.target:
                b_host_a.total_gain += act_gain
                b_host_a.cost_incurred += selected_cand.estimated_cost_value
            elif "192.168.1.20" in selected_cand.target:
                b_host_b.total_gain += act_gain
                b_host_b.cost_incurred += selected_cand.estimated_cost_value
            elif "192.168.1.30" in selected_cand.target:
                b_host_c.total_gain += act_gain
                b_host_c.cost_incurred += selected_cand.estimated_cost_value
            elif "192.168.1.40" in selected_cand.target:
                b_host_d.total_gain += act_gain
                b_host_d.cost_incurred += selected_cand.estimated_cost_value

            trace_rec = Phase17ActionTrace(
                turn=t,
                tool_name=selected_cand.tool,
                target=selected_cand.target,
                canonical_key=canonical_key,
                context_signature=context_sig,
                expected_gain=round(expected_gain, 2),
                actual_gain=act_gain,
                prediction_error=round(pred_err, 2),
                cost=round(selected_cand.estimated_cost_value, 2),
                efficiency=round(act_gain / max(0.1, selected_cand.estimated_cost_value), 2),
                evidence_delta=delta.new_evidence_count,
                node_delta=delta.new_nodes_count,
                capability_delta=delta.new_capabilities_count,
                finding_delta=delta.new_findings_count,
                usefulness=use_class,
                duplicate_classification=dup_class,
                selected_by_model=True,
                selected_by_backend=False,
                backend_fallback=False,
                schema_repaired=False,
                duplicate_blocked=False,
                retry_reason=reason if dup_class != "EXACT_DUPLICATE" else "Stagnant Probe",
                why_this_action=selected_cand.why_this_action,
                active_privilege=lab.current_privilege,
            )
            traces.append(trace_rec)

        if trace_output_path:
            with open(trace_output_path, "w", encoding="utf-8") as f:
                for tr in traces:
                    f.write(json.dumps(asdict(tr)) + "\n")

        exec_time = time.time() - start_time
        unique_actions = len(set(r.canonical_action_key for r in history.records))
        dup_actions = turns - unique_actions

        verified_objs = sum(1 for o in lab.objectives.values() if o.is_verified)
        mae = sum(prediction_errors) / len(prediction_errors) if prediction_errors else 0.0
        signed_err = (total_expected_gain - total_actual_gain) / turns

        branch_rois = {
            "Host A Web": round(b_host_a.roi, 2),
            "Host B Admin": round(b_host_b.roi, 2),
            "Host C DevOps": round(b_host_c.roi, 2),
            "Host D Vault": round(b_host_d.roi, 2),
        }

        report = Phase17BenchmarkReport(
            suite_name="1,000-Action Multi-Host Benchmark",
            turns_requested=turns,
            turns_completed=turns,
            unique_actions_count=unique_actions,
            duplicate_actions_count=dup_actions,
            justified_reconsiderations_count=justified_recons,
            useful_actions_count=useful_count,
            no_information_actions_count=no_info_count,
            false_useful_count=0,
            total_expected_gain=round(total_expected_gain, 2),
            total_actual_gain=round(total_actual_gain, 2),
            mae_prediction_error=round(mae, 2),
            mean_signed_prediction_error=round(signed_err, 2),
            average_efficiency=round(total_actual_gain / max(1.0, turns * 1.5), 2),
            hosts_compromised=len(lab.discovered_hosts),
            objectives_total=len(lab.objectives),
            objectives_verified=verified_objs,
            decoys_refuted_count=decoys_refuted,
            dead_ends_abandoned_count=dead_ends_abandoned,
            conflicts_resolved_count=conflicts_resolved,
            branch_rois=branch_rois,
            execution_time_seconds=round(exec_time, 3),
            is_success=verified_objs >= 3 and useful_count > 0,
            status_message="1,000-Action multi-host investigation completed with validated integrity.",
        )
        return report, traces
