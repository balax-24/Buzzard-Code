"""
Threat Modeling Engine.

Generates STRIDE and OWASP Top 10 threat scenarios based on discovered assets,
entry points, and architectural components.
See plan sections 18, 19 and Phase D.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any
from intelligence.asset_graph import AssetGraph, AssetType


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class ThreatScenario:
    """Individual threat scenario identified during threat modeling."""
    id: str
    category: STRIDECategory
    target_asset: str
    title: str
    description: str
    potential_impact: str
    testable_hypotheses: List[str] = field(default_factory=list)


class ThreatModeler:
    """
    Generates structured threat models from an AssetGraph.
    """
    def __init__(self, asset_graph: AssetGraph):
        self.graph = asset_graph

    def generate_threat_scenarios(self) -> List[ThreatScenario]:
        scenarios: List[ThreatScenario] = []
        counter = 1

        for node in self.graph.nodes.values():
            # 1. Endpoint threat modeling
            if node.type == AssetType.ENDPOINT:
                url = node.metadata.get("url", node.name)
                is_auth_required = node.metadata.get("auth_required", False)

                # Information Disclosure threat on any endpoint
                scenarios.append(ThreatScenario(
                    id=f"THR-{counter:03d}",
                    category=STRIDECategory.INFORMATION_DISCLOSURE,
                    target_asset=node.id,
                    title=f"Sensitive Data Exposure on {url}",
                    description=f"Endpoint {url} may expose unauthenticated metadata, debug info, or PII.",
                    potential_impact="Data leakage and attack surface expansion.",
                    testable_hypotheses=[f"Endpoint {url} returns sensitive headers or debug messages when queried with unusual headers."]
                ))
                counter += 1

                # Elevation of privilege / Broken access control
                if is_auth_required:
                    scenarios.append(ThreatScenario(
                        id=f"THR-{counter:03d}",
                        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                        target_asset=node.id,
                        title=f"Authentication Bypass / IDOR on {url}",
                        description=f"Protected endpoint {url} might fail to enforce object-level authorization across tenant accounts.",
                        potential_impact="Unauthorized account access or privilege escalation.",
                        testable_hypotheses=[f"Requests to {url} with modified tenant IDs or absent auth headers are permitted."]
                    ))
                    counter += 1

            # 2. Input Parameter threat modeling
            elif node.type == AssetType.PARAMETER:
                param_name = node.name
                scenarios.append(ThreatScenario(
                    id=f"THR-{counter:03d}",
                    category=STRIDECategory.TAMPERING,
                    target_asset=node.id,
                    title=f"Injection flaw in parameter '{param_name}'",
                    description=f"Input parameter '{param_name}' may be concatenated into database queries or rendered into DOM without encoding.",
                    potential_impact="Arbitrary query execution (SQLi) or client-side execution (XSS).",
                    testable_hypotheses=[f"Probing parameter '{param_name}' triggers database syntax errors or unencoded reflection."]
                ))
                counter += 1

        return scenarios
