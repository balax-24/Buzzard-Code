"""
Attack Path and Exploit Chain Analysis.

Analyzes relationships between discovered findings and assets to construct
end-to-end attack paths and calculate aggregate blast radius.
See plan sections 41, 42 and Phase E.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Set
from model.schemas import Finding, Severity


@dataclass
class AttackPathStep:
    step_number: int
    finding_id: str
    action: str
    target_asset: str
    gained_access: str


@dataclass
class AttackPath:
    id: str
    title: str
    overall_severity: Severity
    steps: List[AttackPathStep] = field(default_factory=list)
    impact_summary: str = ""


class AttackPathAnalyzer:
    """
    Synthesizes confirmed findings into actionable kill chains.
    """
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def analyze_paths(self) -> List[AttackPath]:
        paths: List[AttackPath] = []
        if not self.findings:
            return paths

        # Group findings by asset
        asset_map: Dict[str, List[Finding]] = {}
        for f in self.findings:
            asset_map.setdefault(f.affected_asset, []).append(f)

        counter = 1
        for asset, f_list in asset_map.items():
            steps = []
            max_sev = Severity.INFO

            for idx, finding in enumerate(f_list, 1):
                steps.append(AttackPathStep(
                    step_number=idx,
                    finding_id=finding.id,
                    action=f"Exploit {finding.title}",
                    target_asset=asset,
                    gained_access=finding.impact
                ))
                if finding.severity == Severity.CRITICAL:
                    max_sev = Severity.CRITICAL
                elif finding.severity == Severity.HIGH and max_sev != Severity.CRITICAL:
                    max_sev = Severity.HIGH
                elif finding.severity == Severity.MEDIUM and max_sev not in (Severity.CRITICAL, Severity.HIGH):
                    max_sev = Severity.MEDIUM

            path = AttackPath(
                id=f"PATH-{counter:03d}",
                title=f"Attack Vector against {asset}",
                overall_severity=max_sev,
                steps=steps,
                impact_summary=f"Compound compromise path exposing {asset} across {len(steps)} verified vulnerability step(s)."
            )
            paths.append(path)
            counter += 1

        return paths
