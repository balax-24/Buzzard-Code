import uuid
import datetime
from typing import List, Dict, Any, Optional
from model.schemas import Finding, Evidence, Severity, Confidence, EvidenceType
from storage.db import StorageManager

def evidence_save(
    session_id: str = "default",
    type: str = "other",
    target: str = "",
    description: str = "",
    data: Any = None,
    storage_manager: Optional[StorageManager] = None,
) -> Dict[str, Any]:
    """
    Saves an evidence item (log, output, config, observation) to the assessment store.
    """
    try:
        ev_type = EvidenceType(type.lower())
    except Exception:
        ev_type = EvidenceType.OTHER

    evidence_id = f"EVI-{uuid.uuid4().hex[:6]}"
    timestamp = datetime.datetime.now().isoformat()

    evidence = Evidence(
        id=evidence_id,
        type=ev_type,
        target=target or "local",
        description=description or f"Evidence {evidence_id}",
        data=data or {},
        timestamp=timestamp,
    )

    if storage_manager is not None:
        try:
            storage_manager.add_evidence(session_id, evidence)
        except Exception as e:
            return {"status": "error", "error": f"Failed to persist evidence: {str(e)}", "evidence_id": evidence_id}

    import json
    return json.dumps({
        "status": "success",
        "evidence_id": evidence_id,
        "type": ev_type.value,
        "target": target or "local",
        "description": description,
        "timestamp": timestamp,
    }, indent=2)


def report_generate(
    session_id: str = "default",
    summary: str = "",
    title: str = "Security Assessment Report",
    storage_manager: Optional[StorageManager] = None,
    state: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Generates a structured security assessment report from recorded findings and evidence.
    """
    timestamp = datetime.datetime.now().isoformat()
    findings_list = []
    evidence_count = 0

    if state is not None and hasattr(state, "findings"):
        for f in state.findings:
            if isinstance(f, dict):
                findings_list.append(f)
            elif hasattr(f, "to_dict"):
                findings_list.append(f.to_dict())
            else:
                findings_list.append(str(f))
    elif storage_manager is not None:
        try:
            db_findings = storage_manager.get_findings(session_id)
            for f in db_findings:
                if hasattr(f, "dict"):
                    findings_list.append(f.dict())
                else:
                    findings_list.append(str(f))
        except Exception:
            pass

    if storage_manager is not None:
        try:
            evs = storage_manager.get_evidence(session_id)
            evidence_count = len(evs)
        except Exception:
            pass

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_list:
        if isinstance(f, dict):
            sev = f.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

    report_content = (
        f"# {title}\n\n"
        f"**Session ID:** `{session_id}`  \n"
        f"**Generated At:** {timestamp}  \n"
        f"**Total Findings:** {len(findings_list)}  \n"
        f"**Supporting Evidence Count:** {evidence_count}  \n\n"
        f"## Executive Summary\n{summary or 'No executive summary provided.'}\n\n"
        f"## Severity Breakdown\n"
        f"- Critical: {severity_counts['critical']}\n"
        f"- High: {severity_counts['high']}\n"
        f"- Medium: {severity_counts['medium']}\n"
        f"- Low: {severity_counts['low']}\n"
        f"- Info: {severity_counts['info']}\n\n"
        f"## Verified Findings\n"
    )

    if not findings_list:
        report_content += "_No findings recorded for this session._\n"
    else:
        for idx, f in enumerate(findings_list, 1):
            if isinstance(f, dict):
                report_content += (
                    f"### {idx}. {f.get('title', 'Untitled Finding')}\n"
                    f"- **Severity:** {f.get('severity', 'medium').upper()}\n"
                    f"- **Asset:** {f.get('affected_asset', 'N/A')}\n"
                    f"- **Status:** {f.get('verification_status', f.get('status', 'recorded'))}\n"
                    f"- **Description:** {f.get('description', '')}\n\n"
                )

    import json
    return json.dumps({
        "status": "success",
        "session_id": session_id,
        "title": title,
        "timestamp": timestamp,
        "summary": summary,
        "findings_count": len(findings_list),
        "evidence_count": evidence_count,
        "severity_counts": severity_counts,
        "report_markdown": report_content,
    }, indent=2)


def log_evidence(
    session_id: str,
    storage_manager: StorageManager,
    type: str,
    target: str,
    description: str,
    data: Any,
) -> str:
    """
    Logs support evidence (e.g. terminal logs, network HTTP response, config file) for a session.
    """
    res = evidence_save(
        session_id=session_id,
        type=type,
        target=target,
        description=description,
        data=data,
        storage_manager=storage_manager,
    )
    import json
    if isinstance(res, str):
        try:
            res_dict = json.loads(res)
        except Exception:
            res_dict = {"status": "error", "error": res}
    else:
        res_dict = res

    if res_dict.get("status") == "error":
        return f"TOOL ERROR: {res_dict.get('error')}"
    return f"Evidence logged successfully with ID: {res_dict.get('evidence_id')}"


def log_finding(
    session_id: str,
    storage_manager: Optional[StorageManager] = None,
    title: str = "",
    severity: str = "medium",
    confidence: str = "medium",
    affected_asset: str = "",
    description: str = "",
    impact: str = "",
    verification: str = "",
    remediation: str = "",
    evidence_ids: Optional[List[str]] = None,
    state: Optional[Any] = None,
) -> str:
    """
    Logs a security finding or vulnerability for a session.
    """
    try:
        sev = Severity(severity.lower())
    except ValueError:
        return f"TOOL ERROR: Invalid severity: '{severity}'. Must be one of {[s.value for s in Severity]}"
        
    try:
        conf = Confidence(confidence.lower())
    except ValueError:
        return f"TOOL ERROR: Invalid confidence: '{confidence}'. Must be one of {[c.value for c in Confidence]}"

    # Secret redaction on inputs
    from reports.report_generator import redact_secrets
    title_clean = str(redact_secrets(title))
    desc_clean = str(redact_secrets(description))
    impact_clean = str(redact_secrets(impact))
    verif_clean = str(redact_secrets(verification))
    remed_clean = str(redact_secrets(remediation))

    finding_id = None
    is_verified = False
    verif_status = "UNVERIFIED"

    # Canonical Single Source of Truth: AssessmentState
    if state is not None:
        state_finding = state.record_finding(
            title=title_clean,
            severity=sev.value,
            description=desc_clean,
            evidence_ids=evidence_ids or [],
            proof=verif_clean,
            finding_id=None,
        )
        finding_id = state_finding.get("id")
        is_verified = state_finding.get("verified", False)
        verif_status = state_finding.get("verification_status", "UNVERIFIED")
    else:
        finding_id = f"FIND-{uuid.uuid4().hex[:6]}"
        is_verified = bool(evidence_ids)
        verif_status = "VERIFIED" if is_verified else "UNVERIFIED"

    # Mirror to storage persistence (never authoritative over AssessmentState)
    if storage_manager is not None:
        finding = Finding(
            id=finding_id,
            title=title_clean,
            severity=sev,
            confidence=conf if is_verified else Confidence.LOW,
            affected_asset=affected_asset,
            description=desc_clean,
            evidence=evidence_ids or [],
            impact=impact_clean,
            verification=verif_clean,
            remediation=remed_clean,
            status="active" if is_verified else "unconfirmed",
        )
        storage_manager.add_finding(session_id, finding)

    return f"Finding logged successfully with ID: {finding_id}"


def register_evidence_tools(registry):
    from tools.registry import ToolCategory
    # Dotted & canonical names
    registry.register(
        name="evidence_save",
        description="Saves evidence item (log, output, config, observation) to assessment store. Arguments: type (str), target (str), description (str), data (any).",
        func=evidence_save,
        sandbox_required=False,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=False,
        destructive=False,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10,
    )
    registry.register(
        name="report_generate",
        description="Generates a structured security assessment report from recorded findings and evidence. Arguments: summary (str), title (str, optional).",
        func=report_generate,
        sandbox_required=False,
        category=ToolCategory.AUTOMATION,
        risk_level="LOW",
        read_only=True,
        destructive=False,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=15,
    )
    registry.register(
        name="log_evidence",
        description="Logs support evidence (e.g. terminal logs, network HTTP response, config file) for a session. Arguments: type (str), target (str), description (str), data (any).",
        func=log_evidence,
        sandbox_required=False,
        category=ToolCategory.EVIDENCE,
        risk_level="LOW",
        read_only=False,
        destructive=False,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10,
    )
    registry.register(
        name="log_finding",
        description="Logs a security finding or vulnerability for a session. Arguments: title (str), severity (str), confidence (str), affected_asset (str), description (str), impact (str), verification (str), remediation (str), evidence_ids (list of strings, optional).",
        func=log_finding,
        sandbox_required=False,
        category=ToolCategory.EVIDENCE,
        risk_level="LOW",
        read_only=False,
        destructive=False,
        network_required=False,
        scope_required=False,
        approval_required=False,
        timeout=10,
    )
