"""
Cloud / container / IaC security capabilities. These are binary-gated
(trivy, checkov, kube-bench, prowler, scoutsuite) — the chains report
clearly when a tool is missing so the agent can suggest installation or
skip to the next capability. No fake results are produced.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from security_agent.tools.fallback import FallbackRunner, strategy_from_cmd


def _scan_with(tool: str, cmd: str, timeout: float = 300) -> Tuple[bool, str, str]:
    def strat(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
        if not runner.tool_available(tool):
            return False, f"'{tool}' not installed", (
                f"Install {tool} to run this scan (e.g. apt/pip/docker as documented). "
                "Skipping this capability.")
        target = kw.get("target") or kw.get("image") or kw.get("path") or kw.get("repo") or kw.get("url") or ""
        if not target:
            return False, "target required (image/path/repo)", ""
        res = runner.run_cmd(cmd.format(target=target), timeout=timeout)
        out = (res.get("stdout") or "").strip()
        if res.get("exit_code") not in (0, 1):
            return False, f"exit={res.get('exit_code')}", out
        if not out:
            return False, "empty output", ""
        return True, f"{tool} scan completed", out
    return strat


def cloud_scan_chain() -> List[Tuple[str, Any]]:
    return [("trivy-image", _scan_with(
        "trivy",
        "trivy image --no-progress --scanners vuln,secret,misconfig --severity HIGH,CRITICAL {target} 2>&1 | tail -60")),
        ("trivy-fs", _scan_with(
            "trivy",
            "trivy fs --no-progress --scanners vuln,secret,misconfig --severity HIGH,CRITICAL {target} 2>&1 | tail -60"))]


def iac_scan_chain() -> List[Tuple[str, Any]]:
    return [("checkov", _scan_with(
        "checkov",
        "checkov -d {target} --compact 2>&1 | tail -60", timeout=240)),
        ("tfsec", _scan_with(
            "tfsec",
            "tfsec {target} --no-color 2>&1 | tail -40", timeout=240))]


def k8s_scan_chain() -> List[Tuple[str, Any]]:
    return [("kube-bench", _scan_with(
        "kube-bench",
        "kube-bench run --targets master,node --json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(\"controls:\", len(d.get(\"Controls\", []))); [print(c[\"id\"], c[\"desc\"][:80]) for c in d.get(\"Controls\", [])]' 2>&1 | tail -30", timeout=300)),
        ("kube-hunter", _scan_with(
            "kube-hunter",
            "kube-hunter --remote {target} 2>&1 | tail -40", timeout=240))]


def cloud_iam_chain() -> List[Tuple[str, Any]]:
    return [("prowler", _scan_with(
        "prowler",
        "prowler aws -M text -F /tmp/prowler_out 2>&1 | tail -40", timeout=300)),
        ("scoutsuite", _scan_with(
            "scout",
            "scout aws 2>&1 | tail -30", timeout=300))]
