"""
Benchmark Runner and Autonomous Evaluation Framework.

Executes standardized vulnerability detection benchmarks against the CyberRange
and computes precision, recall, and false positive metrics.
See plan sections 65, 66 and Phase G.
"""

from dataclasses import dataclass
from typing import Dict, Any, List
import time

from security_agent.range.lab_targets import CyberRangeServer
from security_agent.tools.http_suite import probe_parameter_injection, check_cors_configuration, evaluate_security_headers
from security_agent.intelligence.judge import IndependentJudge


@dataclass
class BenchmarkScorecard:
    total_challenges: int
    detected_count: int
    detection_rate: float
    duration_seconds: float
    challenge_results: List[Dict[str, Any]]


class BenchmarkRunner:
    """
    Evaluates detection engines against offline deterministic challenge suites.
    """
    def run_suite(self) -> BenchmarkScorecard:
        server = CyberRangeServer()
        host, port = server.start()
        start_time = time.time()
        results = []

        try:
            base_url = server.url
            judge = IndependentJudge()

            # Challenge 1: SQL Injection Detection
            sqli_raw = probe_parameter_injection(f"{base_url}/api/products", parameter="id", probe_type="sql_error")
            sqli_data = __import__("json").loads(sqli_raw)
            sqli_verdict = judge.evaluate_finding(
                candidate_title="SQLi in products API",
                affected_asset=f"{base_url}/api/products",
                evidence_data=sqli_data,
                vulnerability_type="sql_injection"
            )
            results.append({
                "challenge": "SQL Injection Detection",
                "detected": sqli_verdict.is_confirmed,
                "severity": sqli_verdict.severity.value,
                "details": sqli_verdict.reason
            })

            # Challenge 2: CORS Misconfiguration Detection
            cors_raw = check_cors_configuration(f"{base_url}/api/user/profile", custom_origin="https://attacker.org")
            cors_data = __import__("json").loads(cors_raw)
            cors_verdict = judge.evaluate_finding(
                candidate_title="CORS Arbitrary Origin Reflection",
                affected_asset=f"{base_url}/api/user/profile",
                evidence_data=cors_data,
                vulnerability_type="cors_misconfiguration"
            )
            results.append({
                "challenge": "CORS Misconfiguration Detection",
                "detected": cors_verdict.is_confirmed,
                "severity": cors_verdict.severity.value,
                "details": cors_verdict.reason
            })

            # Challenge 3: Security Header Audit
            headers_raw = evaluate_security_headers(base_url)
            headers_data = __import__("json").loads(headers_raw)
            headers_detected = headers_data.get("score", 100) < 100
            results.append({
                "challenge": "Security Header Deficiencies",
                "detected": headers_detected,
                "score": headers_data.get("score"),
                "details": f"Discovered {len(headers_data.get('recommendations', []))} missing headers."
            })

        finally:
            server.stop()

        elapsed = time.time() - start_time
        detected_count = sum(1 for r in results if r["detected"])
        total = len(results)

        return BenchmarkScorecard(
            total_challenges=total,
            detected_count=detected_count,
            detection_rate=round(detected_count / total, 2) if total > 0 else 0.0,
            duration_seconds=round(elapsed, 2),
            challenge_results=results
        )
