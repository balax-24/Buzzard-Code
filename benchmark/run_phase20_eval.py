"""
Phase 20 Benchmark Runner.
Executes the Phase 20 Production Hardening and E2E Benchmark Suite.
"""

import sys
from pathlib import Path

repo_root = str(Path(__file__).resolve().parent.parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from tests.phase20_bench import Phase20HardeningSuite


def main():
    suite = Phase20HardeningSuite()
    report = suite.run_all()

    success = (
        report.e2e_lifecycle_passed
        and report.chat_mode_clean
        and report.assessment_lifecycle_passed
        and report.reconnect_chaos_passed
        and report.crash_resume_passed
        and report.secret_audit_clean
        and report.verification_integrity_passed
        and report.approval_integrity_passed
        and report.engagement_isolation_passed
        and report.long_run_memory_stable
    )

    if success:
        print("ALL PHASE 20 PRODUCTION HARDENING BENCHMARKS PASSED SUCCESSFULLY.")
        sys.exit(0)
    else:
        print("PHASE 20 BENCHMARK FAILED ON ONE OR MORE GATES.")
        sys.exit(1)


if __name__ == "__main__":
    main()
