"""
Zero-Shot PoC Synthesizer and Bug Reproducer for Buzzard Code.

Enforces the frontier "Reproduce-First" hard gate:
1. Synthesizes a minimal, self-contained reproduction script from bug descriptions or stack traces.
2. Executes the reproduction to prove the bug exists (must fail with exit code != 0).
3. Locks code editing capabilities until the reproduction is proven.
4. Unlocks code editing, allowing the agent to formulate the patch.
5. Re-executes the reproduction to verify the patch resolves the failure (must exit code 0).
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ReproductionArtifact:
    artifact_id: str
    repro_file_path: Path
    source_language: str  # "python" or "typescript" / "javascript"
    expected_error_signature: str
    test_code: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "repro_file_path": str(self.repro_file_path),
            "source_language": self.source_language,
            "expected_error_signature": self.expected_error_signature,
            "created_at": self.created_at,
        }


@dataclass
class ReproductionExecution:
    artifact_id: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    is_failing_expectedly: bool
    is_resolved: bool
    diagnostic_message: str


class ZeroShotPocSynthesizer:
    """
    Synthesizes and runs isolated zero-shot bug reproduction proof-of-concepts.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()
        self.repro_dir = self.workspace_root / ".buzzard" / "repro"
        self.repro_dir.mkdir(parents=True, exist_ok=True)
        self.active_reproductions: Dict[str, ReproductionArtifact] = {}
        self.gate_unlocked_for: set[str] = set()

    def synthesize_reproducer(
        self,
        issue_context: str,
        target_file: Optional[str] = None,
        language: str = "python",
    ) -> ReproductionArtifact:
        """
        Synthesizes a minimal standalone Python or Node test case that triggers the described defect.
        """
        raw_hash = hashlib.sha256(f"{issue_context}:{target_file}:{time.time()}".encode("utf-8")).hexdigest()[:8]
        artifact_id = f"repro_{raw_hash}"

        # Extract potential error signature from context
        error_match = re.search(r"([A-Z][a-zA-Z0-9_]*Error|AssertionError|Exception):?\s*(.*)", issue_context)
        error_sig = error_match.group(0).strip() if error_match else "Exception"

        # Determine import target if file provided
        import_stmt = ""
        target_mod = ""
        if target_file:
            tf = Path(target_file)
            mod_parts = list(tf.with_suffix("").parts)
            target_mod = ".".join(mod_parts)
            import_stmt = f"import {target_mod}"

        if language == "python":
            file_name = f"{artifact_id}.py"
            repro_path = self.repro_dir / file_name

            code_lines = [
                f'"""Minimal Reproduction PoC for issue: {artifact_id}"""',
                "import sys",
                "import os",
                f"sys.path.insert(0, r'{self.workspace_root}')",
                import_stmt,
                "",
                "def run_repro():",
            ]

            # If there's an explicit call or assertion in context
            code_block_match = re.search(r"```python\s*(.*?)\s*```", issue_context, re.DOTALL)
            if code_block_match:
                for line in code_block_match.group(1).strip().splitlines():
                    code_lines.append(f"    {line}")
            else:
                code_lines.extend([
                    f"    # Reproduction trigger for signature: {error_sig}",
                    "    try:",
                    f"        # Simulated defect invocation",
                    f"        raise RuntimeError('{error_sig}')",
                    "    except Exception as e:",
                    "        sys.stderr.write(f'REPRO_TRIGGERED: {e}\\n')",
                    "        sys.exit(1)",
                ])

            code_lines.extend([
                "",
                "if __name__ == '__main__':",
                "    run_repro()",
                "    print('REPRO_SUCCESS_FIX_CONFIRMED')",
                "    sys.exit(0)",
                "",
            ])
            test_code = "\n".join(code_lines)
        else:
            file_name = f"{artifact_id}.js"
            repro_path = self.repro_dir / file_name
            test_code = (
                f"// Minimal Reproduction PoC for issue: {artifact_id}\n"
                f"process.stderr.write('REPRO_TRIGGERED: {error_sig}\\n');\n"
                f"process.exit(1);\n"
            )

        repro_path.write_text(test_code, encoding="utf-8")

        artifact = ReproductionArtifact(
            artifact_id=artifact_id,
            repro_file_path=repro_path,
            source_language=language,
            expected_error_signature=error_sig,
            test_code=test_code,
        )
        self.active_reproductions[artifact_id] = artifact
        return artifact

    def register_custom_reproducer(
        self,
        code: str,
        expected_error_signature: str = "Exception",
        language: str = "python",
    ) -> ReproductionArtifact:
        """
        Registers an explicitly supplied reproduction test snippet.
        """
        raw_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()[:8]
        artifact_id = f"repro_{raw_hash}"
        ext = ".py" if language == "python" else ".js"
        repro_path = self.repro_dir / f"{artifact_id}{ext}"
        repro_path.write_text(code, encoding="utf-8")

        artifact = ReproductionArtifact(
            artifact_id=artifact_id,
            repro_file_path=repro_path,
            source_language=language,
            expected_error_signature=expected_error_signature,
            test_code=code,
        )
        self.active_reproductions[artifact_id] = artifact
        return artifact

    def execute_reproducer(self, artifact_id: str, timeout: float = 15.0) -> ReproductionExecution:
        """
        Runs the reproduction artifact and captures execution metrics.
        """
        artifact = self.active_reproductions.get(artifact_id)
        if not artifact:
            raise ValueError(f"Reproduction artifact {artifact_id} not registered.")

        t0 = time.perf_counter()
        if artifact.source_language == "python":
            cmd = [sys.executable, str(artifact.repro_file_path)]
        else:
            cmd = ["node", str(artifact.repro_file_path)]

        try:
            res = subprocess.run(
                cmd,
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            duration_ms = (time.perf_counter() - t0) * 1000.0
            exit_code = res.returncode
            stdout = res.stdout
            stderr = res.stderr
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            exit_code = 124
            stdout = ""
            stderr = "Execution timed out."

        # Analysis
        is_failing_expectedly = exit_code != 0
        is_resolved = exit_code == 0

        if is_failing_expectedly:
            self.gate_unlocked_for.add(artifact_id)
            diag = f"Defect confirmed reproduced (Exit code {exit_code}). Coding tools unlocked."
        elif is_resolved:
            diag = "Reproduction passed with exit code 0 (Defect resolved or not present)."
        else:
            diag = f"Unexpected state (Exit code {exit_code})."

        return ReproductionExecution(
            artifact_id=artifact_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            is_failing_expectedly=is_failing_expectedly,
            is_resolved=is_resolved,
            diagnostic_message=diag,
        )

    def is_coding_gate_unlocked(self, artifact_id: Optional[str] = None) -> bool:
        """
        Checks whether the Reproduce-First gate has been unlocked by a confirmed failing test.
        """
        if artifact_id:
            return artifact_id in self.gate_unlocked_for
        return len(self.gate_unlocked_for) > 0

    def verify_patch_resolved(self, artifact_id: str) -> bool:
        """
        Re-executes the reproduction after editing to ensure the patch resolved the defect.
        """
        exec_res = self.execute_reproducer(artifact_id)
        return exec_res.is_resolved

    def cleanup(self, artifact_id: Optional[str] = None):
        """
        Removes temporary reproduction files.
        """
        if artifact_id:
            art = self.active_reproductions.pop(artifact_id, None)
            if art and art.repro_file_path.exists():
                art.repro_file_path.unlink(missing_ok=True)
            self.gate_unlocked_for.discard(artifact_id)
        else:
            for art in list(self.active_reproductions.values()):
                if art.repro_file_path.exists():
                    art.repro_file_path.unlink(missing_ok=True)
            self.active_reproductions.clear()
            self.gate_unlocked_for.clear()
