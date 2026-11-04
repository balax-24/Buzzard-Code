from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from toolchain.manifest import ToolDependency, ToolchainManifest
from sandbox.container import get_sandbox, is_docker_active, SandboxProvider, DockerSandbox


class CheckStatus(str, Enum):
    INSTALLED = "installed"
    MISSING = "missing"
    BROKEN = "broken"
    ERROR = "error"


@dataclass
class ToolCheckResult:
    dependency: ToolDependency
    status: CheckStatus
    version: Optional[str] = None
    error: Optional[str] = None
    output: str = ""

    @property
    def is_ok(self) -> bool:
        return self.status == CheckStatus.INSTALLED or (not self.dependency.required and self.status == CheckStatus.MISSING)


class ToolchainChecker:
    """
    Validates tool runtime dependencies strictly inside the isolated sandbox container.
    """
    def __init__(self, sandbox: Optional[SandboxProvider] = None):
        self.sandbox = sandbox or get_sandbox()

    def check_docker(self) -> Tuple[bool, str]:
        """
        Verifies Docker daemon reachability.
        """
        if not is_docker_active():
            return False, "Docker daemon is unreachable or permissions required."
        return True, "Docker sandbox operational."

    def check_dependency(self, dep: ToolDependency) -> ToolCheckResult:
        """
        Checks whether an individual tool dependency exists inside the sandbox.
        """
        docker_ok, msg = self.check_docker()
        if not docker_ok:
            return ToolCheckResult(
                dependency=dep,
                status=CheckStatus.ERROR,
                error=msg
            )

        cmd = dep.verification_cmd or f"which {dep.executable}"
        try:
            res = self.sandbox.execute(cmd, timeout=10.0)
            if res.get("exit_code") == 0:
                out = res.get("stdout", "").strip()
                first_line = out.split("\n")[0] if out else "verified"
                return ToolCheckResult(
                    dependency=dep,
                    status=CheckStatus.INSTALLED,
                    version=first_line[:40],
                    output=out
                )
            else:
                stderr = res.get("stderr", "").strip()
                return ToolCheckResult(
                    dependency=dep,
                    status=CheckStatus.MISSING,
                    error=stderr or f"Command '{cmd}' returned exit code {res.get('exit_code')}",
                    output=res.get("stdout", "")
                )
        except Exception as e:
            return ToolCheckResult(
                dependency=dep,
                status=CheckStatus.BROKEN,
                error=str(e)
            )

    def check_all(self, manifest: ToolchainManifest) -> Dict[str, ToolCheckResult]:
        """
        Checks all dependencies in the manifest.
        """
        results = {}
        for dep in manifest.get_all():
            results[dep.name] = self.check_dependency(dep)
        return results
