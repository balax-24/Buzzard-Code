import re
import os
import subprocess
import shutil
import signal
import logging
import tempfile
import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from cli.renderer import console


def get_security_sandbox_image() -> str:
    """
    Single authoritative source of truth for the Docker sandbox image.
    Used identically across toolchain verification, preflight checks, and production tool execution.
    """
    from toolchain.manifest import ToolchainManifest
    return ToolchainManifest().get_image_tag()


class ToolErrorType(str, Enum):
    NONE = "none"
    DEPENDENCY_MISSING = "dependency_missing"  # exit code 127
    TIMEOUT = "timeout"                       # exit code 124 or process timeout
    EXECUTION_BLOCKED = "execution_blocked"   # exit code 126 or policy denied
    CONNECTION_REFUSED = "connection_refused" # connection refused / unreachable
    INVALID_ARGUMENT = "invalid_argument"     # missing or malformed parameter
    TARGET_NOT_SUPPORTED = "target_not_supported" # targeted tool on undiscovered surface
    SCHEMA_VIOLATION = "schema_violation"     # missing required schema properties
    TOOL_FAILURE = "tool_failure"             # general non-zero exit code or tool error


@dataclass
class ToolResult:
    """
    Structured representation of a tool or terminal execution result.
    Enforces exit-code & payload semantics so stderr, tool errors, or connection refused
    are never treated as success.
    """
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    error_type: ToolErrorType = ToolErrorType.NONE
    sandbox_image: Optional[str] = None
    container_id: Optional[str] = None
    duration: float = 0.0
    command: Optional[str] = None
    tool_name: Optional[str] = None
    evidence_id: Optional[str] = None
    structured_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_sandbox_response(cls, res: Dict[str, Any], command: str = "", tool_name: str = "") -> "ToolResult":
        raw_code = res.get("exit_code", 0)
        stdout = res.get("stdout", "")
        stderr = res.get("stderr", "")
        duration = res.get("duration", 0.0)
        image = res.get("sandbox_image")
        cid = res.get("container_id")
        
        # Determine success and classification
        err_lower = stderr.lower()
        out_lower = stdout.lower()
        combined = f"{err_lower}\n{out_lower}"
        
        if raw_code == 127 or "not found" in err_lower or "command not found" in out_lower:
            error_type = ToolErrorType.DEPENDENCY_MISSING
            success = False
            exit_code = 127
        elif raw_code == 124 or raw_code == -1 or "timed out" in err_lower or "timeout" in combined:
            error_type = ToolErrorType.TIMEOUT
            success = False
            exit_code = 124
        elif raw_code == 126 or "blocked" in err_lower or "permission denied" in err_lower or res.get("blocked", False) or "policy denied" in combined:
            error_type = ToolErrorType.EXECUTION_BLOCKED
            success = False
            exit_code = 126
        elif any(k in combined for k in ("err_connection_refused", "connection refused", "could not connect", "failed to connect", "unreachable", "host unreachable", "network unreachable")):
            error_type = ToolErrorType.CONNECTION_REFUSED
            success = False
            exit_code = 111
        elif "target_not_supported" in combined or "not supported by evidence" in combined:
            error_type = ToolErrorType.TARGET_NOT_SUPPORTED
            success = False
            exit_code = 2
        elif any(k in combined for k in ("parameter is required", "required parameter", "missing required", "invalid port", "schema error")):
            error_type = ToolErrorType.INVALID_ARGUMENT
            success = False
            exit_code = 2
        elif "tool error:" in combined or "error:" in err_lower or raw_code != 0:
            error_type = ToolErrorType.TOOL_FAILURE
            success = False
            exit_code = raw_code if raw_code != 0 else 1
        else:
            error_type = ToolErrorType.NONE
            success = True
            exit_code = 0

        return cls(
            success=success,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            error_type=error_type,
            sandbox_image=image,
            container_id=cid,
            duration=duration,
            command=command,
            tool_name=tool_name
        )

    @classmethod
    def from_raw_output(
        cls, 
        output_str: str, 
        exit_code: int = 0, 
        tool_name: str = "", 
        command: str = "",
        evidence_id: Optional[str] = None,
        structured_data: Optional[Dict[str, Any]] = None
    ) -> "ToolResult":
        """Parses any raw string tool output into a standardized ToolResult."""
        out_lower = output_str.lower()
        
        if "security stop:" in out_lower or "security blocked:" in out_lower:
            return cls(
                success=False,
                exit_code=126,
                stdout=output_str,
                error_type=ToolErrorType.EXECUTION_BLOCKED,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )

        if "err_connection_refused" in out_lower or "connection refused" in out_lower or "failed to connect" in out_lower or "unreachable" in out_lower:
            return cls(
                success=False,
                exit_code=111,
                stdout=output_str,
                error_type=ToolErrorType.CONNECTION_REFUSED,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "timed out" in out_lower or "timeout" in out_lower or exit_code == 124:
            return cls(
                success=False,
                exit_code=124,
                stdout=output_str,
                error_type=ToolErrorType.TIMEOUT,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "target_not_supported" in out_lower or "not supported by evidence" in out_lower:
            return cls(
                success=False,
                exit_code=2,
                stdout=output_str,
                error_type=ToolErrorType.TARGET_NOT_SUPPORTED,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "action rejected" in out_lower or "parameter is required" in out_lower or "required parameter" in out_lower or "missing parameter" in out_lower:
            return cls(
                success=False,
                exit_code=2,
                stdout=output_str,
                error_type=ToolErrorType.INVALID_ARGUMENT,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "command not found" in out_lower or "not found" in out_lower or exit_code == 127:
            return cls(
                success=False,
                exit_code=127,
                stdout=output_str,
                error_type=ToolErrorType.DEPENDENCY_MISSING,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "policy denied" in out_lower or "permission denied" in out_lower or exit_code == 126:
            return cls(
                success=False,
                exit_code=126,
                stdout=output_str,
                error_type=ToolErrorType.EXECUTION_BLOCKED,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )
        if "tool error:" in out_lower or "status: failed" in out_lower or exit_code != 0:
            return cls(
                success=False,
                exit_code=exit_code if exit_code != 0 else 1,
                stdout=output_str,
                error_type=ToolErrorType.TOOL_FAILURE,
                tool_name=tool_name,
                command=command,
                evidence_id=evidence_id,
                structured_data=structured_data or {}
            )

        return cls(
            success=True,
            exit_code=0,
            stdout=output_str,
            error_type=ToolErrorType.NONE,
            tool_name=tool_name,
            command=command,
            evidence_id=evidence_id,
            structured_data=structured_data or {}
        )

    def to_output_string(self) -> str:
        """Returns clean representation for LLM ingestion and logging."""
        out = []
        if self.stdout.strip():
            out.append(self.stdout.strip())
        if self.stderr.strip():
            out.append(f"Stderr: {self.stderr.strip()}")
        out.append(f"Exit code: {self.exit_code}")
        if self.success:
            out.append("Status: SUCCESS")
        else:
            out.append(f"Status: FAILED ({self.error_type.value})")
        return "\n\n".join(out) if out else f"(no output) Exit code: {self.exit_code}"

    def __str__(self) -> str:
        return self.to_output_string()


class SandboxProvider:
    """
    Abstract representation of a sandbox provider.
    """
    def execute(self, command: str, timeout: float = 30.0, tool_name: str = "") -> Dict[str, Any]:
        """
        Executes a shell command and returns dict containing stdout, stderr, exit_code, and metadata.
        """
        raise NotImplementedError("Subclasses must implement execute()")


class DockerSandbox(SandboxProvider):
    """
    Sandbox provider running commands inside an isolated Docker container.
    """
    def __init__(
        self,
        image: Optional[str] = None,
        memory_limit: str = "512m",
        cpu_quota: float = 0.5,
        network_mode: str = "host"
    ):
        self.image = image or get_security_sandbox_image()
        self.memory_limit = memory_limit
        self.cpu_quota = cpu_quota
        self.network_mode = network_mode
        self._prepull_image()

    def _prepull_image(self):
        """
        Ensures the Docker image is available locally if from a remote registry.
        """
        if ":" in self.image and not self.image.startswith("buzzard-security-sandbox"):
            try:
                subprocess.run(
                    ["docker", "pull", self.image],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False
                )
            except Exception:
                pass

    def execute(self, command: str, timeout: float = 30.0, tool_name: str = "") -> Dict[str, Any]:
        """
        Executes the command inside a temporary Docker container with resource constraints.
        Logs container metadata, duration, image, and exit code.
        """
        # The container must see the project the agent is working on
        from tools.filesystem import get_active_workspace
        host_workspace = get_active_workspace()
        container_id = f"sandbox-{uuid.uuid4().hex[:8]}"

        docker_cmd = [
            "docker", "run",
            "--rm",
            "--name", container_id,
            "-m", self.memory_limit,
            "--cpus", str(self.cpu_quota),
            "--network", self.network_mode,
            "-v", f"{host_workspace}:/workspace",
            "-w", "/workspace",
            self.image,
            "sh", "-c", command
        ]
        
        start_time = time.time()
        try:
            res = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            duration = time.time() - start_time
            return {
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "sandboxed": True,
                "sandbox_image": self.image,
                "container_id": container_id,
                "start_time": start_time,
                "duration": duration,
                "command": command,
                "tool_name": tool_name
            }
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            # Cleanup timed out container if needed
            try:
                subprocess.run(["docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            return {
                "exit_code": 124,
                "stdout": "",
                "stderr": f"Error: Command timed out after {timeout} seconds",
                "sandboxed": True,
                "sandbox_image": self.image,
                "container_id": container_id,
                "start_time": start_time,
                "duration": duration,
                "command": command,
                "tool_name": tool_name
            }
        except Exception as e:
            duration = time.time() - start_time
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Docker run failure: {e}",
                "sandboxed": True,
                "sandbox_image": self.image,
                "container_id": container_id,
                "start_time": start_time,
                "duration": duration,
                "command": command,
                "tool_name": tool_name
            }


class BlockedSandbox(SandboxProvider):
    """
    Fail-closed sandbox provider.
    Blocks execution when isolated container environment is unavailable.
    """
    def __init__(self, reason: str = "Docker sandbox is unavailable", image: Optional[str] = None):
        self.reason = reason
        self.image = image or get_security_sandbox_image()

    def execute(self, command: str, timeout: float = 30.0, tool_name: str = "") -> Dict[str, Any]:
        error_msg = f"SECURITY STOP: Sandbox unavailable — execution disabled. ({self.reason})"
        return {
            "exit_code": 126,
            "stdout": "",
            "stderr": error_msg,
            "sandboxed": False,
            "sandbox_image": self.image,
            "container_id": "blocked",
            "start_time": time.time(),
            "duration": 0.0,
            "blocked": True,
            "command": command,
            "tool_name": tool_name
        }


DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"\b(sudo|su|doas|runas)\b", re.IGNORECASE),
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+([/~]|[a-zA-Z]:\\)", re.IGNORECASE),
    re.compile(r"\b(mkfs|dd\s+if=|format\s+[a-zA-Z]:)\b", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
    re.compile(r"\b(shutdown|reboot|init\s+[06])\b", re.IGNORECASE),
]


_SECRET_ENV_NAME = re.compile(
    r"API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|(^|_)TOKENS?($|_)",
    re.IGNORECASE,
)


def _scrubbed_host_env() -> Dict[str, str]:
    """Copies the host environment without variables whose names indicate secrets."""
    return {name: value for name, value in os.environ.items() if not _SECRET_ENV_NAME.search(name)}


def _terminate_process_tree(process: subprocess.Popen) -> None:
    """Kills a shell and its descendants so none outlive a timeout."""
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=10,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError) as e:
        logging.getLogger(__name__).warning("Process tree kill failed for pid %s: %s", process.pid, e)
    process.kill()
    process.wait()


def _read_bounded_output(stream: Any, max_bytes: int, label: str) -> str:
    """Reads at most max_bytes from a captured output file, marking any truncation."""
    stream.seek(0)
    data = stream.read(max_bytes + 1)
    text = data[:max_bytes].decode("utf-8", errors="replace")
    if len(data) > max_bytes:
        text += f"\n... [{label} truncated to 100KB limit]"
    return text


class ControlledHostSandbox(SandboxProvider):
    """
    Controlled host execution provider for repository coding workflows.

    This is NOT an isolation boundary: commands run as the current user through
    a shell and can leave the working directory (e.g. `cd ..`) or reach the
    network. The command patterns are a best-effort denylist. Use DockerSandbox
    for untrusted code.

    Enforces:
    - Kill switch verification (blocks if the switch cannot be checked)
    - Workspace working directory (get_active_workspace())
    - Command timeout, applied to the whole process tree
    - Output size bounds (100KB max returned per stream)
    - Removal of secret-named environment variables
    - Rejection of commands matching privilege escalation and destructive patterns
    - Detailed exit code and error tracking
    """
    def __init__(self, workspace: Optional[str] = None):
        self.image = "controlled-host"
        self._custom_workspace = workspace

    def execute(self, command: str, timeout: float = 60.0, tool_name: str = "terminal.execute") -> Dict[str, Any]:
        # 1. Check Kill Switch
        try:
            from security.kill_switch import KillSwitch
            if KillSwitch.get_instance().is_triggered():
                return {
                    "exit_code": 126,
                    "stdout": "",
                    "stderr": "SECURITY STOP: Execution blocked — Kill switch is currently armed.",
                    "sandboxed": False,
                    "sandbox_image": self.image,
                    "container_id": "host-blocked",
                    "start_time": time.time(),
                    "duration": 0.0,
                    "blocked": True,
                    "command": command,
                    "tool_name": tool_name
                }
        except Exception as e:
            return {
                "exit_code": 126,
                "stdout": "",
                "stderr": f"SECURITY STOP: Execution blocked — Kill switch state could not be checked: {e}",
                "sandboxed": False,
                "sandbox_image": self.image,
                "container_id": "host-blocked",
                "start_time": time.time(),
                "duration": 0.0,
                "blocked": True,
                "command": command,
                "tool_name": tool_name
            }

        # 2. Block dangerous commands
        for pat in DANGEROUS_COMMAND_PATTERNS:
            if pat.search(command):
                return {
                    "exit_code": 126,
                    "stdout": "",
                    "stderr": f"SECURITY BLOCKED: Command matches restricted dangerous pattern ({pat.pattern}).",
                    "sandboxed": False,
                    "sandbox_image": self.image,
                    "container_id": "host-blocked",
                    "start_time": time.time(),
                    "duration": 0.0,
                    "blocked": True,
                    "command": command,
                    "tool_name": tool_name
                }

        # 3. Resolve workspace working directory
        from tools.filesystem import get_active_workspace
        target_ws = self._custom_workspace or get_active_workspace()
        os.makedirs(target_ws, exist_ok=True)
        start_time = time.time()
        max_bytes = 100 * 1024  # 100KB limit

        try:
            # Files rather than pipes: a surviving grandchild cannot block on them,
            # and output is not buffered in memory while the command runs.
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    stdin=subprocess.DEVNULL,
                    cwd=target_ws,
                    env=_scrubbed_host_env(),
                    start_new_session=os.name != "nt",
                )
                timed_out = False
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_process_tree(process)
                duration = time.time() - start_time
                stdout = _read_bounded_output(stdout_file, max_bytes, "Output")
                stderr = _read_bounded_output(stderr_file, max_bytes, "Stderr")

            if timed_out:
                timeout_message = f"Error: Command timed out after {timeout} seconds"
                return {
                    "exit_code": 124,
                    "stdout": stdout,
                    "stderr": f"{stderr}\n{timeout_message}" if stderr else timeout_message,
                    "sandboxed": False,
                    "sandbox_image": self.image,
                    "container_id": "host-process",
                    "start_time": start_time,
                    "duration": duration,
                    "command": command,
                    "tool_name": tool_name
                }

            return {
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "sandboxed": False,
                "sandbox_image": self.image,
                "container_id": "host-process",
                "start_time": start_time,
                "duration": duration,
                "command": command,
                "tool_name": tool_name
            }
        except Exception as e:
            duration = time.time() - start_time
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"Controlled host execution failure: {e}",
                "sandboxed": False,
                "sandbox_image": self.image,
                "container_id": "host-process",
                "start_time": start_time,
                "duration": duration,
                "command": command,
                "tool_name": tool_name
            }


# Backwards compatibility alias
LocalSandboxFallback = ControlledHostSandbox


class ApprovedHostSandbox(ControlledHostSandbox):
    """
    Host execution for coding tasks when Docker is unavailable.

    Only terminal.execute may run, because PolicyEngine requires operator approval for
    each of its commands before dispatch. Every other tool stays blocked. Approved
    commands run as the current user with no isolation.
    """
    ALLOWED_TOOLS = frozenset({"terminal.execute"})

    def execute(self, command: str, timeout: float = 60.0, tool_name: str = "") -> Dict[str, Any]:
        if tool_name not in self.ALLOWED_TOOLS:
            reason = f"'{tool_name or 'unknown tool'}' requires the Docker sandbox"
            return BlockedSandbox(reason=reason).execute(command, tool_name=tool_name)
        return super().execute(command, timeout=timeout, tool_name=tool_name)


def is_docker_active() -> bool:
    """Returns True if Docker CLI and daemon are reachable."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        return res.returncode == 0
    except Exception:
        return False


def get_sandbox(
    image: Optional[str] = None,
    force_local: bool = False,
    strict: bool = True
) -> SandboxProvider:
    """
    Factory function resolving sandbox provider.
    Always uses get_security_sandbox_image() as the single authoritative image.
    Uses DockerSandbox when Docker is active, ControlledHostSandbox when authorized/local,
    or BlockedSandbox if strict isolation is required but Docker is unavailable.
    """
    if force_local:
        return ControlledHostSandbox()

    resolved_image = image or get_security_sandbox_image()

    if is_docker_active():
        return DockerSandbox(image=resolved_image)

    if os.environ.get("BUZZARD_HOST_SANDBOX") == "1":
        return ControlledHostSandbox()

    from core.config import load_merged_config
    try:
        cfg = load_merged_config()
        sandbox_mode = (cfg.get("runtime", {}) or {}).get("sandbox", "docker").lower()
        if sandbox_mode in ("host", "local", "native", "controlled"):
            return ControlledHostSandbox()
    except Exception:
        pass

    if not strict:
        return ControlledHostSandbox()

    return BlockedSandbox(reason="Docker daemon is unreachable or sandbox image is missing", image=resolved_image)
