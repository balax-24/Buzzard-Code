import os
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple
from security_agent.toolchain.manifest import ToolDependency, ToolchainManifest
from security_agent.toolchain.dockerfile import get_dockerfile_content
from security_agent.sandbox.container import is_docker_active
from security_agent.cli.renderer import console


class ToolchainInstaller:
    """
    Builds and maintains the isolated security sandbox container image with declared dependencies.
    """
    def __init__(self, manifest: Optional[ToolchainManifest] = None):
        self.manifest = manifest or ToolchainManifest()

    def is_image_available(self, image_tag: str) -> bool:
        """
        Checks if the versioned Docker image exists in local Docker daemon.
        """
        if not is_docker_active():
            return False
        try:
            res = subprocess.run(
                ["docker", "image", "inspect", image_tag],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

    def build_sandbox_image(self, image_tag: Optional[str] = None, force_rebuild: bool = False) -> Tuple[bool, str]:
        """
        Builds the deterministic Docker sandbox image containing the complete toolchain.
        """
        if not is_docker_active():
            return False, "Cannot build sandbox image: Docker daemon is unreachable."

        tag = image_tag or self.manifest.get_image_tag()

        if not force_rebuild and self.is_image_available(tag):
            return True, f"Image {tag} is already built and up-to-date."

        dockerfile_content = get_dockerfile_content(self.manifest)
        
        with tempfile.TemporaryDirectory() as build_dir:
            dockerfile_path = os.path.join(build_dir, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(dockerfile_content)

            console.print(f"[bold cyan]● Building sandbox image: {tag}...[/bold cyan]")
            try:
                build_proc = subprocess.run(
                    ["docker", "build", "-t", tag, build_dir],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if build_proc.returncode == 0:
                    console.print(f"[bold green]✓ Sandbox image {tag} built successfully.[/bold green]")
                    return True, f"Image {tag} built successfully."
                else:
                    return False, f"Docker build failed:\n{build_proc.stderr}"
            except subprocess.TimeoutExpired:
                return False, "Docker build timed out after 300 seconds."
            except Exception as e:
                return False, f"Error building image: {e}"

    def install_missing(self, missing_deps: List[ToolDependency]) -> Tuple[bool, str]:
        """
        Installs missing dependencies into the sandbox image.
        """
        # Guardrail: only allow packages declared in trusted manifest
        trusted_packages = {dep.package for dep in self.manifest.get_all()}
        invalid = [d for d in missing_deps if d.package not in trusted_packages]
        if invalid:
            return False, f"Untrusted dependency requested: {[d.name for d in invalid]}"

        # Trigger full deterministic build of the sandbox image
        return self.build_sandbox_image(force_rebuild=True)
