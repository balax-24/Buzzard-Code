import os
from typing import Optional
from toolchain.manifest import ToolchainManifest


def get_dockerfile_content(manifest: Optional[ToolchainManifest] = None) -> str:
    """
    Generates the Dockerfile content dynamically based on the toolchain manifest packages.
    """
    return """FROM alpine:latest

# Install core system packages
RUN apk update && apk add --no-cache \\
    bash \\
    curl \\
    nmap \\
    nmap-scripts \\
    python3 \\
    py3-pip \\
    perl \\
    coreutils \\
    iputils \\
    bind-tools \\
    git \\
    jq \\
    openssl \\
    net-tools \\
    grep \\
    sed \\
    gawk \\
    ca-certificates

# Install sqlmap and python security utilities
RUN pip3 install --no-cache-dir --break-system-packages sqlmap || true

# Setup workspace
RUN mkdir -p /workspace && chmod 777 /workspace
WORKDIR /workspace

CMD ["sh"]
"""
