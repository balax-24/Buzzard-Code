"""
Secure credential store for Buzzard Code.

Manages API keys and provider authentication tokens.
Secrets are stored in user-scoped protected configuration directories and NEVER
committed or stored inside project configurations.
"""

import os
import sys
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional

def get_credentials_dir() -> Path:
    """Returns platform-appropriate global user directory for secrets."""
    if sys.platform == "win32":
        app_data = os.environ.get("APPDATA")
        if app_data:
            base = Path(app_data) / "buzzard"
        else:
            base = Path.home() / ".config" / "buzzard"
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            base = Path(xdg) / "buzzard"
        else:
            base = Path.home() / ".config" / "buzzard"
    base.mkdir(parents=True, exist_ok=True)
    return base

def get_credentials_file() -> Path:
    return get_credentials_dir() / "credentials.json"

def _secure_file_permissions(filepath: Path) -> None:
    """Ensure user-only read/write permissions on POSIX systems."""
    if sys.platform != "win32":
        try:
            os.chmod(filepath, 0o600)
        except OSError:
            pass

def mask_secret(secret: Optional[str]) -> str:
    """Safely mask secret for display (e.g. sk-1234...wxyz)."""
    if not secret:
        return "[NOT CONFIGURED]"
    s = secret.strip()
    if len(s) <= 8:
        return "********"
    return f"{s[:4]}...{s[-4:]}"

def get_credential(provider_name: str) -> Optional[str]:
    """
    Retrieve API key/secret for provider.
    Priority:
    1. Environment variables (e.g. OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY)
    2. Global credentials.json
    """
    provider_upper = provider_name.strip().upper().replace("-", "_")
    
    # Check well-known env vars
    env_keys = [
        f"{provider_upper}_API_KEY",
        f"{provider_upper}_KEY",
        f"{provider_upper}_TOKEN",
    ]
    if provider_upper == "OPENAI":
        env_keys.append("OPENAI_API_KEY")
    elif provider_upper == "ANTHROPIC":
        env_keys.append("ANTHROPIC_API_KEY")
    elif provider_upper == "GEMINI":
        env_keys.extend(["GEMINI_API_KEY", "GOOGLE_API_KEY"])
    elif provider_upper == "OLLAMA":
        env_keys.append("OLLAMA_API_KEY")
    elif provider_upper == "OPENAI_COMPATIBLE":
        env_keys.extend(["OPENAI_COMPATIBLE_API_KEY", "CUSTOM_API_KEY"])
    elif provider_upper in ("META", "MUSE"):
        env_keys.extend(["META_API_KEY", "MUSE_API_KEY", "MODEL_API_KEY"])

    for env_var in env_keys:
        val = os.environ.get(env_var)
        if val and val.strip():
            return val.strip()

    # Check credentials.json
    creds_file = get_credentials_file()
    if creds_file.exists():
        try:
            data = json.loads(creds_file.read_text(encoding="utf-8"))
            val = data.get(provider_name.lower()) or data.get(provider_upper)
            if val and isinstance(val, str) and val.strip():
                return val.strip()
        except Exception:
            pass

    return None

def set_credential(provider_name: str, secret: str) -> None:
    """Save API key/secret to secure global credentials file."""
    creds_file = get_credentials_file()
    data: Dict[str, Any] = {}
    if creds_file.exists():
        try:
            data = json.loads(creds_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    data[provider_name.lower()] = secret.strip()
    creds_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _secure_file_permissions(creds_file)

def delete_credential(provider_name: str) -> bool:
    """Remove API key for provider."""
    creds_file = get_credentials_file()
    if not creds_file.exists():
        return False
    try:
        data = json.loads(creds_file.read_text(encoding="utf-8"))
        key = provider_name.lower()
        if key in data:
            del data[key]
            creds_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            _secure_file_permissions(creds_file)
            return True
    except Exception:
        pass
    return False

def list_configured_credentials() -> Dict[str, str]:
    """Returns dictionary of provider -> masked secret."""
    results: Dict[str, str] = {}
    known_providers = ["openai", "gemini", "anthropic", "meta", "openai-compatible"]
    
    # Check credentials file
    creds_file = get_credentials_file()
    if creds_file.exists():
        try:
            data = json.loads(creds_file.read_text(encoding="utf-8"))
            for p, val in data.items():
                if val:
                    results[p] = mask_secret(val)
        except Exception:
            pass

    # Check env vars
    for p in known_providers:
        if p not in results:
            env_val = get_credential(p)
            if env_val:
                results[p] = f"{mask_secret(env_val)} (env)"
                
    return results
