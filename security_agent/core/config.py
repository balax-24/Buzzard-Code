"""
Unified configuration system for Buzzard Code.

Deterministic Precedence:
1. CLI option overrides
2. Project configuration (./buzzard.json or ./.buzzard/config.json)
3. Global configuration (~/.config/buzzard/config.json or %APPDATA%/buzzard/config.json)
4. Built-in defaults

Secrets are strictly redacted from any serialized output or console views.
"""

import os
import sys
import json
import re
import copy
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union

DEFAULT_CONFIG: Dict[str, Any] = {
    "$schema": "https://buzzard.dev/schema/buzzard.json",
    "version": "1.0.0",
    "model": {
        "provider": "ollama",
        "name": "qwen3:8b",
        "endpoint": "http://localhost:11434"
    },
    "runtime": {
        "sandbox": "docker",
        "confirmation": "ask",
        "max_iterations": 15,
        "timeout_seconds": 900
    },
    "security": {
        "scope": ["localhost", "127.0.0.1"],
        "allow_network": True,
        "autonomy_level": 2,
        "environment": "lab"
    }
}

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"api[-_]?key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"authorization", re.IGNORECASE),
]

SENSITIVE_VAL_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
]

def redact_secrets(data: Any) -> Any:
    """
    Recursively redacts secrets and sensitive information from data structures.
    """
    if isinstance(data, dict):
        redacted = {}
        for k, v in data.items():
            is_sensitive_key = any(p.search(str(k)) for p in SENSITIVE_KEY_PATTERNS)
            if is_sensitive_key and v:
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_secrets(v)
        return redacted
    elif isinstance(data, list):
        return [redact_secrets(item) for item in data]
    elif isinstance(data, str):
        val = data
        for p in SENSITIVE_VAL_PATTERNS:
            val = p.sub("[REDACTED]", val)
        return val
    return data

def get_global_config_dir() -> Path:
    """Returns platform-appropriate global config directory."""
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

def get_global_config_file() -> Path:
    return get_global_config_dir() / "config.json"

def get_legacy_config_file() -> Path:
    return Path.home() / ".security-agent" / "config.json"

def get_setup_state_file() -> Path:
    """Returns path to the persistent installation/setup state file."""
    return get_global_config_dir() / "state.json"

def get_setup_state() -> Dict[str, Any]:
    """Reads persistent setup and installation state."""
    state_file = get_setup_state_file()
    if state_file.is_file():
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {
        "installation_initialized": False,
        "setup_completed": False,
        "configured_provider": None,
        "configured_model": None,
        "sandbox_status": "unknown",
        "installed_at": None,
        "updated_at": None,
    }

def save_setup_state(state: Dict[str, Any]) -> None:
    """Persists setup state atomically to state.json."""
    state_file = get_setup_state_file()
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = state_file.with_suffix(".tmp")
    temp_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temp_file.replace(state_file)

def is_setup_completed() -> bool:
    """
    Determines if first-run setup is completed.
    Returns True if state.json has setup_completed=True, or if a valid
    global configuration already exists with a configured provider.
    """
    state = get_setup_state()
    if state.get("setup_completed") is True:
        return True

    # Backwards compatibility: If global config.json exists with a provider, mark setup completed
    cfg_file = get_global_config_file()
    if cfg_file.is_file():
        try:
            cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
            model_info = cfg.get("model")
            prov = None
            model_name = None
            if isinstance(model_info, dict):
                prov = model_info.get("provider")
                model_name = model_info.get("name")
            elif isinstance(model_info, str):
                prov = "ollama"
                model_name = model_info

            if prov:
                import datetime
                state["installation_initialized"] = True
                state["setup_completed"] = True
                state["configured_provider"] = prov
                state["configured_model"] = model_name
                state["sandbox_status"] = "ready"
                now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
                state["installed_at"] = now_str
                state["updated_at"] = now_str
                save_setup_state(state)
                return True
        except Exception:
            pass
    return False

def get_project_config_path(project_dir: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Finds project configuration if it exists in current or specified directory."""
    root = Path(project_dir) if project_dir else Path.cwd()
    p1 = root / "buzzard.json"
    if p1.is_file():
        return p1
    p2 = root / ".buzzard" / "config.json"
    if p2.is_file():
        return p2
    return None

def get_project_buzzard_dir(project_dir: Optional[Union[str, Path]] = None) -> Path:
    """Returns the .buzzard directory for the project."""
    root = Path(project_dir) if project_dir else Path.cwd()
    return root / ".buzzard"

def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merges override dictionary into base dictionary without mutating inputs."""
    merged = copy.deepcopy(base)
    for k, v in override.items():
        if k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
            merged[k] = deep_merge(merged[k], v)
        else:
            merged[k] = copy.deepcopy(v)
    return merged

def load_global_config() -> Dict[str, Any]:
    """Loads global configuration file with fallback to legacy config."""
    global_file = get_global_config_file()
    if global_file.is_file():
        try:
            return json.loads(global_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    legacy_file = get_legacy_config_file()
    if legacy_file.is_file():
        try:
            legacy_data = json.loads(legacy_file.read_text(encoding="utf-8"))
            # Normalize legacy flat config to structured 1.0 schema
            return {
                "model": {
                    "provider": "ollama",
                    "name": legacy_data.get("model", "qwen3:8b"),
                    "endpoint": legacy_data.get("ollama_host", "http://localhost:11434")
                },
                "security": {
                    "scope": legacy_data.get("scope", ["localhost", "127.0.0.1"]),
                    "allow_network": True,
                    "autonomy_level": 2,
                    "environment": "lab"
                }
            }
        except Exception:
            pass
    return {}

def load_project_config(project_dir: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Loads project configuration if present."""
    proj_path = get_project_config_path(project_dir)
    if proj_path and proj_path.is_file():
        try:
            return json.loads(proj_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}

def load_merged_config(
    cli_overrides: Optional[Dict[str, Any]] = None,
    project_dir: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """
    Loads unified configuration adhering to deterministic precedence:
    CLI overrides > Project config > Global config > Defaults.
    """
    config = copy.deepcopy(DEFAULT_CONFIG)
    global_cfg = load_global_config()
    if global_cfg:
        config = deep_merge(config, global_cfg)
    proj_cfg = load_project_config(project_dir)
    if proj_cfg:
        config = deep_merge(config, proj_cfg)
    if cli_overrides:
        config = deep_merge(config, cli_overrides)
    return config

def save_global_config(config: Dict[str, Any]) -> None:
    """Saves configuration to global config file (scrubbing secrets)."""
    clean_config = copy.deepcopy(config)
    # Ensure no secrets leaked
    if "api_key" in clean_config.get("model", {}):
        del clean_config["model"]["api_key"]
    global_file = get_global_config_file()
    global_file.write_text(json.dumps(clean_config, indent=2), encoding="utf-8")

def save_project_config(config: Dict[str, Any], project_dir: Optional[Union[str, Path]] = None) -> Path:
    """Saves project configuration to buzzard.json (never storing secrets)."""
    clean_config = copy.deepcopy(config)
    if "api_key" in clean_config.get("model", {}):
        del clean_config["model"]["api_key"]
    root = Path(project_dir) if project_dir else Path.cwd()
    target = root / "buzzard.json"
    target.write_text(json.dumps(clean_config, indent=2), encoding="utf-8")
    return target

def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validates configuration structure and values."""
    errors = []
    if not isinstance(config, dict):
        return False, ["Configuration must be a dictionary."]
    
    # Model validation
    model = config.get("model", {})
    if not isinstance(model, dict):
        errors.append("Invalid 'model' section: must be an object.")
    else:
        provider = model.get("provider")
        if not provider or not isinstance(provider, str):
            errors.append("Model provider must be specified (e.g. 'ollama', 'openai', 'gemini', 'anthropic').")
        name = model.get("name")
        if not name or not isinstance(name, str):
            errors.append("Model name must be specified.")
            
    # Runtime validation
    runtime = config.get("runtime", {})
    if runtime and not isinstance(runtime, dict):
        errors.append("Invalid 'runtime' section: must be an object.")
        
    # Security validation
    security = config.get("security", {})
    if security and not isinstance(security, dict):
        errors.append("Invalid 'security' section: must be an object.")
    elif security:
        scope = security.get("scope")
        if scope is not None and not isinstance(scope, list):
            errors.append("Security scope must be a list of target hostnames/IPs.")
            
    return (len(errors) == 0, errors)
