"""
Configuration Management for Qwythos TUI.
Loads and saves configuration from ~/.qsecurity/config.toml.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore


@dataclass
class TUIConfig:
    default_model: str = "qwythos:latest"
    default_mode: str = "CHAT"
    theme: str = "dark"  # "dark", "light", "high-contrast"
    context_size: int = 4096
    max_iterations: int = 40
    tool_verbosity: str = "summary"  # "minimal", "summary", "detailed"
    checkpoint_interval: int = 5
    streaming: bool = True
    timestamps: bool = True
    ollama_host: str = "http://localhost:11434"
    log_dir: str = str(Path.home() / ".qsecurity" / "logs")
    checkpoint_dir: str = str(Path.home() / ".security-agent" / "checkpoints")

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> TUIConfig:
        if config_path:
            p = Path(config_path)
        else:
            p = Path.home() / ".qsecurity" / "config.toml"

        if not p.exists():
            # Return defaults and write default config file
            cfg = cls()
            cfg.save(str(p))
            return cfg

        try:
            with open(p, "rb") as f:
                data = tomllib.load(f)
            tui_data = data.get("tui", data)
            return cls(
                default_model=tui_data.get("default_model", "qwythos:latest"),
                default_mode=tui_data.get("default_mode", "CHAT"),
                theme=tui_data.get("theme", "dark"),
                context_size=tui_data.get("context_size", 4096),
                max_iterations=tui_data.get("max_iterations", 40),
                tool_verbosity=tui_data.get("tool_verbosity", "summary"),
                checkpoint_interval=tui_data.get("checkpoint_interval", 5),
                streaming=tui_data.get("streaming", True),
                timestamps=tui_data.get("timestamps", True),
                ollama_host=tui_data.get("ollama_host", "http://localhost:11434"),
                log_dir=tui_data.get("log_dir", str(Path.home() / ".qsecurity" / "logs")),
                checkpoint_dir=tui_data.get("checkpoint_dir", str(Path.home() / ".security-agent" / "checkpoints")),
            )
        except Exception:
            return cls()

    def save(self, config_path: Optional[str] = None) -> None:
        if config_path:
            p = Path(config_path)
        else:
            p = Path.home() / ".qsecurity" / "config.toml"

        p.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Qwythos TUI Configuration",
            "[tui]",
            f'default_model = "{self.default_model}"',
            f'default_mode = "{self.default_mode}"',
            f'theme = "{self.theme}"',
            f"context_size = {self.context_size}",
            f"max_iterations = {self.max_iterations}",
            f'tool_verbosity = "{self.tool_verbosity}"',
            f"checkpoint_interval = {self.checkpoint_interval}",
            f"streaming = {'true' if self.streaming else 'false'}",
            f"timestamps = {'true' if self.timestamps else 'false'}",
            f'ollama_host = "{self.ollama_host}"',
            f'log_dir = "{self.log_dir}"',
            f'checkpoint_dir = "{self.checkpoint_dir}"',
        ]
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except Exception:
            pass
