"""
Launcher for Buzzard Code & Buzzard Go React TUI.

Launches the React 18 + Ink 4 terminal application (apps/buzzard-tui),
connecting it directly to the Python runtime stdio JSON-RPC engine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def find_node_executable() -> Optional[str]:
    """Finds the node binary across Linux, macOS, Windows, and WSL."""
    # 1. Standard PATH
    for name in ("node", "node.exe", "nodejs"):
        found = shutil.which(name)
        if found:
            return found

    # 2. Common Windows paths (accessible from WSL or native Windows)
    win_paths = [
        Path(r"C:\Program Files\nodejs\node.exe"),
        Path(r"C:\Program Files (x86)\nodejs\node.exe"),
        Path("/mnt/c/Program Files/nodejs/node.exe"),
        Path("/mnt/c/Program Files (x86)/nodejs/node.exe"),
    ]
    for p in win_paths:
        if p.exists():
            return str(p)

    return None


def resolve_buzzard_tui_dir() -> Optional[Path]:
    """Finds the apps/buzzard-tui directory from the current file or workspace."""
    # Start from this file's location: cli/tui_launcher.py
    current = Path(__file__).resolve().parent
    for _ in range(5):
        tui_dir = current / "apps" / "buzzard-tui"
        if tui_dir.is_dir() and (tui_dir / "package.json").exists():
            return tui_dir
        if current.parent == current:
            break
        current = current.parent

    # Try cwd
    cwd = Path.cwd()
    if (cwd / "apps" / "buzzard-tui" / "package.json").exists():
        return cwd / "apps" / "buzzard-tui"

    return None


def launch_react_tui(workspace: Optional[str] = None, brand: str = "BUZZARD CODE") -> int:
    """
    Launches the React + Ink TUI in the current terminal.
    
    Args:
        workspace: Target workspace directory (defaults to cwd).
        brand: Brand name ('BUZZARD CODE' or 'BUZZARD GO').
        
    Returns:
        Process exit code.
    """
    node_bin = find_node_executable()
    if not node_bin:
        sys.stderr.write(
            "[ERROR] Node.js is required to run the React TUI (apps/buzzard-tui).\n"
            "Please install Node.js 18+ or run with --no-react to use the Python Textual TUI.\n"
        )
        return 1

    tui_dir = resolve_buzzard_tui_dir()
    if not tui_dir:
        sys.stderr.write(
            "[ERROR] Could not locate apps/buzzard-tui package directory.\n"
        )
        return 1

    entrypoint = tui_dir / "dist" / "index.js"
    if not entrypoint.exists():
        sys.stdout.write("[INFO] Building React TUI package (first run)...\n")
        npm_bin = shutil.which("npm") or shutil.which("npm.cmd") or "npm"
        try:
            subprocess.run([npm_bin, "run", "build"], cwd=str(tui_dir), check=True)
        except Exception as e:
            sys.stderr.write(f"[ERROR] Failed to compile apps/buzzard-tui: {e}\n")
            return 1

    target_ws = str(Path(workspace).resolve()) if workspace else str(Path.cwd().resolve())

    args = [node_bin, str(entrypoint), "--workspace", target_ws]
    if brand == "BUZZARD GO" or "--go" in sys.argv:
        args.append("--go")
    else:
        args.extend(["--brand", brand])

    try:
        # Run interactively with inherited standard streams
        res = subprocess.run(args, cwd=str(tui_dir))
        return res.returncode
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        sys.stderr.write(f"[ERROR] Failed to launch React TUI: {e}\n")
        return 1
