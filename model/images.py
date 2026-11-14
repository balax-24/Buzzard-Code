"""
Multimodal image support for Buzzard Code (roadmap D6).

Handles loading, validating, encoding and formatting images for vision-capable models
(Anthropic Claude, OpenAI GPT-4o, Google Gemini, Ollama vision models).
"""

from __future__ import annotations

import base64
import mimetypes
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
MAX_IMAGE_BYTES = 20 * 1024 * 1024  # 20 MB limit

VISION_MODEL_SUBSTRINGS = (
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-4-vision",
    "claude-3",
    "claude-3-5",
    "claude-3-7",
    "gemini-1.5",
    "gemini-2.0",
    "gemini-exp",
    "llava",
    "qwen-vl",
    "vision",
    "omni",
)

_IMAGE_MENTION_RE = re.compile(r'@image(?:\(["\']([^"\']+)["\']\)|\s+([^\s]+))', re.IGNORECASE)


class ImageError(ValueError):
    """Raised when an image path is invalid, missing, outside workspace, or unreadable."""


def is_vision_supported(model_name: Optional[str]) -> bool:
    """Returns True if the model name indicates vision / multimodal capability."""
    if not model_name:
        return False
    lower = model_name.lower()
    return any(sub in lower for sub in VISION_MODEL_SUBSTRINGS)


def extract_image_mentions(prompt: str) -> Tuple[str, List[str]]:
    """
    Finds `@image <path>` or `@image("path")` mentions in a prompt string.
    Returns (cleaned_prompt, list_of_paths).
    """
    paths: List[str] = []
    
    def repl(m: re.Match) -> str:
        p = m.group(1) or m.group(2)
        if p:
            paths.append(p.strip())
        return ""

    cleaned = _IMAGE_MENTION_RE.sub(repl, prompt).strip()
    return cleaned, paths


def resolve_image_path(path_str: str, workspace: Optional[Path] = None) -> Path:
    """Validates that the image file exists, has a supported format, and stays in workspace if provided."""
    target = Path(path_str)
    if not target.is_absolute():
        base = workspace or Path.cwd()
        target = (base / target).resolve()
    else:
        target = target.resolve()

    if not target.is_file():
        raise ImageError(f"Image file not found: {path_str}")

    if target.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ImageError(f"Unsupported image format '{target.suffix}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")

    if workspace is not None:
        ws_resolved = Path(workspace).resolve()
        try:
            target.relative_to(ws_resolved)
        except ValueError:
            raise ImageError(f"Image path '{path_str}' is outside the authorized workspace '{ws_resolved}'.")

    size = target.stat().st_size
    if size > MAX_IMAGE_BYTES:
        raise ImageError(f"Image file too large ({size / (1024*1024):.1f} MB). Maximum size is 20 MB.")

    return target


def encode_image(image_path: Path) -> Tuple[str, str]:
    """Reads the image and returns (media_type, base64_str)."""
    mime, _ = mimetypes.guess_type(str(image_path))
    if not mime:
        suffix = image_path.suffix.lower()
        if suffix in (".jpg", ".jpeg"):
            mime = "image/jpeg"
        elif suffix == ".png":
            mime = "image/png"
        elif suffix == ".webp":
            mime = "image/webp"
        elif suffix == ".gif":
            mime = "image/gif"
        else:
            mime = "application/octet-stream"

    raw = image_path.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    return mime, b64


def format_anthropic_image_block(media_type: str, b64_data: str) -> Dict[str, Any]:
    """Anthropic Messages API image content block."""
    return {
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": media_type,
            "data": b64_data,
        },
    }


def format_openai_image_part(media_type: str, b64_data: str) -> Dict[str, Any]:
    """OpenAI Chat Completions image_url part."""
    return {
        "type": "image_url",
        "image_url": {
            "url": f"data:{media_type};base64,{b64_data}",
        },
    }


def format_gemini_image_part(media_type: str, b64_data: str) -> Dict[str, Any]:
    """Gemini REST API inline_data part."""
    return {
        "inline_data": {
            "mime_type": media_type,
            "data": b64_data,
        },
    }
