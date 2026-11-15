"""
Tests for multimodal image support (roadmap D6).
"""

import base64
from pathlib import Path
import pytest

from model.images import (
    ImageError,
    encode_image,
    extract_image_mentions,
    format_anthropic_image_block,
    format_gemini_image_part,
    format_openai_image_part,
    is_vision_supported,
    resolve_image_path,
)
from model.tool_calls import (
    serialize_openai_messages,
    to_anthropic_messages,
    to_gemini_contents,
)


def test_vision_support_detection():
    assert is_vision_supported("gpt-4o") is True
    assert is_vision_supported("claude-3-5-sonnet-20241022") is True
    assert is_vision_supported("gemini-2.0-flash") is True
    assert is_vision_supported("ollama/llava:7b") is True
    assert is_vision_supported("qwen-cyber:latest") is False
    assert is_vision_supported("gpt-3.5-turbo") is False


def test_extract_image_mentions():
    text = "Review this UI layout @image assets/mockup.png and check styling."
    cleaned, paths = extract_image_mentions(text)
    assert cleaned == "Review this UI layout  and check styling."
    assert paths == ["assets/mockup.png"]

    text2 = 'Compare with @image("designs/v2.jpg") please.'
    cleaned2, paths2 = extract_image_mentions(text2)
    assert cleaned2 == "Compare with  please."
    assert paths2 == ["designs/v2.jpg"]


def test_resolve_image_path_validation(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    valid_png = ws / "test.png"
    valid_png.write_bytes(b"\x89PNG\r\n\x1a\nfake-data")

    resolved = resolve_image_path("test.png", workspace=ws)
    assert resolved == valid_png

    # Non-existent
    with pytest.raises(ImageError, match="not found"):
        resolve_image_path("missing.png", workspace=ws)

    # Unsupported format
    txt_file = ws / "readme.txt"
    txt_file.write_text("not an image")
    with pytest.raises(ImageError, match="Unsupported image format"):
        resolve_image_path("readme.txt", workspace=ws)

    # Outside workspace
    outside = tmp_path / "outside.png"
    outside.write_bytes(b"\x89PNG\r\n\x1a\n")
    with pytest.raises(ImageError, match="outside the authorized workspace"):
        resolve_image_path(str(outside), workspace=ws)


def test_encode_image(tmp_path):
    img = tmp_path / "sample.png"
    raw_bytes = b"\x89PNG\r\n\x1a\n" + b"12345"
    img.write_bytes(raw_bytes)

    mime, b64 = encode_image(img)
    assert mime == "image/png"
    assert base64.b64decode(b64.encode("ascii")) == raw_bytes


def test_provider_message_assembly(tmp_path):
    img = tmp_path / "icon.webp"
    img.write_bytes(b"RIFF....WEBP")
    mime, b64 = encode_image(img)

    user_msg = {
        "role": "user",
        "content": "What is in this picture?",
        "images": [(mime, b64)],
    }

    # 1. Anthropic
    sys_prompt, anthropic_msgs = to_anthropic_messages([user_msg])
    assert len(anthropic_msgs) == 1
    content_blocks = anthropic_msgs[0]["content"]
    assert content_blocks[0] == {"type": "text", "text": "What is in this picture?"}
    assert content_blocks[1]["type"] == "image"
    assert content_blocks[1]["source"]["media_type"] == "image/webp"

    # 2. Gemini
    _, gemini_contents = to_gemini_contents([user_msg])
    assert len(gemini_contents) == 1
    parts = gemini_contents[0]["parts"]
    assert parts[0] == {"text": "What is in this picture?"}
    assert "inline_data" in parts[1]
    assert parts[1]["inline_data"]["mime_type"] == "image/webp"

    # 3. OpenAI
    openai_msgs = serialize_openai_messages([user_msg])
    assert len(openai_msgs) == 1
    openai_parts = openai_msgs[0]["content"]
    assert openai_parts[0] == {"type": "text", "text": "What is in this picture?"}
    assert openai_parts[1]["type"] == "image_url"
    assert openai_parts[1]["image_url"]["url"].startswith("data:image/webp;base64,")
