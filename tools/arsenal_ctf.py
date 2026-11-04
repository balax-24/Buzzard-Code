"""
CTF toolbox: crypto analysis (encoding/hash/cipher identification), digital
forensics, and steganography extraction. Binary-first, Python fallback.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from tools.fallback import FallbackRunner, strategy_from_cmd


# ---------------------------------------------------------------------------
# crypto_analyze
# ---------------------------------------------------------------------------

def _crypto_try_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    data = kw.get("data") or kw.get("ciphertext") or kw.get("text") or ""
    if not data:
        return False, "data required", ""
    out: List[str] = []
    out.append(f"Input ({len(data)} chars): {data[:120]}{'...' if len(data) > 120 else ''}")
    out.append("")

    # --- encodings ---
    encodings: List[Tuple[str, str]] = []
    try:
        dec = base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", data) and len(data) % 4 == 0 or re.fullmatch(r"[A-Za-z0-9+/=]+", data):
            encodings.append(("base64", dec))
    except Exception:
        pass
    try:
        dec = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        encodings.append(("base64url", dec))
    except Exception:
        pass
    try:
        encodings.append(("hex", bytes.fromhex(data).decode("utf-8", "replace")))
    except Exception:
        pass
    try:
        encodings.append(("rot13", codecs.decode(data, "rot_13")))
    except Exception:
        pass
    try:
        encodings.append(("url-decode", __import__("urllib.parse").parse.unquote(data)))
    except Exception:
        pass
    seen = set()
    for name, dec in encodings:
        if dec == data or dec in seen or not dec.strip():
            continue
        seen.add(dec)
        out.append(f"[{name}] {dec[:300]}")
    if seen:
        out.append("")

    # --- hash identification ---
    if re.fullmatch(r"[0-9a-fA-F]{16}", data):
        out.append("[hash] MD5 (16 hex) or MySQL3")
    elif re.fullmatch(r"[0-9a-fA-F]{32}", data):
        out.append("[hash] MD5 (32 hex) — likely MD5/NTLM/MD4")
    elif re.fullmatch(r"[0-9a-fA-F]{40}", data):
        out.append("[hash] SHA1 (40 hex) — or SHA-0")
    elif re.fullmatch(r"[0-9a-fA-F]{56}", data):
        out.append("[hash] SHA224 (56 hex)")
    elif re.fullmatch(r"[0-9a-fA-F]{64}", data):
        out.append("[hash] SHA256 (64 hex) — could also be SHA3-256/BLAKE2s")
    elif re.fullmatch(r"[0-9a-fA-F]{128}", data):
        out.append("[hash] SHA512 (128 hex)")
    elif re.fullmatch(r"\$2[aby]\$\d\d\$[./0-9A-Za-z]{53}", data):
        out.append("[hash] bcrypt")
    elif data.startswith("$6$"):
        out.append("[hash] SHA-512 crypt ($6$)")
    elif data.startswith("$5$"):
        out.append("[hash] SHA-256 crypt ($5$)")
    elif data.startswith("$1$"):
        out.append("[hash] MD5 crypt ($1$)")

    # --- single-byte XOR / Caesar ---
    caesar_found = False
    for shift in range(1, 26):
        dec = "".join(chr((ord(c) - ord('a' if c.islower() else 'A') - shift) % 26 + ord('a' if c.islower() else 'A')) if c.isalpha() else c for c in data)
        if re.search(r"\b(the|and|flag|is|of|to|you|ctf)\b", dec.lower()):
            out.append(f"[caesar-{shift}] {dec[:300]}")
            caesar_found = True
    if not caesar_found and data.isalpha():
        for shift in (13,):
            dec = codecs.decode(data.lower(), "rot_13")
            out.append(f"[rot{shift}] {dec[:300]}")
    try:
        raw = bytes.fromhex(data) if re.fullmatch(r"[0-9a-fA-F]+", data) else data.encode()
        for key in range(256):
            dec = bytes(b ^ key for b in raw)
            if re.search(rb"\b(the|and|flag|is|of|to|you|ctf|this)\b", dec.lower()):
                out.append(f"[xor-0x{key:02x}] {dec[:300].decode('utf-8', 'replace')}")
    except Exception:
        pass

    if len(out) <= 2:
        out.append("No common encoding/hash/cipher matched. Try: cyberchef, SageMath, or a custom python script.")
    return True, "crypto/encoding analysis done", "\n".join(out)


def _crypto_openssl(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    file_path = kw.get("file")
    if not file_path or not os.path.exists(file_path):
        return False, "file arg required for openssl strategy", ""
    res = runner.run_cmd(f"openssl enc -d -aes-256-cbc -in '{file_path}' -k '{kw.get('password', '')}' -md sha256 2>&1 | head -20", timeout=30)
    out = (res.get("stdout") or "").strip()
    if res.get("exit_code") == 0 and out:
        return True, "openssl decrypted", out
    return False, "openssl decrypt failed", out


def crypto_analyze_chain() -> List[Tuple[str, Any]]:
    return [("python-crypto-detect", _crypto_try_py), ("openssl", _crypto_openssl)]


# ---------------------------------------------------------------------------
# forensics_analyze
# ---------------------------------------------------------------------------

def _forensics_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or kw.get("path") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    parts: List[str] = []
    steps: List[Tuple[str, str, int]] = [
        ("file", f"file '{path}'", 1),
        ("exiftool", f"exiftool '{path}' 2>/dev/null | head -30", 1),
        ("binwalk", f"binwalk '{path}' 2>/dev/null | head -25", 1),
        ("strings", f"strings -n 6 '{path}' 2>/dev/null | grep -iE 'flag|secret|key|pass|ctf|BEGIN|http' | head -40", 1),
        ("foremost", f"foremost -o /tmp/arsenal_foremost -i '{path}' -q 2>&1 | tail -15 && find /tmp/arsenal_foremost -type f 2>/dev/null | head -20", 1),
    ]
    for name, cmd, min_len in steps:
        if not runner.tool_available(name):
            continue
        res = runner.run_cmd(cmd, timeout=90)
        out = (res.get("stdout") or "").strip()
        if len(out) >= min_len:
            parts.append(f"### {name}\n{out}")
    if parts:
        return True, f"{len(parts)} forensics passes", "\n\n".join(parts)
    return False, "no forensics tools available", "install exiftool/binwalk/foremost, or extract manually"


def forensics_analyze_chain() -> List[Tuple[str, Any]]:
    return [("binwalk/exiftool/strings", _forensics_py)]


# ---------------------------------------------------------------------------
# stego_extract
# ---------------------------------------------------------------------------

def _stego_extract_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    password = kw.get("password", "")
    parts: List[str] = []
    steps: List[Tuple[str, str]] = [
        ("steghide", f"steghide extract -sf '{path}' {'-p ' + password if password else '-p \"\"'} -xf /tmp/arsenal_stego_out 2>&1 | tail -5 && ls -la /tmp/arsenal_stego_out 2>/dev/null"),
        ("zsteg", f"zsteg '{path}' 2>&1 | head -40"),
        ("binwalk", f"binwalk -e '{path}' 2>&1 | tail -15 && find _* 2>/dev/null | head -20"),
    ]
    for name, cmd in steps:
        if not runner.tool_available(name.split()[0]):
            continue
        res = runner.run_cmd(cmd, timeout=90)
        out = (res.get("stdout") or "").strip()
        if out:
            parts.append(f"### {name}\n{out}")
    if parts:
        return True, f"{len(parts)} stego passes", "\n\n".join(parts)
    return False, "no stego tools available", "install steghide/zsteg/binwalk, or analyze the file manually (LSB analysis, appended data)"


def stego_extract_chain() -> List[Tuple[str, Any]]:
    return [("steghide/zsteg/binwalk", _stego_extract_py)]
