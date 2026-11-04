"""
Binary / reverse-engineering capabilities: file identification, strings,
disassembly summary, ELF metadata, and exploit-mitigation (checksec) analysis.

Binary-first (objdump/readelf/checksec) with a pure-Python ELF parser
fallback so basic RE still works without any external tool.
"""
from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from security_agent.tools.fallback import FallbackRunner, strategy_from_cmd

ELF_MAGIC = b"\x7fELF"


def _binary_analyze_objdump(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or kw.get("binary") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    out_parts = []
    for name, cmd, min_len in [
        ("file", f"file '{path}'", 1),
        ("readelf", f"readelf -h '{path}' 2>/dev/null | head -25", 1),
        ("strings", "strings -n 6 " + repr(path) + " 2>/dev/null | grep -iE 'flag|secret|key|pass|http|/bin|usage|FLAG|CTF' | head -40", 1),
    ]:
        if not runner.tool_available(name):
            continue
        res = runner.run_cmd(cmd, timeout=60)
        out = (res.get("stdout") or "").strip()
        if out:
            out_parts.append(f"### {name}\n{out}")
    if not out_parts:
        return False, "no binary analysis tools available", ""
    return True, f"{len(out_parts)} analysis sections", "\n\n".join(out_parts)


def _elf_parse_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or kw.get("binary") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        return False, f"cannot read file: {e}", ""
    if not data.startswith(ELF_MAGIC):
        try:
            out = runner.run_cmd(f"file '{path}'", timeout=15)
            stdout = (out.get("stdout") or "").strip()
            if stdout:
                return True, "non-ELF binary identified", stdout
        except Exception:
            pass
        return False, "not an ELF binary", "cannot parse non-ELF without external tools"
    elf_class = data[4]
    is64 = elf_class == 2
    fmt = "<" + ("Q" if is64 else "I")
    endian = "<" if data[5] == 1 else ">"
    e_type = struct.unpack(endian + "H", data[16:18])[0]
    e_machine = struct.unpack(endian + "H", data[18:20])[0]
    e_entry = struct.unpack(endian + fmt, data[24:24 + (8 if is64 else 4)])[0]
    types = {0: "NONE", 1: "REL (relocatable)", 2: "EXEC", 3: "DYN (PIE/shared)", 4: "CORE"}
    machines = {62: "x86-64", 3: "i386", 40: "ARM", 183: "AArch64", 8: "MIPS", 243: "RISC-V"}
    sections = []
    e_shoff = struct.unpack(endian + fmt, data[0x28:0x28 + (8 if is64 else 4)])[0]
    e_shentsize = struct.unpack(endian + "H", data[0x3A:0x3C])[0]
    e_shnum = struct.unpack(endian + "H", data[0x3C:0x3E])[0]
    if e_shoff and e_shentsize and e_shnum:
        shstr_idx = struct.unpack(endian + "H", data[0x3E:0x40])[0]
        for i in range(1, e_shnum):
            off = e_shoff + i * e_shentsize
            name_off = struct.unpack(endian + "I", data[off:off + 4])[0]
            name = _read_cstr(data, e_shoff + shstr_idx * e_shentsize + name_off) if e_shoff else ""
            if name in (".text", ".bss", ".data", ".got", ".got.plt", ".plt", ".init_array", ".fini_array"):
                size = struct.unpack(endian + fmt, data[off + 0x20:off + 0x20 + (8 if is64 else 4)])[0]
                sections.append(f"  {name}: {size}B")
    lines = [
        f"ELF {elf_class * 32}-bit, {'LSB' if data[5] == 1 else 'MSB'}",
        f"Type : {types.get(e_type, e_type)}",
        f"Machine : {machines.get(e_machine, e_machine)}",
        f"Entry : 0x{e_entry:x}",
        f"Sections ({len(sections)}):",
    ] + sections
    lines.append("")
    lines.append("Strings (select):")
    import re
    strings = re.findall(rb"[\x20-\x7e]{6,}", data)
    interesting = [s.decode("ascii", "replace") for s in strings
                   if re.search(rb"flag|secret|key|pass|http|/bin|usage|FLAG|CTF", s, re.IGNORECASE)]
    lines += [f"  {s[:100]}" for s in interesting[:40]]
    if not interesting:
        lines.append("  (no interesting strings found)")
    return True, f"ELF {elf_class * 32}-bit {types.get(e_type, '')}", "\n".join(lines)


def _read_cstr(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    if end == -1:
        return ""
    return data[off:end].decode("ascii", "replace")


def binary_analyze_chain() -> List[Tuple[str, Any]]:
    return [("objdump-family", _binary_analyze_objdump), ("python-elf", _elf_parse_py)]


# ---------------------------------------------------------------------------
# binary_checksec / pwn_check — exploit mitigation analysis
# ---------------------------------------------------------------------------

def _checksec_cmd(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or kw.get("binary") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    if runner.tool_available("checksec"):
        cmd = f"checksec --file='{path}' 2>&1 | tail -20"
    else:
        cmd = f"readelf -l '{path}' 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO' && readelf -d '{path}' 2>/dev/null | grep -E 'BIND_NOW'"
    res = runner.run_cmd(cmd, timeout=30)
    out = (res.get("stdout") or "").strip()
    if not out:
        return False, "no mitigation output", ""
    return True, "mitigation summary", out


def _checksec_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = kw.get("file") or kw.get("binary") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(ELF_MAGIC):
        return False, "not an ELF binary", ""
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    fmt = "Q" if is64 else "I"
    e_phoff = struct.unpack(endian + fmt, data[0x20:0x20 + (8 if is64 else 4)])[0]
    e_phentsize = struct.unpack(endian + "H", data[0x36:0x38])[0]
    e_phnum = struct.unpack(endian + "H", data[0x38:0x3A])[0]
    relro = "No RELRO"
    canary = "No canary found"
    nx = "NX unknown"
    pie = "No PIE"
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 4 > len(data):
            break
        p_type = struct.unpack(endian + "I", data[off:off + 4])[0]
        if p_type == 0x6474E551:  # PT_GNU_STACK
            flags = struct.unpack(endian + "I", data[off + (8 if is64 else 16):off + (8 if is64 else 16) + 4])[0]
            nx = "NX enabled" if not (flags & 1) else "NX disabled (executable stack!)"
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            relro = "Partial RELRO"
    # BIND_NOW => full RELRO
    if b"BIND_NOW" in data:
        relro = "Full RELRO"
    # Canary detection via .text reference patterns is heuristic; use strings
    if b"__stack_chk_fail" in data:
        canary = "Canary found"
    # PIE via e_type DYN
    e_type = struct.unpack(endian + "H", data[16:18])[0]
    if e_type == 3:
        pie = "PIE enabled"
    lines = [
        f"RELRO   : {relro}",
        f"STACK CANARY : {canary}",
        f"NX      : {nx}",
        f"PIE     : {pie}",
        "",
        "Exploit implications:",
    ]
    advice = []
    if "No" in relro:
        advice.append("no/full RELRO missing -> GOT overwrite feasible")
    if "No canary" in canary:
        advice.append("no stack canary -> classic buffer overflow on stack")
    if "NX disabled" in nx:
        advice.append("executable stack -> shellcode on stack feasible")
    if "No PIE" in pie:
        advice.append("no PIE -> fixed addresses, ret2libc/ROP with known addresses")
    lines += [f"  - {a}" for a in advice] or ["  - mitigations look solid; look for logic bugs"]
    return True, f"RELRO:{relro.split()[0]} CANARY:{'yes' if 'found' in canary else 'no'} NX:{'on' if 'enabled' in nx else 'off'} PIE:{'on' if 'enabled' in pie else 'off'}", "\n".join(lines)


def binary_checksec_chain() -> List[Tuple[str, Any]]:
    return [("checksec/readelf", _checksec_cmd), ("python-elf-mitigations", _checksec_py)]


def _pwn_check_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Look for classic pwn primitives: format strings, unbounded strcpy,
    gets, dangerous functions, and weak mitigations."""
    path = kw.get("file") or ""
    if not path or not os.path.exists(path):
        return False, f"file not found: {path}", ""
    lines: List[str] = []
    # 1) mitigation summary via checksec python
    ok, summary, detail = _checksec_py(runner, kw)
    if ok:
        lines.append("### mitigations\n" + detail)
    # 2) dangerous function scan
    res = runner.run_cmd(
        f"objdump -d '{path}' 2>/dev/null | grep -oE 'call.*(gets|strcpy|strcat|sprintf|vsprintf|scanf|system|exec|mprotect|printf)' | sort | uniq -c | sort -rn | head -20",
        timeout=60)
    out = (res.get("stdout") or "").strip()
    if out:
        lines.append("### dangerous calls\n" + out)
    # 3) format-string hint: printf with no format arg is hard to detect statically;
    #    flag if printf appears and NX is off or canary missing
    res2 = runner.run_cmd(f"objdump -d '{path}' 2>/dev/null | grep -c 'call.*printf'", timeout=60)
    n_printf = (res2.get("stdout") or "0").strip()
    if n_printf.isdigit() and int(n_printf) > 0:
        lines.append(f"### note\n{int(n_printf)} printf call sites — review for format-string bugs (printf(user_input)).")
    if not lines:
        return False, "no pwn signals found", "no objdump output; is this a valid binary?"
    return True, "pwn primitive scan done", "\n\n".join(lines)


def pwn_check_chain() -> List[Tuple[str, Any]]:
    return [("objdump+checksec", _pwn_check_py)]
