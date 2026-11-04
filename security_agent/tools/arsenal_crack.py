"""Cracking strategies: hash identify, hash/zip/file crack, wordlist generation."""
from __future__ import annotations

import hashlib
import itertools
import os
import re
import shlex
import string
import zipfile
from typing import Any, Dict, List, Tuple

from security_agent.tools.fallback import FallbackRunner
from security_agent.tools.arsenal_http import PASS_WORDS, best_wordlist

HASH_ALGOS = {
    "md5": (32, hashlib.md5), "sha1": (40, hashlib.sha1),
    "sha224": (56, hashlib.sha224), "sha256": (64, hashlib.sha256),
    "sha384": (96, hashlib.sha384), "sha512": (128, hashlib.sha512),
}

TOP_PASSWORDS = [
    "admin", "password", "123456", "12345678", "123456789", "12345", "qwerty",
    "abc123", "letmein", "welcome", "monkey", "dragon", "master", "football",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess", "shadow",
    "superman", "michael", "ninja", "mustang", "batman", "admin123", "root",
    "toor", "passw0rd", "P@ssw0rd", "Password1", "changeme", "default", "test",
    "guest", "secret", "secret123", "123123", "000000", "111111", "admin@123",
]


def _hashid(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("hashid") and not runner.tool_available("hash-identifier"):
        return False, "hashid not installed", ""
    hv = kw.get("hash_value") or kw.get("hash") or ""
    tool = "hashid" if runner.tool_available("hashid") else "hash-identifier"
    res = runner.run_cmd(f"echo {shlex.quote(hv)} | {tool} 2>&1 | head -30", timeout=30)
    out = res.get("stdout", "").strip()
    if out:
        return True, "hash type identified", out
    return False, "hashid empty", ""


def _hashid_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    hv = (kw.get("hash_value") or kw.get("hash") or "").strip()
    if not hv:
        return False, "no hash", ""
    n = len(hv)
    hex_ok = bool(re.fullmatch(r"[0-9a-fA-F]+", hv))
    cands = []
    for name, (ln, _) in HASH_ALGOS.items():
        if hex_ok and n == ln:
            cands.append(name)
    if hex_ok and n == 16:
        cands.append("MySQL3/old")
    if hex_ok and n == 64 and "$" not in hv:
        cands.append("sha256")
    if hv.startswith("$2") and len(hv) == 60:
        cands.append("bcrypt ($2a/$2b/$2y)")
    if hv.startswith("$6$"):
        cands.append("sha512crypt")
    if hv.startswith("$5$"):
        cands.append("sha256crypt")
    if hv.startswith("$1$"):
        cands.append("md5crypt")
    if hv.startswith("$apr1$"):
        cands.append("Apache MD5")
    if hv.startswith("$P$") or hv.startswith("$H$"):
        cands.append("phpass (WordPress/Drupal)")
    if hv.startswith("pbkdf2"):
        cands.append("PBKDF2")
    if len(hv) == 64 and hex_ok and ":" in (kw.get("hash_value") or kw.get("hash") or ""):
        cands.append("NTLM? (LM:NTLM pair)")
    if not cands:
        cands = ["unknown — use hashcat --example-hashes to compare"]
    return True, f"{n} chars, hex={hex_ok}", "Candidates: " + ", ".join(cands)


def _hashcat(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("hashcat"):
        return False, "hashcat not installed", ""
    hv = kw.get("hash_value") or kw.get("hash") or ""
    mode = kw.get("mode", "") or "0"
    wl = kw.get("wordlist") or best_wordlist("pass")
    hf = "/tmp/arsenal_hash.txt"
    with open(hf, "w") as f:
        f.write(hv + "\n")
    res = runner.run_cmd(
        f"hashcat -m {shlex.quote(str(mode))} {hf} {shlex.quote(wl)} --potfile-path /tmp/arsenal_hash.pot "
        f"--force --quiet -O 2>&1 | tail -10; echo '---POT---'; cat /tmp/arsenal_hash.pot 2>/dev/null", timeout=300)
    out = res.get("stdout", "")
    pot = re.findall(rf"^{re.escape(hv)}:(\S+)", out, re.M)
    if pot:
        return True, f"Cracked: {pot[0]}", f"Hash: {hv}\nPassword: {pot[0]}"
    return False, "hashcat did not crack", out[-1500:]


def _john(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("john"):
        return False, "john not installed", ""
    hv = kw.get("hash_value") or kw.get("hash") or ""
    wl = kw.get("wordlist") or best_wordlist("pass")
    hf = "/tmp/arsenal_john_hash.txt"
    with open(hf, "w") as f:
        f.write(hv + "\n")
    fmt = kw.get("format", "")
    farg = f"--format={fmt}" if fmt else ""
    res = runner.run_cmd(
        f"john --wordlist={shlex.quote(wl)} {farg} {hf} 2>&1 | tail -8; john --show {hf} 2>&1 | tail -8", timeout=300)
    out = res.get("stdout", "")
    m = re.search(r"([^:\s]+):([^:\s]+)", out.split("password hash cracked")[0] if "password hash cracked" in out else out)
    show = [l for l in out.splitlines() if ":" in l and l.strip().split(":")[1].strip()]
    if show:
        return True, f"Cracked: {show[0].split(':')[1]}", out[-2000:]
    return False, "john did not crack", out[-1500:]


def _crack_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    hv = (kw.get("hash_value") or kw.get("hash") or "").strip().lower()
    algo = (kw.get("algorithm") or "").lower()
    if not hv:
        return False, "no hash", ""
    n = len(hv)
    if not algo:
        for name, (ln, _) in HASH_ALGOS.items():
            if n == ln and re.fullmatch(r"[0-9a-f]+", hv):
                algo = name
                break
    if algo not in HASH_ALGOS:
        return False, f"unsupported algo '{algo}' (python fallback handles {', '.join(HASH_ALGOS)})", ""
    _, fn = HASH_ALGOS[algo]
    wl = kw.get("wordlist") or ""
    words = []
    if wl and os.path.exists(wl):
        with open(wl, errors="ignore") as f:
            words = [l.strip() for l in f if l.strip()][:200_000]
    if not words:
        words = TOP_PASSWORDS
    for w in words:
        if fn(w.encode()).hexdigest() == hv:
            return True, f"Cracked: {w}", f"Algorithm: {algo}\nHash: {hv}\nPassword: {w}"
        for prefix in ("admin", "root", "user"):
            if fn((prefix + w).encode()).hexdigest() == hv:
                return True, f"Cracked: {prefix}{w}", f"Algorithm: {algo}\nHash: {hv}\nPassword: {prefix}{w}"
    return False, "not in wordlist", f"{algo} lookup over {len(words)} words failed"


def _fcrackzip(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("fcrackzip"):
        return False, "fcrackzip not installed", ""
    zf = kw.get("file", "")
    wl = kw.get("wordlist") or best_wordlist("pass")
    res = runner.run_cmd(f"fcrackzip -u -D -p {shlex.quote(wl)} {shlex.quote(zf)} 2>&1 | tail -10", timeout=300)
    out = res.get("stdout", "")
    if "PASSWORD FOUND" in out or "found" in out.lower() and ":" in out:
        return True, "zip password found", out
    return False, "fcrackzip did not find password", out[-1000:]


def _john_zip(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("john"):
        return False, "john not installed", ""
    zf = kw.get("file", "")
    wl = kw.get("wordlist") or best_wordlist("pass")
    res = runner.run_cmd(
        f"john --wordlist={shlex.quote(wl)} {shlex.quote(zf)} 2>&1 | tail -6; john --show {shlex.quote(zf)} 2>&1 | tail -6",
        timeout=300)
    out = res.get("stdout", "")
    show = [l for l in out.splitlines() if ":" in l and not l.startswith("0 ")]
    if show:
        return True, "zip password found", out[-1500:]
    return False, "john did not crack zip", out[-1200:]


def _zip_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    zf = kw.get("file", "")
    if not zf or not os.path.exists(zf):
        return False, "zip file missing", ""
    wl = kw.get("wordlist") or ""
    words = []
    if wl and os.path.exists(wl):
        with open(wl, errors="ignore") as f:
            words = [l.strip() for l in f if l.strip()][:150_000]
    if not words:
        words = TOP_PASSWORDS
    try:
        z = zipfile.ZipFile(zf)
    except Exception as e:
        return False, f"not a readable zip: {e}", ""
    for w in words:
        try:
            for info in z.infolist()[:3]:
                z.read(info, pwd=w.encode())
            return True, f"zip password: {w}", f"Password: {w}\nFiles: {', '.join(z.namelist()[:20])}"
        except RuntimeError:
            continue
        except Exception:
            continue
    return False, "password not found", f"Brute-forced {len(words)} passwords (ZipCrypto only; AES needs pyzipper)"


def _crunch(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("crunch"):
        return False, "crunch not installed", ""
    min_l = kw.get("min_len", "4")
    max_l = kw.get("max_len", "6")
    charset = kw.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")
    outfile = kw.get("outfile", "/tmp/arsenal_crunch.txt")
    res = runner.run_cmd(f"crunch {shlex.quote(str(min_l))} {shlex.quote(str(max_l))} "
                         f"{shlex.quote(charset)} -o {shlex.quote(outfile)} 2>&1 | tail -5", timeout=300)
    out = res.get("stdout", "")
    if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
        return True, f"wordlist generated ({os.path.getsize(outfile)} bytes)", f"Output: {outfile}\n{out}"
    return False, "crunch failed", out


def _wordlist_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    base = kw.get("base", "admin")
    max_len = min(int(kw.get("max_len", "4")), 5)
    charset = kw.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789")
    outfile = kw.get("outfile", "/tmp/arsenal_wordlist.txt")
    count = 0
    with open(outfile, "w") as f:
        for ln in range(1, max_len + 1):
            for tup in itertools.product(charset, repeat=ln):
                f.write(base + "".join(tup) + "\n")
                count += 1
                if count >= 200_000:
                    break
            if count >= 200_000:
                break
    return True, f"generated {count} candidates", f"Output: {outfile}"


def hash_identify_chain() -> List[Tuple[str, Any]]:
    return [("hashid", _hashid), ("python-heuristics", _hashid_py)]


def crack_hash_chain() -> List[Tuple[str, Any]]:
    return [("hashcat", _hashcat), ("john", _john), ("python-lookup", _crack_py)]


def crack_zip_chain() -> List[Tuple[str, Any]]:
    return [("fcrackzip", _fcrackzip), ("john", _john_zip), ("python-zipfile", _zip_py)]


def wordlist_gen_chain() -> List[Tuple[str, Any]]:
    return [("crunch", _crunch), ("python-itertools", _wordlist_py)]
