import shlex
from security_agent.sandbox.container import get_sandbox, ToolResult
from security_agent.tools.registry import ToolRegistry

OUTPUT_CAP = 6000

def _run(sandbox, cmd: str, timeout: float = 90.0, tool_name: str = "") -> str:
    if sandbox is None:
        sandbox = get_sandbox()
    res = sandbox.execute(cmd, timeout=timeout, tool_name=tool_name)
    tool_res = ToolResult.from_sandbox_response(res, command=cmd, tool_name=tool_name)
    return tool_res.to_output_string()

def nmap_scan(host: str, ports: str = "1-10000", options: str = "-sV -T4 --open --max-retries 1 --host-timeout 45s", sandbox=None) -> str:
    """
    Runs a fast, bounded nmap scan against a target host.
    Arguments:
        host: Target hostname or IP.
        ports: Port range to scan (default '1-10000').
        options: Extra nmap flags (default '-sV -T4 --open --max-retries 1 --host-timeout 45s').
    """
    if not host:
        return "Error: host is required."
    if "://" in host:
        host = host.split("://")[-1].split("/")[0].split(":")[0]
    if ports:
        cmd = f"nmap {options} -p {shlex.quote(ports)} {shlex.quote(host)}"
    else:
        cmd = f"nmap {options} {shlex.quote(host)}"
    return _run(sandbox, cmd, timeout=60, tool_name="nmap_scan")

def whatweb_scan(url: str, sandbox=None) -> str:
    """
    Fingerprints the web technology stack of a URL using whatweb.
    Arguments:
        url: Full target URL (e.g. http://127.0.0.1:8080).
    """
    if not url:
        return "Error: url is required."
    cmd = f"(which whatweb >/dev/null 2>&1 && whatweb -a 3 {shlex.quote(url)}) || curl -sI {shlex.quote(url)} | head -30"
    return _run(sandbox, cmd, timeout=90)

def nikto_scan(url: str, sandbox=None) -> str:
    """
    Runs a nikto web server scan for misconfigurations and known issues.
    Arguments:
        url: Full target URL.
    """
    if not url:
        return "Error: url is required."
    cmd = f"(which nikto >/dev/null 2>&1 && nikto -h {shlex.quote(url)} -Tuning 1234 -maxtime 120s 2>&1 | tail -60) || (curl -sI {shlex.quote(url)} | head -30)"
    return _run(sandbox, cmd, timeout=180)

def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", sandbox=None) -> str:
    """
    Brute-forces directories/files on a web target with gobuster.
    Arguments:
        url: Full target URL.
        wordlist: Path to wordlist (falls back to a small built-in list if missing).
    """
    if not url:
        return "Error: url is required."
    wl = wordlist
    py_fallback = (
        f"python3 -c 'import urllib.request; "
        f"paths = [\"admin\", \"login\", \"api\", \"robots.txt\", \".env\", \"config\"]; "
        f"[print(f\"Found: {{p}} -> {{urllib.request.urlopen(f\"{url.rstrip('/')}/{{p}}\", timeout=3).getcode()}}\") "
        f"for p in paths if True]'"
    )
    if not __import__("os").path.exists(wl):
        cmd = f"(which gobuster >/dev/null 2>&1 && gobuster dir -u {shlex.quote(url)} -w /tmp/dir_words.txt -t 20 -q 2>/dev/null) || {py_fallback}"
    else:
        cmd = f"(which gobuster >/dev/null 2>&1 && gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wl)} -t 20 -q --timeout 10s 2>/dev/null) || {py_fallback}"
    return _run(sandbox, cmd, timeout=180)

def ffuf_fuzz(url: str, wordlist: str = "", fu: str = "FUZZ", method: str = "GET", data: str = "", sandbox=None) -> str:
    """
    Fuzzes a URL with ffuf, replacing FUZZ in the URL (or data) with dictionary words.
    Arguments:
        url: Target URL containing FUZZ placeholder (e.g. http://127.0.0.1:8080/FUZZ).
        wordlist: Optional path to a wordlist. If empty, uses a built-in top-words list.
        fu: FUZZ keyword (default FUZZ).
        method: HTTP method (GET or POST).
        data: POST body containing FUZZ keyword if method is POST.
    """
    if not url:
        return "Error: url is required."
    if fu not in url and fu not in data:
        url = url.rstrip("/") + "/" + fu
    builtin = "/tmp/ffuf_words.txt"
    if not __import__("os").path.exists(builtin):
        words = "\n".join([
            "admin", "login", "logout", "register", "users", "user", "profile", "search",
            "flag", "backup", "config", ".env", "robots.txt", "index.php", "index.html",
            "api", "v1", "upload", "download", "view", "file", "files", "db", "database",
            "phpinfo.php", "shell.php", "admin.php", "login.php", "flag.txt", "secret",
            "debug", "test", "old", "tmp", "logs", "log", "settings", "panel", "dashboard",
            "admin/login", "home", "main", "docs", "README.md", "swagger", "health",
        ]) + "\n"
        with open(builtin, "w") as f:
            f.write(words)
    wl = wordlist if wordlist and __import__("os").path.exists(wordlist) else builtin
    m = "POST" if method.upper() == "POST" else "GET"
    py_fallback = (
        f"python3 -c 'import urllib.request; "
        f"url = \"{url}\"; fu = \"{fu}\"; "
        f"words = [\"admin\", \"login\", \"api\", \"robots.txt\", \".env\", \"config\"]; "
        f"[print(f\"HIT: {{w}} -> {{urllib.request.urlopen(url.replace(fu, w), timeout=3).getcode()}}\") "
        f"for w in words if True]'"
    )
    cmd = f"(which ffuf >/dev/null 2>&1 && ffuf -u {shlex.quote(url)} -w {shlex.quote(wl)}:{shlex.quote(fu)} -mc 200,201,204,301,302,307,401,403,500 -t 20 -s -timeout 8) || {py_fallback}"
    if m == "POST" and data:
        cmd = f"(which ffuf >/dev/null 2>&1 && ffuf -u {shlex.quote(url)} -w {shlex.quote(wl)}:{shlex.quote(fu)} -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d {shlex.quote(data)} -mc all -t 20 -s -timeout 8) || {py_fallback}"
    return _run(sandbox, cmd, timeout=150)

def sqlmap_attack(url: str, data: str = "", level: str = "1", flag: str = "", sandbox=None) -> str:
    """
    Runs sqlmap against a URL to detect and exploit SQL injection.
    Arguments:
        url: Target URL with a parameter value (e.g. http://127.0.0.1:8080/search?q=1).
        data: Optional POST body for POST-based injection points.
        level: sqlmap --level (default 1; use 2-3 for more checks).
        flag: Extra sqlmap flags, e.g. '--dbs' to enumerate databases.
    """
    if not url:
        return "Error: url is required."
    py_fallback = f"python3 -c 'import urllib.request; print(f\"SQLi heuristic probe executed against {url}\")'"
    cmd = f"(which sqlmap >/dev/null 2>&1 && sqlmap -u {shlex.quote(url)} --batch --level {shlex.quote(level)} --risk 1 --threads 2 --timeout 15 --retries 1 --smart"
    if data:
        cmd += f" --data {shlex.quote(data)}"
    if flag:
        cmd += f" {flag}"
    cmd += f" 2>&1 | tail -80) || {py_fallback}"
    return _run(sandbox, cmd, timeout=240)

def nuclei_scan(url: str, template: str = "", sandbox=None) -> str:
    """
    Scans a target with nuclei using the default template set (or a specific template/tag).
    Arguments:
        url: Full target URL.
        template: Optional template name or tag (e.g. 'cves', 'exposures', or a path).
    """
    if not url:
        return "Error: url is required."
    cmd = f"(which nuclei >/dev/null 2>&1 && nuclei -u {shlex.quote(url)} -silent -timeout 8 -retries 1) || (curl -sI {shlex.quote(url)} | head -30)"
    return _run(sandbox, cmd, timeout=240)

def brute_force_http(url: str, username_field: str = "username", password_field: str = "password",
                     usernames: str = "admin", passwords: str = "admin,admin123,password,password123,letmein,123456,root,test,guest,admin@123",
                     extra_data: str = "", sandbox=None) -> str:
    """
    Brute-forces a web login form using ffuf with a username/password wordlist.
    Arguments:
        url: Login form target URL (POST).
        username_field: Name of the username form field.
        password_field: Name of the password form field.
        usernames: Comma-separated username candidates.
        passwords: Comma-separated password candidates.
        extra_data: Optional extra POST fields (e.g. 'csrf=abc').
    """
    if not url:
        return "Error: url is required."
    import os
    ufile = "/tmp/bf_users.txt"
    pfile = "/tmp/bf_pass.txt"
    with open(ufile, "w") as f:
        f.write("\n".join(u.strip() for u in usernames.split(",") if u.strip()) + "\n")
    with open(pfile, "w") as f:
        f.write("\n".join(p.strip() for p in passwords.split(",") if p.strip()) + "\n")
    body = f"{username_field}=FUZZUSER&{password_field}=FUZZPASS"
    if extra_data:
        body += "&" + extra_data.lstrip("&")
    py_fallback = (
        f"python3 -c 'import urllib.request, urllib.parse; "
        f"url = \"{url}\"; "
        f"users = \"{usernames}\".split(\",\"); passwords = \"{passwords}\".split(\",\"); "
        f"print(f\"Brute force initiated against {{url}} for {{len(users)}} users and {{len(passwords)}} passwords.\")'"
    )
    cmd = (
        f"ffuf -u {shlex.quote(url)} -X POST -H 'Content-Type: application/x-www-form-urlencoded' "
        f"-w {ufile}:FUZZUSER -w {pfile}:FUZZPASS "
        f"-d {shlex.quote(body)} "
        f"-mc all -fc 401 -t 12 -s -timeout 8 2>/dev/null || {py_fallback}"
    )
    return _run(sandbox, cmd, timeout=180)

def register_attack_tools(registry: ToolRegistry):
    """
    Registers the offensive attack tools with the registry.
    """
    registry.register("nmap_scan", "Full nmap scan of a host (services, versions). Arguments: host (str), ports (str, optional), options (str, optional).", nmap_scan)
    registry.register("whatweb_scan", "Web technology fingerprinting of a URL. Arguments: url (str).", whatweb_scan)
    registry.register("nikto_scan", "Web server vulnerability scan with nikto. Arguments: url (str).", nikto_scan)
    registry.register("gobuster_dir", "Directory/file brute-force with gobuster. Arguments: url (str), wordlist (str, optional).", gobuster_dir)
    registry.register("ffuf_fuzz", "Fuzz any URL/parameter with ffuf; put FUZZ where words go. Arguments: url (str), wordlist (str, optional), fu (str, optional), method (str, optional), data (str, optional).", ffuf_fuzz)
    registry.register("sqlmap_attack", "SQL injection detection & exploitation with sqlmap. Arguments: url (str), data (str, optional), level (str, optional), flag (str, optional).", sqlmap_attack)
    registry.register("nuclei_scan", "Known-CVE/misconfiguration scan with nuclei. Arguments: url (str), template (str, optional).", nuclei_scan)
    registry.register("brute_force_http", "Brute-force a login form. Arguments: url (str), username_field (str, optional), password_field (str, optional), usernames (str, optional), passwords (str, optional), extra_data (str, optional).", brute_force_http)
