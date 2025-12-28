#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Capture + YARA analysis runner
Author: ChatGPT (adapted for Muthu)

Usage:
    python capture_and_yara.py example.com --iface eth0 --timeout 8

This script:
  - Resolves the domain to IP(s)
  - Starts a Scapy sniff filtered to those IPs
  - Performs a simple HTTP request to the domain to generate traffic
  - Stops capture after a short timeout, saves a pcap
  - Scans captured TCP payloads with scan_data_with_yara (from your src.yara_scanner)
  - Prints a JSON report to stdout
"""

import argparse
import json
import os
import socket
import threading
import time
from datetime import datetime

from scapy.all import sniff, wrpcap, TCP, raw, IP, conf, get_if_list as scapy_get_if_list

# Import your yara scanner wrapper (the module you showed earlier)
try:
    from src.yara_scanner import scan_data_with_yara, YARA_AVAILABLE
except Exception:
    # Fail gracefully if import fails - we will still run but mark YARA as unavailable
    scan_data_with_yara = None
    YARA_AVAILABLE = False

# --------- Config ----------
PCAP_DIR = "data/pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

# --------- Globals ----------
capturing = False
_packets = []
_target_ips = set()
_sniffer_thread = None

# --------- Helpers ----------
def resolve_domain(domain):
    """Return list of IPs for a domain (may be empty)"""
    try:
        # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
        ips = socket.gethostbyname_ex(domain)[2]
        return list(set(ips))
    except Exception as e:
        return []

def _packet_handler(packet):
    """Internal packet handler used by sniff: collect packets that involve target IPs."""
    global _packets, _target_ips
    # Ensure packet has IP/TCP layers
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    if _target_ips and (ip_src in _target_ips or ip_dst in _target_ips):
        _packets.append(packet)

def _start_sniff(iface=None, bpf_filter=None):
    """Run sniff until capturing flag is False. Runs in background thread."""
    # We use stop_filter inside sniff; but we also rely on daemon thread stopping when capturing set False
    sniff(
        iface=iface,
        prn=_packet_handler,
        store=False,
        filter=bpf_filter,
        stop_filter=lambda pkt: not capturing
    )

def generate_traffic(domain, timeout=5):
    """Make a simple HTTP(S) request to the domain to generate traffic.
       Returns (url_used, response_ok_boolean, exception_or_none)
    """
    import requests

    tried = []
    # try both http and https (attempt http first)
    for scheme in ("http://", "https://"):
        url = scheme + domain
        try:
            # do not verify certs to avoid failures for testing; but in real scenario consider verify=True
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return url, True, None
        except Exception as e:
            tried.append((url, str(e)))
    # if both fail return last exception
    return None, False, tried

def extract_domains_and_yara_from_packets(packets):
    """Extract Host headers seen in TCP payloads and run YARA on payload bytes.
       Returns list of domains (unique) and yara summary.
    """
    domains = set()
    yara_matches = []
    yara_detected = False

    for pkt in packets:
        if pkt.haslayer(TCP):
            try:
                payload_bytes = raw(pkt[TCP].payload)
                if not payload_bytes:
                    continue
                # extract Host header if present
                try:
                    payload_str = payload_bytes.decode(errors="ignore")
                    if "Host:" in payload_str:
                        lines = payload_str.split("\r\n")
                        for l in lines:
                            if l.lower().startswith("host:"):
                                host = l.split(":", 1)[1].strip()
                                if host:
                                    domains.add(host)
                except Exception:
                    pass

                # YARA scan (if available)
                if YARA_AVAILABLE and scan_data_with_yara:
                    # scan_data_with_yara returns a dict with status/matches in your module
                    try:
                        scan_res = scan_data_with_yara(payload_bytes)
                        # Your scan_data_with_yara returns {"status": "...", "matches": [...]}
                        if isinstance(scan_res, dict):
                            status = scan_res.get("status")
                            matches = scan_res.get("matches", [])
                            if status == "OK" and matches:
                                yara_detected = True
                                yara_matches.extend(matches)
                    except Exception:
                        # on scan failure, continue scanning remaining packets
                        continue

            except Exception:
                continue

    # dedupe matches
    yara_matches = list(dict.fromkeys(yara_matches))
    return list(domains), {"yara_available": bool(YARA_AVAILABLE), "malicious": yara_detected, "matches": yara_matches}

# --------- Main operation ----------
def capture_and_analyze(domain, iface=None, capture_duration=8, http_timeout=6):
    """
    Domain -> capture -> traffic generation -> save pcap -> yara scan -> JSON result
    """
    global capturing, _packets, _target_ips, _sniffer_thread

    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain is required")

    # Resolve domain
    resolved_ips = resolve_domain(domain)
    resolved_ips_str = resolved_ips or []

    # Build BPF filter for scapy sniff to reduce captured traffic
    bpf_filter = None
    if resolved_ips:
        # create filter like: "tcp and (host 1.2.3.4 or host 5.6.7.8)"
        host_parts = " or ".join([f"host {ip}" for ip in resolved_ips])
        bpf_filter = f"tcp and ({host_parts})"

    # Prepare capture
    _packets = []
    _target_ips = set(resolved_ips)
    capturing = True

    # Start sniffer thread
    _sniffer_thread = threading.Thread(target=_start_sniff, kwargs={"iface": iface, "bpf_filter": bpf_filter}, daemon=True)
    _sniffer_thread.start()

    # small warmup
    time.sleep(0.25)

    # Generate traffic (perform HTTP request) to domain to create packets
    url_used, request_ok, request_info = generate_traffic(domain, timeout=http_timeout)

    # Wait a bit more to capture all related traffic (server response, DNS, redirects)
    time.sleep(capture_duration)

    # Stop capture
    capturing = False
    # give sniff a moment to stop
    time.sleep(0.5)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    pcap_filename = os.path.join(PCAP_DIR, f"{domain.replace(':','_')}_{timestamp}.pcap")

    # Save if any packets captured
    total_packets = len(_packets)
    if total_packets > 0:
        try:
            wrpcap(pcap_filename, _packets)
        except Exception as e:
            pcap_filename = None
    else:
        pcap_filename = None

    # Analyze captured packets for Host headers + run YARA on payloads
    captured_domains, yara_summary = extract_domains_and_yara_from_packets(_packets)

    # Build final report
    report = {
        "domain_analyzed": domain,
        "resolved_ips": resolved_ips_str,
        "pcap_file": pcap_filename,
        "total_captured_packets": total_packets,
        "http_request": {
            "url_used": url_used,
            "ok": bool(request_ok),
            "info": request_info
        },
        "captured_domains_from_payloads": captured_domains,
        "yara": {
            "yara_available": yara_summary.get("yara_available", False),
            "malicious_detected": yara_summary.get("malicious", False),
            "matches": yara_summary.get("matches", [])
        }
    }

    # If YARA not available, provide a clear message
    if not yara_summary.get("yara_available", False):
        report["yara"]["note"] = "YARA not available locally — install libyara + yara-python to enable scanning."

    # If no malicious matches found
    if not report["yara"]["malicious_detected"]:
        report["yara"]["message"] = "No malicious activity detected in scanned payloads."

    return report

# ---------- CLI ----------
def main_cli():
    parser = argparse.ArgumentParser(description="Capture traffic for a domain and run YARA on payloads.")
    parser.add_argument("domain", help="Domain to test (example.com)")
    parser.add_argument("--iface", help="Network interface to capture on (default: auto)", default=None)
    parser.add_argument("--timeout", type=int, help="Extra capture wait seconds after generating traffic (default: 8)", default=8)
    parser.add_argument("--http-timeout", type=int, help="HTTP request timeout seconds (default: 6)", default=6)
    args = parser.parse_args()

    # If user did not pass iface, choose the default route interface
    iface = args.iface
    if not iface:
        # scapy conf.route.route("0.0.0.0")[0] returns gateway ip; use conf.iface as default
        iface = conf.iface

    report = capture_and_analyze(args.domain, iface=iface, capture_duration=args.timeout, http_timeout=args.http_timeout)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main_cli()
