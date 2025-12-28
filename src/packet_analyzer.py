#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Packet analyzer for domain-specific live URL capture
Rewritten to provide a single capture_and_analyze() entrypoint that:
 - resolves domain -> IPs
 - starts a targeted Scapy sniff using a BPF filter (tcp and host ...)
 - generates HTTP/HTTPS traffic to the domain (to create packets)
 - saves captured packets to data/pcaps/*.pcap
 - runs scan_data_with_yara on TCP payloads and returns a JSON-like report

Other utility functions kept for compatibility: get_if_list(), process_pcaps()
"""

import os
import logging
import json
import threading
import time
import socket
from datetime import datetime

from scapy.all import sniff, wrpcap, TCP, raw, IP, conf, get_if_list as scapy_get_if_list

# local yara wrapper (your module). This returns dict results.
try:
    from src.yara_scanner import scan_data_with_yara, YARA_AVAILABLE
except Exception:
    scan_data_with_yara = None
    YARA_AVAILABLE = False

# ---------------- Config ----------------
PCAP_DIR = "data/pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ---------------- Globals (internal) ----------------
_capturing_flag = False
_packets_buffer = []
_target_ips = set()
_sniffer_thread = None

# ---------------- Interface List ----------------
def get_if_list():
    """Return available network interfaces"""
    return scapy_get_if_list()

# ---------------- Helpers ----------------
def resolve_domain(domain):
    """Resolve domain to list of IPs (may be empty)."""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return list(dict.fromkeys(ips))
    except Exception as e:
        logger.warning(f"DNS resolve failed for {domain}: {e}")
        return []

def _packet_handler(pkt):
    """Internal scapy packet handler: store TCP packets involving target IPs."""
    global _packets_buffer, _target_ips
    try:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if _target_ips and (ip_src in _target_ips or ip_dst in _target_ips):
            _packets_buffer.append(pkt)
    except Exception:
        # defensive: ignore malformed packets
        return

def _sniff_loop(iface=None, bpf_filter=None, timeout=None):
    """
    Run scapy.sniff until _capturing_flag becomes False, or until timeout expires.
    This uses stop_filter to periodically check flag.
    """
    def _stop(pkt):
        return not _capturing_flag

    try:
        sniff(iface=iface, prn=_packet_handler, store=False, filter=bpf_filter, stop_filter=_stop, timeout=timeout)
    except Exception as e:
        logger.error(f"Sniffing error: {e}")

def _generate_http_traffic(domain, http_timeout=6):
    """
    Generate simple HTTP(S) traffic to the domain to create network packets.
    Tries https then http; returns dict with details.
    """
    try:
        import requests
        tried = []
        for scheme in ("https://", "http://"):
            url = scheme + domain
            try:
                # verify=False to avoid cert issues during testing (note security tradeoff)
                r = requests.get(url, timeout=http_timeout, allow_redirects=True, verify=False)
                return {"url": url, "ok": True, "status_code": getattr(r, "status_code", None), "error": None}
            except Exception as e:
                tried.append({"url": url, "error": str(e)})
        return {"url": None, "ok": False, "status_code": None, "error": tried}
    except Exception as e:
        # requests not present or other import error
        return {"url": None, "ok": False, "status_code": None, "error": f"requests error: {e}"}

def _extract_domains_and_yara(packets):
    """
    Examine TCP payloads for Host: headers and run YARA on raw payloads.
    Returns (list_of_seen_hosts, yara_summary_dict).
    yara_summary_dict has: {"yara_available": bool, "malicious": bool, "matches": [...]}
    """
    seen_hosts = set()
    yara_matches = []
    malicious_flag = False

    for pkt in packets:
        try:
            if not pkt.haslayer(TCP):
                continue
            payload_bytes = raw(pkt[TCP].payload)
            if not payload_bytes:
                continue

            # extract Host header (HTTP)
            try:
                payload_text = payload_bytes.decode(errors="ignore")
                if "host:" in payload_text.lower():
                    # split lines and find Host: header(s)
                    for line in payload_text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            if host:
                                seen_hosts.add(host)
            except Exception:
                pass

            # run yara scan on payload bytes if available
            if YARA_AVAILABLE and callable(scan_data_with_yara):
                try:
                    scan_res = scan_data_with_yara(payload_bytes)
                    # expected a dict like {"status": "...", "matches": [...]}
                    if isinstance(scan_res, dict):
                        matches = scan_res.get("matches", []) or []
                        status = scan_res.get("status", "")
                        if status == "OK" and matches:
                            malicious_flag = True
                            yara_matches.extend(matches)
                except Exception as e:
                    logger.debug(f"YARA scanning error for one payload: {e}")
                    # continue scanning other packets
                    continue

        except Exception:
            continue

    # dedupe matches
    yara_matches = list(dict.fromkeys(yara_matches))
    return list(seen_hosts), {"yara_available": bool(YARA_AVAILABLE), "malicious": malicious_flag, "matches": yara_matches}

# ---------------- Public API (capture + analyze) ----------------
def capture_and_analyze(domain, iface=None, capture_duration=8, http_timeout=6, save_pcap=True):
    """
    High-level function to capture traffic for a domain, generate traffic, and run YARA analysis.
    Returns a JSON-serializable dict with the final report.

    Parameters:
      - domain: domain string (e.g., "example.com")
      - iface: network interface to capture on (None -> scapy default)
      - capture_duration: seconds to keep capturing after generating traffic
      - http_timeout: request timeout when generating traffic
      - save_pcap: whether to write a pcap file (True by default)

    Important: run in an isolated environment when testing untrusted domains.
    """
    global _capturing_flag, _packets_buffer, _target_ips, _sniffer_thread

    domain = (domain or "").strip()
    if not domain:
        raise ValueError("Domain is required")

    # Resolve domain -> IPs
    resolved_ips = resolve_domain(domain)
    resolved_ips = resolved_ips if resolved_ips else []

    # Build BPF filter (limit to tcp traffic to/from resolved IPs)
    bpf_filter = None
    if resolved_ips:
        hosts = " or ".join([f"host {ip}" for ip in resolved_ips])
        bpf_filter = f"tcp and ({hosts})"

    # reset buffers and flags
    _packets_buffer = []
    _target_ips = set(resolved_ips)
    _capturing_flag = True

    # start sniffing thread
    _sniffer_thread = threading.Thread(target=_sniff_loop, kwargs={"iface": iface, "bpf_filter": bpf_filter, "timeout": None}, daemon=True)
    _sniffer_thread.start()

    # tiny warm-up
    time.sleep(0.2)

    # generate traffic (simple HTTP/HTTPS requests)
    http_result = _generate_http_traffic(domain, http_timeout=http_timeout)

    # wait for capture_duration to capture responses, redirects, and TCP teardown
    time.sleep(capture_duration)

    # stop capture
    _capturing_flag = False
    # give sniff a moment to stop
    time.sleep(0.5)

    # Save pcap if packets exist
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_domain = domain.replace(":", "_")
    pcap_path = None
    total_packets = len(_packets_buffer)
    if save_pcap and total_packets > 0:
        try:
            pcap_filename = f"{safe_domain}_{timestamp}.pcap"
            pcap_path = os.path.join(PCAP_DIR, pcap_filename)
            wrpcap(pcap_path, _packets_buffer)
            logger.info(f"Saved {total_packets} packets to {pcap_path}")
        except Exception as e:
            logger.error(f"Failed to write pcap: {e}")
            pcap_path = None

    # Analyze packets: extract Host headers and YARA scan payloads
    captured_domains, yara_summary = _extract_domains_and_yara(_packets_buffer)

    # Build final report
    report = {
        "domain_analyzed": domain,
        "resolved_ips": resolved_ips,
        "pcap_file": pcap_path,
        "total_captured_packets": total_packets,
        "http_generation": http_result,
        "captured_domains_from_payloads": captured_domains,
        "yara": {
            "yara_available": yara_summary.get("yara_available", False),
            "malicious_detected": yara_summary.get("malicious", False),
            "matches": yara_summary.get("matches", []),
        }
    }

    if not report["yara"]["yara_available"]:
        report["yara"]["note"] = "YARA not available locally — install libyara + yara-python to enable scanning."

    if not report["yara"]["malicious_detected"]:
        report["yara"]["message"] = "No malicious activity detected in scanned payloads."

    return report

# ---------------- PCAP File Analysis ----------------
def process_pcaps():
    """Process saved PCAP files for aggregated domain report (kept from original)."""
    results = set()
    total_packets = 0

    pcap_files = [os.path.join(PCAP_DIR, f) for f in os.listdir(PCAP_DIR) if f.endswith((".pcap", ".pcapng"))]

    for pcap_file in pcap_files:
        try:
            pkts = sniff(offline=pcap_file)
            # reuse the local extractor to gather domains (no yara to avoid double compile cost)
            domains, _ = _extract_domains_and_yara(pkts)
            results.update(domains)
            total_packets += len(pkts)
        except Exception as e:
            logger.error(f"Error processing {pcap_file}: {e}")

    return {
        "message": "Aggregated PCAP analysis completed",
        "total_packets": total_packets,
        "all_domains": list(results)
    }

# If run directly, print interfaces (kept for compatibility)
if __name__ == "__main__":
    print(json.dumps({"available_interfaces": get_if_list()}, indent=2))
