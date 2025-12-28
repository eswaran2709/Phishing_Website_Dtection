#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML model stub for malware classification.
Uses yara_scanner if available; otherwise falls back to light heuristic rules
(scans for MZ/PE/ELF headers, suspicious strings) so pipeline doesn't crash.
"""

import logging
from typing import Dict, Any
from scapy.all import TCP, Raw
from .yara_scanner import scan_data_with_yara, YARA_AVAILABLE

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple heuristic signatures for fallback (bytes or strings)
FALLBACK_SIGNATURES = {
    "MZ_PE": b"MZ",                      # Windows PE header
    "PE_SIG": b"PE\x00\x00",             # PE signature
    "ELF": b"\x7fELF",                   # ELF header
    "ANDROID_MANIFEST": b"AndroidManifest.xml",
    "POWERSHELL": b"powershell",
    "CMD_EXE": b"cmd.exe",
    "WGET": b"wget",
    "CURL": b"curl",
    "BASE64_EXEC": b"ZXhlYw=="           # base64 "exec"
}

def _heuristic_scan(data: bytes):
    """Return list of matched heuristic signature keys."""
    hits = []
    if not data:
        return hits
    low = data.lower()
    for name, sig in FALLBACK_SIGNATURES.items():
        try:
            if sig.lower() in low:
                hits.append(name)
        except Exception:
            # if sig is bytes we can still attempt find
            if sig in data:
                hits.append(name)
    return hits

def classify_payload(pkt) -> Dict[str, Any]:
    """
    Classify a scapy packet payload.
    Returns dict: {'prediction': 'benign'|'malicious', 'details':..., 'yara_hits':[...], 'heuristic_hits':[...]}
    This is a stub — replace with real model later.
    """
    try:
        # Get raw payload bytes
        payload_bytes = b""
        if pkt.haslayer(Raw):
            payload_bytes = bytes(pkt[Raw].load)
        elif pkt.haslayer(TCP) and pkt[TCP].payload:
            payload_bytes = bytes(pkt[TCP].payload)

        result = {
            "prediction": "benign",
            "yara_hits": [],
            "heuristic_hits": []
        }

        # If YARA is available, prefer YARA results
        if YARA_AVAILABLE:
            yara_hits = scan_data_with_yara(payload_bytes)
            # scan_data_with_yara returns ['YARA_UNAVAILABLE'] if no rules / error; handle that
            if yara_hits and all(not s.startswith("YARA") for s in yara_hits):
                result["yara_hits"] = yara_hits
                result["prediction"] = "malicious"
                return result
            # if yara returned YARA_UNAVAILABLE or YARA_ERROR, fall through to heuristics

        # Heuristic fallback
        heur_hits = _heuristic_scan(payload_bytes)
        if heur_hits:
            result["heuristic_hits"] = heur_hits
            result["prediction"] = "suspicious"

        return result

    except Exception as e:
        logger.exception(f"[ML classify_payload error] {e}")
        return {"prediction": "error", "error": str(e)}
