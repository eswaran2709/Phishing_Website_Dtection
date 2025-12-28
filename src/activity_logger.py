#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Activity logger for phishing website & malware analysis
"""

import os
import csv
import json
from datetime import datetime

# Load config.json if available
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
DEFAULT_LOG_FILE = "Network_Malware_analyzer/objects/alerts.csv"

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            LOG_FILE = config.get("log_file", DEFAULT_LOG_FILE)
    except Exception as e:
        print(f"[CONFIG ERROR] Could not load config.json: {e}")
        LOG_FILE = DEFAULT_LOG_FILE
else:
    print("[CONFIG] config.json not found, using defaults.")
    LOG_FILE = DEFAULT_LOG_FILE

# Ensure directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Create file with headers if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Original_URL", "Normalized_Domain",
            "Punycode_Used", "Original_Punycode", "Homoglyphs",
            "Registrar", "Creation_Date", "Expiration_Date",
            "Cert_Issuer", "Cert_Not_Before", "Cert_Not_After"
        ])

def log_domain_result(result):
    """Write analysis results into alerts.csv"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    whois_info = result["whois"]
    cert_info = result["certs"][0] if result["certs"] else {}

    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            result["original_url"],
            result["normalized_domain"],
            result["punycode_used"],
            result["original_punycode"],
            ",".join(result["homoglyphs"][:5]) if result["homoglyphs"] else "",
            whois_info.get("registrar", ""),
            whois_info.get("creation_date", ""),
            whois_info.get("expiration_date", ""),
            cert_info.get("issuer", ""),
            cert_info.get("not_before", ""),
            cert_info.get("not_after", "")
        ])
    print(f"[DOMAIN LOGGED] {result['normalized_domain']}")
