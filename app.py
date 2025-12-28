#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Streamlit URL Analysis Tool (updated)
Author: Muthu Eswaran (adapted)
"""

import streamlit as st
from src.lstm_classifier import classify_file
from src.domain_analysis import get_whois_api, get_certificates, preprocess_url
from src.packet_analyzer import capture_and_analyze, process_pcaps, get_if_list

st.set_page_config(page_title="URL Analysis Tool", layout="centered")

def main():
    st.title("🔎 URL Analysis Tool")

    url = st.text_input("Enter a URL to analyze (e.g., example.com or https://example.com):")

    # Analysis (preprocessing + whois + certificates)
    if url and st.button("Analyze URL"):
        with st.spinner("Processing URL..."):
            pre = preprocess_url(url)
            st.subheader("Preprocessing Results")
            st.write(pre)

            whois_info = get_whois_api(pre["domain"])
            st.subheader("WHOIS Information")
            st.write(whois_info)

            cert_info = get_certificates(pre["domain"])
            st.subheader("Certificate Info (crt.sh)")
            st.write(cert_info)

    # Packet capture UI
    interfaces = get_if_list()
    selected_iface = st.selectbox("Select Interface for Capture", interfaces)

    st.header("📡 Capture & YARA Analysis (live)")
    st.write("This will perform a real HTTP(S) request from this environment to the target domain to generate traffic.")
    st.warning("Run only in an isolated VM/network and with permission.")

    # Capture & Analyze settings
    col1, col2 = st.columns(2)
    capture_seconds = col1.number_input("Capture duration after request (s)", min_value=3, max_value=60, value=8)
    http_timeout = col2.number_input("HTTP request timeout (s)", min_value=2, max_value=30, value=6)

    if st.button("Capture & Analyze"):
        if not url:
            st.error("Please enter a URL/domain first.")
        else:
            with st.spinner("Capturing traffic and running YARA... (this may take a few seconds)"):
                try:
                    pre = preprocess_url(url)
                    domain = pre["domain"]
                except Exception:
                    domain = url.strip()

                # call capture_and_analyze synchronously (blocking)
                try:
                    report = capture_and_analyze(
                        domain=domain,
                        iface=selected_iface,
                        capture_duration=int(capture_seconds),
                        http_timeout=int(http_timeout)
                    )
                except Exception as e:
                    st.error(f"Error during capture_and_analyze: {e}")
                    report = None

            if report:
                st.success("Capture & analysis completed.")
                st.subheader("Final JSON Report")
                st.json(report)

                # Friendly human-readable summary
                st.subheader("Summary")
                st.write(f"- Domain analyzed: **{report.get('domain_analyzed')}**")
                st.write(f"- Resolved IPs: **{report.get('resolved_ips', [])}**")
                if report.get("pcap_file"):
                    st.write(f"- PCAP saved to: `{report.get('pcap_file')}`")

                yara_info = report.get("yara", {})
                if yara_info.get("yara_available") is False:
                    st.warning("YARA is not available on this host. Install libyara + yara-python to enable scanning.")
                if yara_info.get("malicious_detected"):
                    st.error(f"Malicious activity detected! Matches: {yara_info.get('matches')}")
                else:
                    st.success("No malicious activity detected in scanned payloads.")

    # Aggregated PCAP analysis (existing functionality)
    st.subheader("Aggregated PCAP Analysis")
    if st.button("Show All Domains from Saved PCAPs"):
        with st.spinner("Processing saved pcaps..."):
            report = process_pcaps()
        st.json(report)
        
    st.set_page_config(page_title="LSTM Malware Classifier", layout="wide")
    st.title("LSTM Malware Classification Dashboard")

    uploaded_file = st.file_uploader("Upload file", type=["csv","txt","zip","pkl", "exe"])
    filepath = st.text_input("Or paste local file path (server-side)")

    data = None

    if uploaded_file is not None:
        # uploaded_file is a Streamlit UploadedFile - has .read()
        uploaded_file.seek(0)     # safe reset before reading if reused
        data = uploaded_file.read()
    elif filepath:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            st.error(f"Failed to open path: {e}")

    if data is not None:
        st.success("File loaded — processing...")
        # Do your processing with `data`
    else:
        st.info("Please upload a file or provide a valid local path.")


if __name__ == "__main__":
    main()
