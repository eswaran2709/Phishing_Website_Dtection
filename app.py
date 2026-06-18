import os
from datetime import datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse
import socket
import ipaddress

import joblib
import numpy as np
import pandas as pd
import requests
import streamlit as st
import tldextract

from feature_extractor import (
    MAX_URL_SEQUENCE_LENGTH,
    URL_CHAR_TO_INDEX,
    encode_url_to_char_sequence,
    extract_url_features,
    normalize_url,
)

try:
    import yara
except ImportError:
    yara = None

try:
    import tensorflow as tf
except ImportError:
    tf = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # Fallback if dotenv not available
    def load_dotenv(dotenv_path=".env"):
        if not os.path.exists(dotenv_path):
            return
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    load_dotenv()


def predict_lstm_probability(lstm_model, char_to_index, max_length, url):
    if lstm_model is None or url is None:
        return 0.0

    seq = np.array([encode_url_to_char_sequence(url, char_to_index, max_length)])
    try:
        proba = lstm_model.predict(seq, verbose=0)
        if proba.shape[-1] == 2:
            return float(proba[0][1])
        return float(proba[0][0])
    except Exception:
        return 0.0


# Avoid cache write issues and network fetches in restricted environments.
TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
PROTECTED_BRANDS = ["facebook", "google", "apple", "amazon", "paypal", "microsoft", "netflix"]


@st.cache_resource
def load_assets():
    try:
        # Prefer enhanced model if present, fallback to legacy model filenames.
        model_path = "model/random_forest_enhanced.pkl"
        features_path = "model/feature_names_enhanced.pkl"
        if not (os.path.exists(model_path) and os.path.exists(features_path)):
            model_path = "model/random_forest_light.pkl"
            features_path = "model/feature_names_light.pkl"

        model = joblib.load(model_path)
        feature_names = joblib.load(features_path)

        yara_rules = None
        if yara is not None:
            rules_path = "rules/phishing_url_rules.yar"
            if os.path.exists(rules_path):
                yara_rules = yara.compile(filepath=rules_path)
            else:
                st.warning("YARA rules file missing at rules/phishing_url_rules.yar")
        else:
            st.warning("yara-python is not installed. YARA checks are disabled.")

        lstm_model = None
        lstm_tokenizer = None
        lstm_max_length = None
        lstm_path = None
        if tf is not None:
            lstm_path_candidate = "model/lstm_url_model.h5"
            tokenizer_path = "model/url_char_to_index.pkl"
            config_path = "model/lstm_config.pkl"
            if os.path.exists(lstm_path_candidate) and os.path.exists(tokenizer_path) and os.path.exists(config_path):
                try:
                    lstm_model = tf.keras.models.load_model(lstm_path_candidate)
                    lstm_tokenizer = joblib.load(tokenizer_path)
                    lstm_max_length = joblib.load(config_path).get("max_length", MAX_URL_SEQUENCE_LENGTH)
                    lstm_path = lstm_path_candidate
                except Exception as err:
                    st.warning(f"Could not load LSTM model: {err}")
        else:
            st.warning("TensorFlow is not installed. LSTM hybrid detection is disabled.")

        return model, feature_names, yara_rules, model_path, lstm_model, lstm_tokenizer, lstm_max_length, lstm_path
    except Exception as e:
        st.error(f"Error loading assets: {e}")
        return None, None, None, None, None, None, None, None


model, feature_names, yara_rules, loaded_model_path, lstm_model, lstm_tokenizer, lstm_max_length, loaded_lstm_path = load_assets()


def detect_typosquatting(url):
    domain_info = TLD_EXTRACTOR(url)
    domain = domain_info.domain.lower()

    sub_map = str.maketrans("0135@|", "olesal")
    normalized = domain.translate(sub_map)

    for brand in PROTECTED_BRANDS:
        if normalized == brand and domain != brand:
            return True, f"Visual Deception: Mimicking '{brand}'"
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if 0.85 < similarity < 1.0:
            return True, f"High Similarity: Likely spoofing '{brand}'"

    return False, ""


def scan_url_with_yara(url, compiled_rules):
    if compiled_rules is None:
        return []

    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    scan_targets = {
        "full_url": normalized.lower(),
        "hostname": parsed.netloc.lower(),
        "path_query": f"{parsed.path}?{parsed.query}".lower(),
    }

    matches = []
    seen = set()
    for target_name, text in scan_targets.items():
        try:
            for match in compiled_rules.match(data=text.encode("utf-8", errors="ignore")):
                key = (match.rule, target_name)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(
                    {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "target": target_name,
                    }
                )
        except Exception as err:
            st.error(f"YARA scan failed: {err}")
            return []
    return matches


def check_virustotal(url, api_key, timeout_seconds=10):
    """Optional VirusTotal free-tier API check (requires your own key). Checks both URL and resolved IP."""
    if not api_key:
        return {"malicious": False, "source": "VirusTotal", "detail": "no_api_key"}

    headers = {"x-apikey": api_key}
    normalized = normalize_url(url)

    # Extract domain and get IP
    extracted = tldextract.extract(normalized)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    try:
        ipaddress.ip_address(domain)
        ip_address = domain  # It's already an IP
    except ValueError:
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_address = None

    url_malicious = False
    ip_malicious = False
    url_detail = ""
    ip_detail = ""
    analysis_id = ""
    stats = {}
    ip_stats = {}

    # Check URL
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": normalized},
            timeout=timeout_seconds,
        )
        submit.raise_for_status()

        analysis_id = submit.json().get("data", {}).get("id")
        if analysis_id:
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=timeout_seconds,
            )
            report.raise_for_status()
            response_data = report.json().get("data", {}).get("attributes", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            url_malicious = malicious >= 1
            url_detail = f"URL: malicious={malicious}, suspicious={suspicious}, harmless={stats.get('harmless', 0)}, undetected={stats.get('undetected', 0)}"
    except Exception as exc:
        url_detail = f"URL: unavailable: {exc}"

    # Check IP if available
    if ip_address:
        try:
            ip_report = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
                headers=headers,
                timeout=timeout_seconds,
            )
            ip_report.raise_for_status()
            ip_data = ip_report.json().get("data", {}).get("attributes", {})
            ip_stats = ip_data.get("last_analysis_stats", {})

            ip_malicious_count = int(ip_stats.get("malicious", 0))
            ip_malicious = ip_malicious_count >= 1
            ip_detail = f"IP ({ip_address}): malicious={ip_stats.get('malicious', 0)}, suspicious={ip_stats.get('suspicious', 0)}, harmless={ip_stats.get('harmless', 0)}, undetected={ip_stats.get('undetected', 0)}"
        except Exception as exc:
            ip_detail = f"IP ({ip_address}): unavailable: {exc}"
    else:
        ip_detail = "IP: could not resolve"

    overall_malicious = url_malicious or ip_malicious
    combined_detail = f"{url_detail}; {ip_detail}"

    return {
        "malicious": overall_malicious,
        "source": "VirusTotal",
        "detail": combined_detail,
        "analysis_id": analysis_id,
        "stats": stats,
        "ip_address": ip_address,
        "ip_stats": ip_stats,
    }


def get_phishing_probability(model_obj, feature_frame):
    proba = 0.0
    if hasattr(model_obj, "predict_proba") and hasattr(model_obj, "classes_"):
        classes = [str(c).lower() for c in model_obj.classes_]
        if "phishing" in classes:
            idx = classes.index("phishing")
            proba = float(model_obj.predict_proba(feature_frame)[0][idx])
    return proba


st.title("PhishGuard AI Pro")
st.write("Multi-layer detection: Typosquat + YARA + Enhanced ML + Optional Threat Intel")
if loaded_model_path:
    st.caption(f"Loaded model: {loaded_model_path}")
if loaded_lstm_path:
    st.caption(f"Loaded LSTM model: {loaded_lstm_path}")

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Default settings
ml_threshold = 0.5
enable_reputation_checks = bool(VIRUSTOTAL_API_KEY)

with st.sidebar:
    st.subheader("Detection Settings")
    if VIRUSTOTAL_API_KEY:
        st.success("VirusTotal API key loaded - reputation checks enabled")
    else:
        st.warning("VirusTotal API key not configured - reputation checks disabled")

url_input = st.text_input("Enter URL to scan", placeholder="https://example.com/login")

if st.button("Deep Scan", use_container_width=True):
    if not url_input:
        st.warning("Please enter a URL.")
    elif model is None or feature_names is None:
        st.error("Model assets are unavailable. Run training first.")
    else:
        with st.spinner("Analyzing URL..."):
            normalized_url = normalize_url(url_input)
            is_typo, typo_reason = detect_typosquatting(normalized_url)
            yara_matches = scan_url_with_yara(normalized_url, yara_rules)

            feat_df = extract_url_features(normalized_url, feature_names)
            rf_prediction = str(model.predict(feat_df)[0]).lower()
            rf_phishing_probability = get_phishing_probability(model, feat_df)
            lstm_phishing_probability = 0.0
            if lstm_model is not None and lstm_tokenizer is not None and lstm_max_length is not None:
                lstm_phishing_probability = predict_lstm_probability(
                    lstm_model, lstm_tokenizer, lstm_max_length, normalized_url
                )

            ml_phishing_probability = 0.55 * rf_phishing_probability + 0.45 * lstm_phishing_probability
            is_ml_phishing = ml_phishing_probability >= ml_threshold

            intel_results = []
            if enable_reputation_checks and VIRUSTOTAL_API_KEY:
                intel_results.append(check_virustotal(normalized_url, VIRUSTOTAL_API_KEY))

            intel_malicious = any(r.get("malicious") for r in intel_results)

            st.divider()
            st.subheader("Scan Breakdown")
            st.write(f"- Typosquat check: {'hit' if is_typo else 'clear'}")
            st.write(f"- YARA matches: {len(yara_matches)}")
            st.write(f"- Random Forest label: `{rf_prediction}`")
            st.write(f"- Random Forest phishing probability: `{rf_phishing_probability:.2%}`")
            st.write(f"- LSTM phishing probability: `{lstm_phishing_probability:.2%}`")
            st.write(f"- Hybrid ML phishing probability: `{ml_phishing_probability:.2%}`")

            if enable_reputation_checks:
                st.subheader("🛡️ VirusTotal Reputation Check")

                vt_data = None
                for item in intel_results:
                    if item["source"] == "VirusTotal":
                        vt_data = item
                        break

                if vt_data:
                    # Enhanced VirusTotal display
                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.markdown("**🛡️ VirusTotal Analysis**")

                    with col2:
                        status_emoji = "⚠️ MALICIOUS" if vt_data["malicious"] else "✅ CLEAN"
                        status_color = "🔴" if vt_data["malicious"] else "🟢"
                        st.markdown(f"**{status_emoji}**")

                    # Legend
                    st.info("🔴 Malicious | 🟡 Suspicious | 🟢 Clean | ⚪ Unknown - Number of antivirus engines that detected this classification")

                    # URL Scan Statistics
                    if vt_data.get("url_stats"):
                        st.markdown("**🔍 URL Scan Results:**")
                        stats = vt_data["url_stats"]
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("🔴 Malicious", stats.get("malicious", 0))
                        with col2:
                            st.metric("🟡 Suspicious", stats.get("suspicious", 0))
                        with col3:
                            st.metric("🟢 Clean", stats.get("harmless", 0))
                        with col4:
                            st.metric("⚪ Unknown", stats.get("undetected", 0))

                    # IP Analysis Statistics
                    if vt_data.get("ip_stats"):
                        st.markdown("**🌐 IP Address Analysis:**")
                        stats = vt_data["ip_stats"]
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("🔴 Malicious", stats.get("malicious", 0))
                        with col2:
                            st.metric("🟡 Suspicious", stats.get("suspicious", 0))
                        with col3:
                            st.metric("🟢 Clean", stats.get("harmless", 0))
                        with col4:
                            st.metric("⚪ Unknown", stats.get("undetected", 0))

                    # Links to full reports
                    if vt_data.get("analysis_id"):
                        st.markdown(f"[🔗 View Full URL Report on VirusTotal](https://www.virustotal.com/gui/analysis/{vt_data['analysis_id']})")
                    if vt_data.get("ip_address"):
                        st.markdown(f"[🔗 View Full IP Report on VirusTotal](https://www.virustotal.com/gui/ip-address/{vt_data['ip_address']}/detection)")
                else:
                    st.info("VirusTotal check completed - no detailed results available")

            risk_score = 0
            if is_typo:
                risk_score += 45
            risk_score += min(30, 10 * len(yara_matches))
            risk_score += int(ml_phishing_probability * 45)
            if intel_malicious:
                risk_score += 35

            if is_typo:
                verdict = "PHISHING (Visual Check)"
                st.error(f"DANGER: {typo_reason}")
            elif len(yara_matches) > 0:
                verdict = "PHISHING (YARA Rules)"
                st.error("DANGER: YARA custom rules flagged phishing indicators.")
            elif intel_malicious:
                verdict = "PHISHING (Reputation Intel)"
                st.error("DANGER: Threat-intel source marked this URL as malicious.")
            elif is_ml_phishing:
                verdict = "PHISHING (ML Model)"
                st.error("DANGER: Enhanced ML detected phishing characteristics.")
            elif risk_score >= 55:
                verdict = "SUSPICIOUS (Review Needed)"
                st.warning("Suspicious signals detected. Treat cautiously.")
            else:
                verdict = "SAFE"
                st.success("VERDICT: Likely Legitimate")

            if yara_matches:
                st.markdown("**YARA Hits**")
                for hit in yara_matches:
                    desc = hit["meta"].get("description", "No description")
                    st.write(f"- Rule `{hit['rule']}` on `{hit['target']}`: {desc}")

            st.markdown(f"**Composite Risk Score:** `{risk_score}/100`")

            log_file = "scan_history.csv"
            log_entry = pd.DataFrame(
                [[datetime.now(), normalized_url, verdict, f"{ml_phishing_probability:.4f}", risk_score]],
                columns=["Date", "URL", "Verdict", "ML_Prob", "Risk_Score"],
            )
            log_entry.to_csv(log_file, mode="a", header=not os.path.exists(log_file), index=False)
