import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from asgiref.wsgi import WsgiToAsgi
import joblib
import numpy as np
import pandas as pd
import requests
import tldextract
import socket
import ipaddress
from urllib.parse import urlparse

try:
    import yara
except ImportError:
    yara = None

from feature_extractor import (
    MAX_URL_SEQUENCE_LENGTH,
    URL_CHAR_TO_INDEX,
    encode_url_to_char_sequence,
    extract_url_features,
    normalize_url,
)

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

flask_app = Flask(__name__)
CORS(flask_app)  # Enable CORS for browser extension requests

# Load models and data
model = None
feature_names = None
lstm_model = None
lstm_tokenizer = None
lstm_max_length = None
yara_rules = None

def load_assets():
    global model, feature_names, lstm_model, lstm_tokenizer, lstm_max_length, yara_rules
    try:
        model = joblib.load("model/random_forest.pkl")
        feature_names = joblib.load("model/feature_names.pkl")
        if yara:
            yara_rules = yara.compile("rules/phishing_url_rules.yar")
        try:
            import tensorflow as tf
            lstm_model = tf.keras.models.load_model("model/lstm_url_model.h5")
            lstm_tokenizer = joblib.load("model/url_char_to_index.pkl")
            lstm_max_length = joblib.load("model/lstm_config.pkl").get("max_length", MAX_URL_SEQUENCE_LENGTH)
        except:
            pass
    except Exception as e:
        print(f"Error loading assets: {e}")

load_assets()

def detect_typosquatting(url):
    # Simplified version - you can implement full logic
    return False, ""

def scan_url_with_yara(url, compiled_rules):
    if compiled_rules is None or yara is None:
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
            print(f"YARA scan failed: {err}")
            return []
    return matches

def check_virustotal(url, api_key, timeout_seconds=10):
    """Check URL and IP via VirusTotal."""
    if not api_key:
        return {"malicious": False, "detail": "no_api_key"}

    headers = {"x-apikey": api_key}
    normalized = normalize_url(url)

    extracted = tldextract.extract(normalized)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    try:
        ipaddress.ip_address(domain)
        ip_address = domain
    except ValueError:
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            ip_address = None

    url_malicious = False
    ip_malicious = False
    url_detail = ""
    ip_detail = ""

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
            stats = response_data.get("stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            url_malicious = malicious >= 1
            url_detail = f"URL: malicious={malicious}, suspicious={suspicious}"
    except Exception as exc:
        url_detail = f"URL: unavailable: {exc}"

    # Check IP
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
            ip_detail = f"IP: malicious={ip_stats.get('malicious', 0)}, suspicious={ip_stats.get('suspicious', 0)}"
        except Exception as exc:
            ip_detail = f"IP: unavailable: {exc}"
    else:
        ip_detail = "IP: could not resolve"

    overall_malicious = url_malicious or ip_malicious
    return {
        "malicious": overall_malicious,
        "url_detail": url_detail,
        "ip_detail": ip_detail,
        "url_stats": {
            "malicious": malicious if 'malicious' in locals() else 0,
            "suspicious": suspicious if 'suspicious' in locals() else 0,
            "harmless": stats.get("harmless", 0) if 'stats' in locals() else 0,
            "undetected": stats.get("undetected", 0) if 'stats' in locals() else 0
        } if 'stats' in locals() else None,
        "ip_stats": {
            "malicious": ip_stats.get("malicious", 0) if 'ip_stats' in locals() else 0,
            "suspicious": ip_stats.get("suspicious", 0) if 'ip_stats' in locals() else 0,
            "harmless": ip_stats.get("harmless", 0) if 'ip_stats' in locals() else 0,
            "undetected": ip_stats.get("undetected", 0) if 'ip_stats' in locals() else 0
        } if 'ip_stats' in locals() else None
    }

def get_phishing_probability(model_obj, feature_frame):
    proba = 0.0
    if hasattr(model_obj, "predict_proba") and hasattr(model_obj, "classes_"):
        classes = [str(c).lower() for c in model_obj.classes_]
        if "phishing" in classes:
            idx = classes.index("phishing")
            proba = float(model_obj.predict_proba(feature_frame)[0][idx])
    return proba

def predict_lstm_probability(model, tokenizer, max_length, url):
    try:
        sequence = encode_url_to_char_sequence(url, tokenizer, max_length)
        prediction = model.predict(sequence)[0][0]
        return float(prediction)
    except:
        return 0.0

@flask_app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    if not isinstance(url, str):
        url = str(url or '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    normalized_url = normalize_url(url)
    is_typo, typo_reason = detect_typosquatting(normalized_url)
    yara_matches = scan_url_with_yara(normalized_url, yara_rules) if yara_rules else []

    rf_prediction = "unknown"
    rf_phishing_probability = 0.0
    lstm_phishing_probability = 0.0
    ml_phishing_probability = 0.0

    if model is not None and feature_names is not None:
        feat_df = extract_url_features(normalized_url, feature_names)
        rf_prediction = str(model.predict(feat_df)[0]).lower()
        rf_phishing_probability = get_phishing_probability(model, feat_df)

    if lstm_model is not None and lstm_tokenizer is not None and lstm_max_length is not None:
        lstm_phishing_probability = predict_lstm_probability(
            lstm_model, lstm_tokenizer, lstm_max_length, normalized_url
        )

    ml_phishing_probability = 0.55 * rf_phishing_probability + 0.45 * lstm_phishing_probability

    intel_results = []
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if VIRUSTOTAL_API_KEY:
        intel_results.append(check_virustotal(normalized_url, VIRUSTOTAL_API_KEY))

    intel_malicious = any(r.get("malicious") for r in intel_results)

    risk_score = 0
    if is_typo:
        risk_score += 45
    risk_score += min(30, 10 * len(yara_matches))
    risk_score += int(ml_phishing_probability * 45)
    if intel_malicious:
        risk_score += 35

    verdict = "SAFE"
    if is_typo:
        verdict = "PHISHING (Visual Check)"
    elif len(yara_matches) > 0:
        verdict = "PHISHING (YARA Rules)"
    elif intel_malicious:
        verdict = "PHISHING (Reputation Intel)"
    elif ml_phishing_probability >= 0.5:
        verdict = "PHISHING (ML Model)"
    elif risk_score >= 55:
        verdict = "SUSPICIOUS"

    result = {
        "url": normalized_url,
        "verdict": verdict,
        "risk_score": risk_score,
        "details": {
            "typosquat": "hit" if is_typo else "clear",
            "yara_matches": len(yara_matches),
            "rf_label": rf_prediction,
            "rf_probability": rf_phishing_probability,
            "lstm_probability": lstm_phishing_probability,
            "hybrid_probability": ml_phishing_probability,
            "virustotal": intel_results[0] if intel_results else None,
        }
    }

    return jsonify(result)

if __name__ == '__main__':
    # For development with Flask
    flask_app.run(debug=True, host='0.0.0.0', port=5001)

# ASGI application for uvicorn
application = WsgiToAsgi(flask_app)

# Alias for compatibility with `uvicorn api:app`
app = application
