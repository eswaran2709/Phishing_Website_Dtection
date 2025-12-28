#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 15 03:01:18 2025
@author: Muthu Eswaran
"""

import requests
import idna
from urllib.parse import urlparse
import homoglyphs as hg
#from src.activity_logger import log_domain_result

glph = hg.Homoglyphs()

# -------------------------------
# Configuration
# -------------------------------
API_KEY = "at_QriGxlimPmdpxXo6FkmeqwW26s70f"  # Your WHOISXML API key

def preprocess_url(url):
    """Extract domain and detect punycode / homoglyphs"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path  # handle URLs without scheme

        punycode_used = domain.startswith("xn--")
        original_punycode = None
        if punycode_used:
            try:
                original_punycode = idna.decode(domain)
            except Exception:
                original_punycode = None

        homoglyphs = [c for c in domain if ord(c) > 127]

        return {
            "domain": domain,
            "punycode_used": punycode_used,
            "original_punycode": original_punycode,
            "homoglyphs": homoglyphs
        }
    except Exception as e:
        return {"error": str(e)}

def get_whois_api(domain):
    """Fetch WHOIS info using WHOISXML API"""
    try:
        url = (
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={API_KEY}&domainName={domain}&outputFormat=JSON"
        )
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()

        registry = data.get("WhoisRecord", {}).get("registryData", {})
        registrant = data.get("WhoisRecord", {}).get("registrant", {})
        audit = data.get("WhoisRecord", {}).get("audit", {})
        registrar = registry.get("registrarName") or "N/A"
        creation = registry.get("createdDateNormalized") or audit.get("createdDate") or "N/A"
        expiration = registry.get("expiresDateNormalized") or "N/A"
        organization = registrant.get("organization") or "N/A"
        country = registrant.get("country") or "N/A"
        countrycode = registrant.get("countryCode") or "N/A"
        state = registrant.get("state") or "N/A"
        city = registrant.get("city") or "N/A"
        telephone = registrant.get("telephone") or "N/A"
        email = registrant.get("email") or "N/A"
        updatedDate = audit.get("updatedDate") or "N/A"
        
        

        return {"Registrar": registrar, 
                "Organization": organization,
                "creation_date": creation, 
                "Updated_Date": updatedDate,
                "expiration_date": expiration,
                "Country": country,
                "Country_Code": countrycode,
                "State": state,
                "City": city,
                "Telephone": telephone,
                "Email": email
                }
    except requests.exceptions.Timeout:
        return {"error": "WHOIS request timed out"}
    except Exception as e:
        return {"error": str(e)}

def get_certificates(domain):
    """Fetch certificates from crt.sh"""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if data:
            cert = data[0]  # take the first/latest certificate
            return {
                "issuer": cert.get("issuer_name", "N/A"),
                "not_before": cert.get("not_before", "N/A"),
                "not_after": cert.get("not_after", "N/A")
            }
        return {"message": "No certificate found"}
    except requests.exceptions.Timeout:
        return {"error": "crt.sh request timed out"}
    except Exception as e:
        return {"error": str(e)}
    