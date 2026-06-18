import math
import re
from collections import Counter
from ipaddress import ip_address
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract

# Disable cache writes and online fetches so extraction works in offline/restricted environments.
EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

URL_CHAR_VOCAB = tuple("abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
URL_PAD_INDEX = 0
URL_OOV_INDEX = 1
URL_CHAR_TO_INDEX = {char: idx + 2 for idx, char in enumerate(URL_CHAR_VOCAB)}
MAX_URL_SEQUENCE_LENGTH = 300

PROTECTED_BRANDS = ["facebook", "google", "apple", "amazon", "paypal", "microsoft", "netflix", "instagram", "bank", "chase"]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "gq", "work", "country", "kim", "tk", "ml", "ga", "cf", "rest", "fit", "cn", "ru", "top"
}
PHISH_HINTS = {
    "login", "verify", "update", "secure", "account", "signin", "password", "confirm", "banking", "wallet", "invoice", "billing"
}
PATH_EXTENSIONS = {".php", ".exe", ".zip", ".rar", ".scr", ".js", ".html", ".htm", ".aspx", ".jsp"}

ENHANCED_FEATURES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_or",
    "nb_eq",
    "nb_underscore",
    "nb_tilde",
    "nb_percent",
    "nb_slash",
    "nb_star",
    "nb_colon",
    "nb_comma",
    "nb_semicolumn",
    "nb_dollar",
    "nb_space",
    "nb_www",
    "nb_com",
    "nb_dslash",
    "http_in_path",
    "https_token",
    "ratio_digits_url",
    "ratio_digits_host",
    "punycode",
    "port",
    "tld_in_path",
    "tld_in_subdomain",
    "abnormal_subdomain",
    "nb_subdomains",
    "prefix_suffix",
    "random_domain",
    "shortening_service",
    "path_extension",
    "length_words_raw",
    "char_repeat",
    "shortest_words_raw",
    "shortest_word_host",
    "shortest_word_path",
    "longest_words_raw",
    "longest_word_host",
    "longest_word_path",
    "avg_words_raw",
    "avg_word_host",
    "avg_word_path",
    "phish_hints",
    "domain_in_brand",
    "brand_in_subdomain",
    "brand_in_path",
    "suspecious_tld",
]


def _safe_ratio(numerator: int, denominator: int) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _word_stats(text: str):
    words = [w for w in re.split(r"[^a-zA-Z0-9]+", text.lower()) if w]
    if not words:
        return 0, 0, 0, 0.0
    lengths = [len(w) for w in words]
    return len(words), min(lengths), max(lengths), sum(lengths) / len(lengths)


def _char_repeat_score(text: str) -> int:
    # Counts repeated runs such as "aaaa" or "1111" as a suspiciousness indicator.
    return sum(1 for _, group in re.findall(r"((.)\\2{2,})", text.lower()))


def _is_ip(hostname: str) -> int:
    try:
        ip_address(hostname)
        return 1
    except ValueError:
        return 0


def _domain_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return entropy


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def encode_url_to_char_sequence(url: str, char_to_index=None, max_length=MAX_URL_SEQUENCE_LENGTH) -> np.ndarray:
    url = normalize_url(url).lower()
    char_to_index = char_to_index or URL_CHAR_TO_INDEX
    sequence = []
    for char in url:
        if len(sequence) >= max_length:
            break
        sequence.append(char_to_index.get(char, URL_OOV_INDEX))
    if len(sequence) < max_length:
        sequence += [URL_PAD_INDEX] * (max_length - len(sequence))
    return np.array(sequence, dtype=np.int32)


def extract_url_features(url: str, feature_names=None) -> pd.DataFrame:
    url = normalize_url(url)
    parsed = urlparse(url)
    host_port = parsed.netloc.lower()
    hostname = host_port.split("@")[-1].split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    url_l = url.lower()

    tld = EXTRACTOR(url)
    subdomain = (tld.subdomain or "").lower()
    domain = (tld.domain or "").lower()
    suffix = (tld.suffix or "").lower()

    raw_word_count, shortest_raw, longest_raw, avg_raw = _word_stats(url_l)
    _, shortest_host, longest_host, avg_host = _word_stats(hostname)
    _, shortest_path, longest_path, avg_path = _word_stats(path)

    host_parts = [p for p in subdomain.split(".") if p]
    full_domain = f"{domain}.{suffix}" if suffix else domain

    phish_hints = sum(url_l.count(hint) for hint in PHISH_HINTS)
    domain_in_brand = 1 if domain in PROTECTED_BRANDS else 0
    brand_in_subdomain = 1 if any(brand in subdomain for brand in PROTECTED_BRANDS) else 0
    brand_in_path = 1 if any(brand in path.lower() for brand in PROTECTED_BRANDS) else 0

    try:
        has_port = 1 if parsed.port else 0
    except ValueError:
        has_port = 0

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": _is_ip(hostname),
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" "),
        "nb_www": 1 if "www" in hostname else 0,
        "nb_com": url_l.count(".com"),
        "nb_dslash": url.count("//"),
        "http_in_path": 1 if "http" in path.lower() else 0,
        "https_token": 1 if parsed.scheme == "https" else 0,
        "ratio_digits_url": _safe_ratio(sum(c.isdigit() for c in url), len(url)),
        "ratio_digits_host": _safe_ratio(sum(c.isdigit() for c in hostname), len(hostname)),
        "punycode": 1 if "xn--" in hostname else 0,
        "port": has_port,
        "tld_in_path": 1 if suffix and suffix in path.lower() else 0,
        "tld_in_subdomain": 1 if suffix and suffix in subdomain else 0,
        "abnormal_subdomain": 1 if subdomain and any(ch.isdigit() for ch in subdomain) else 0,
        "nb_subdomains": len(host_parts),
        "prefix_suffix": 1 if "-" in domain else 0,
        "random_domain": 1 if _domain_entropy(domain) > 3.3 and _safe_ratio(sum(c.isdigit() for c in domain), len(domain)) > 0.2 else 0,
        "shortening_service": 1 if full_domain in SHORTENERS else 0,
        "path_extension": 1 if any(path.lower().endswith(ext) for ext in PATH_EXTENSIONS) else 0,
        "length_words_raw": raw_word_count,
        "char_repeat": _char_repeat_score(url_l),
        "shortest_words_raw": shortest_raw,
        "shortest_word_host": shortest_host,
        "shortest_word_path": shortest_path,
        "longest_words_raw": longest_raw,
        "longest_word_host": longest_host,
        "longest_word_path": longest_path,
        "avg_words_raw": avg_raw,
        "avg_word_host": avg_host,
        "avg_word_path": avg_path,
        "phish_hints": phish_hints,
        "domain_in_brand": domain_in_brand,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_path": brand_in_path,
        "suspecious_tld": 1 if suffix.split(".")[-1] in SUSPICIOUS_TLDS else 0,
    }

    ordered = feature_names or ENHANCED_FEATURES
    row = {name: features.get(name, 0) for name in ordered}
    return pd.DataFrame([row])
