#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct  9 15:02:51 2025

@author: root
"""
#!/usr/bin/env python3
"""
lstm_classifier.py

Load LSTM model, extract features from a binary file, and classify.
All model logic is contained here.
"""

import numpy as np
from tensorflow.keras.models import load_model

# Optional: PE parsing
try:
    import pefile
except Exception:
    pefile = None

# -------------------- Feature extraction --------------------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))

def byte_histogram_coarse(data: bytes, bins: int = 32) -> list:
    if not data:
        return [0.0]*bins
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(float)
    counts /= counts.sum()
    group_size = 256 // bins
    coarse = [float(counts[i*group_size:(i+1)*group_size].sum()) for i in range(bins)]
    return coarse

def count_ascii_strings(data: bytes, min_len: int = 4) -> int:
    s = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in data)
    parts = [p for p in s.split() if len(p)>=min_len]
    return len(parts)

def analyze_pe(data: bytes) -> dict:
    res = {"is_pe": False, "imports_count": 0, "sections_count": 0}
    if not pefile:
        return res
    try:
        pe = pefile.PE(data=data, fast_load=True)
        res["is_pe"] = True
        imports_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports_count += len(entry.imports or [])
        res["imports_count"] = imports_count
        res["sections_count"] = len(pe.sections or [])
    except Exception:
        pass
    return res

def extract_features(data: bytes) -> np.ndarray:
    size = len(data)
    ent = entropy(data)
    is_pe = data.startswith(b"MZ")
    is_elf = data.startswith(b"\x7fELF")
    strings_count = count_ascii_strings(data)
    pe_info = analyze_pe(data)
    hist32 = byte_histogram_coarse(data)
    feature_vector = np.array([
        size, ent, int(is_pe), int(is_elf), strings_count,
        pe_info.get("imports_count",0),
        pe_info.get("sections_count",0)
    ] + hist32, dtype=float)
    return feature_vector

# -------------------- LSTM model setup --------------------
MODEL_PATH = "/home/devi/Downloads/malware_ffnn.h5"
LABEL_MAPPING = {
    0: "benign",
    1: "ransomware",
    2: "trojan",
    3: "adware"
    # add your classes here
}

# Load LSTM model once
_lstm_model = None
def get_model():
    global _lstm_model
    if _lstm_model is None:
        _lstm_model = load_model(MODEL_PATH)
    return _lstm_model

# -------------------- Prediction --------------------
def classify_file(data: bytes):
    """
    Input: binary data
    Output: dictionary with predicted label, confidence, probabilities, features
    """
    feature_vector = extract_features(data)
    model = get_model()
    X_input = np.expand_dims(feature_vector, axis=0)   # (1, num_features)
    X_input = np.expand_dims(X_input, axis=1)          # (1, 1, num_features)
    probs = model.predict(X_input, verbose=0)
    pred_idx = int(np.argmax(probs, axis=1)[0])
    label = LABEL_MAPPING.get(pred_idx, str(pred_idx))
    confidence = float(probs[0][pred_idx])
    return {
        "label": label,
        "confidence": confidence,
        "probabilities": probs[0].tolist(),
        "features": {
            "size": len(data),
            "entropy": float(feature_vector[1]),
            "is_pe": bool(feature_vector[2]),
            "is_elf": bool(feature_vector[3]),
            "strings_count": int(feature_vector[4])
        }
    }
