import os
import threading

import joblib

_model = None
_model_lock = threading.Lock()
FEATURE_COLUMNS = [
    "url_length", "num_dots", "num_hyphen", "contains_ip",
    "has_https", "domain_age", "suspicious_words", "redirect_count", "entropy_score",
]


def load_model(model_path):
    global _model
    with _model_lock:
        if _model is None and os.path.exists(model_path):
            _model = joblib.load(model_path)
    return _model


def get_model():
    return _model


def predict_phishing(features_dict):
    model = _model
    if model is None:
        return _heuristic_prediction(features_dict)

    try:
        import pandas as pd
        vector = pd.DataFrame([{
            "url_length": features_dict.get("url_length", 0),
            "num_dots": features_dict.get("num_dots", 0),
            "num_hyphen": features_dict.get("num_hyphen", 0),
            "contains_ip": features_dict.get("contains_ip", 0),
            "has_https": features_dict.get("has_https", 0),
            "domain_age": features_dict.get("domain_age", 365),
            "suspicious_words": features_dict.get("suspicious_words", 0),
            "redirect_count": features_dict.get("redirect_count", 0),
            "entropy_score": features_dict.get("entropy_score", 0.0),
        }])
        proba = model.predict_proba(vector)[0]
        phishing_prob = round(float(proba[1]) * 100, 1)
        return phishing_prob
    except Exception:
        return _heuristic_prediction(features_dict)


def _heuristic_prediction(features):
    score = 10.0
    if features.get("contains_ip"):
        score += 25
    if not features.get("has_https"):
        score += 20
    if features.get("suspicious_words", 0) >= 2:
        score += 20
    if features.get("domain_age", 365) < 30:
        score += 15
    if features.get("redirect_count", 0) >= 2:
        score += 10
    if features.get("entropy_score", 0) > 4.5:
        score += 10
    return min(95.0, max(2.0, score))
