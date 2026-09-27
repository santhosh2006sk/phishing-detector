"""
Step 4: Risk Engine
----------------------
Combines the trained ML model's probability with rule-based signals
to produce a 0-100 risk score, a risk level, and human-readable reasons.

Usage:
    python risk_engine.py "http://example-login-verify.com/secure/account"
"""

import sys
import joblib
import pandas as pd

from feature_extraction import extract_features

MODEL_FILE = "model.pkl"


def load_model():
    data = joblib.load(MODEL_FILE)
    return data["model"], data["feature_names"]


def rule_based_signals(feats: dict) -> tuple[float, list[str]]:
    """Returns (rule_score 0-1, list of human-readable reasons)."""
    score = 0.0
    reasons = []

    if feats["has_ip"] == 1:
        score += 0.3
        reasons.append("URL uses a raw IP address instead of a domain name")

    if feats["is_https"] == 0:
        score += 0.15
        reasons.append("Connection is not secured with HTTPS")

    if feats["suspicious_word_count"] > 0:
        score += 0.2
        reasons.append("URL contains suspicious keywords (e.g. login, verify, secure)")

    if feats["num_subdomains"] > 2:
        score += 0.15
        reasons.append("Unusually high number of subdomains")

    if feats["num_hyphens"] > 3:
        score += 0.1
        reasons.append("Excessive hyphens in the URL (common phishing tactic)")

    if feats["url_length"] > 75:
        score += 0.1
        reasons.append("URL is unusually long")

    return min(score, 1.0), reasons


def score_url(url: str, model, feature_names) -> dict:
    feats = extract_features(url)
    hostname = feats.pop("hostname")

    X = pd.DataFrame([feats])[feature_names]
    ml_prob = model.predict_proba(X)[0][1]  # probability of class "1" = phishing

    rule_score, rule_reasons = rule_based_signals(feats)

    # Weighted combination: ML model does most of the work,
    # rules add explainable, human-understandable signals on top
    final_score = 0.75 * ml_prob + 0.25 * rule_score
    risk_percent = round(final_score * 100)

    if risk_percent <= 30:
        level = "Low"
    elif risk_percent <= 70:
        level = "Medium"
    else:
        level = "High"

    if not rule_reasons:
        rule_reasons = ["No major rule-based red flags detected"]

    return {
        "url": url,
        "hostname": hostname,
        "ml_probability": round(float(ml_prob), 3),
        "ml_score_percent": round(ml_prob * 100),
        "rule_score_percent": round(rule_score * 100),
        "risk_score": risk_percent,
        "risk_level": level,
        "reasons": rule_reasons,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python risk_engine.py "http://some-url.com"')
        sys.exit(1)

    url = sys.argv[1]
    model, feature_names = load_model()
    result = score_url(url, model, feature_names)

    print(f"\nURL: {result['url']}")
    print(f"Risk score: {result['risk_score']}/100  ({result['risk_level']})")
    print(f"ML model probability of phishing: {result['ml_probability']}")
    print("Reasons:")
    for r in result["reasons"]:
        print(f"  - {r}")
