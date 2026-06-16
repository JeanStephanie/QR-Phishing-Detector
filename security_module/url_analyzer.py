from urllib.parse import urlparse
import re

def analyze_url(url):

    score = 0
    reasons = []

    # HTTPS Check
    if not url.startswith("https://"):
        score += 20
        reasons.append("Not using HTTPS")

    # Suspicious Keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "account",
        "password",
        "signin",
        "update"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword detected: {word}")

    # Long URL Check
    if len(url) > 75:
        score += 10
        reasons.append("Long URL detected")

    domain = urlparse(url).netloc

    # Hyphen Check
    if domain.count("-") >= 2:
        score += 15
        reasons.append("Too many hyphens in domain")

    # IP Address Check
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 25
        reasons.append("IP address used instead of domain")

    # URL Shortener Check
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl"
    ]

    for site in shorteners:
        if site in domain:
            score += 20
            reasons.append("URL shortener detected")

    # Suspicious TLD Check
    if domain.endswith((".xyz", ".top", ".tk", ".ml")):
        score += 15
        reasons.append("Suspicious domain extension")

    # Classification
    if score < 20:
        status = "Safe"
    elif score < 50:
        status = "Suspicious"
    else:
        status = "Phishing Risk"

    return {
        "risk_score": min(score, 100),
        "status": status,
        "reasons": reasons
    }