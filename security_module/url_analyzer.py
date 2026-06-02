from urllib.parse import urlparse

def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 20
        reasons.append("Not using HTTPS")

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "bank",
        "account",
        "password"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {word}")

    if len(url) > 75:
        score += 10
        reasons.append("Long URL detected")

    domain = urlparse(url).netloc

    if domain.count("-") >= 2:
        score += 15
        reasons.append("Too many hyphens in domain")

    return {
        "risk_score": min(score, 100),
        "reasons": reasons
    }