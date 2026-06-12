def compute_risk_score(security_score, ml_probability):
    """Combine security (60%) and ML (40%) into 0-100 risk score."""
    ml_score = ml_probability
    combined = (security_score * 0.6) + (ml_score * 0.4)
    return min(100, max(0, int(round(combined))))


def risk_to_verdict(risk_score):
    if risk_score <= 20:
        return "safe", "low"
    if risk_score <= 50:
        return "suspicious", "low"
    if risk_score <= 75:
        return "suspicious", "medium"
    return "malicious", "critical"


def risk_label(risk_score):
    if risk_score <= 20:
        return "Safe"
    if risk_score <= 50:
        return "Low Risk"
    if risk_score <= 75:
        return "Suspicious"
    return "Dangerous"


def get_recommendations(verdict):
    if verdict == "malicious":
        return [
            "Do not enter credentials on this URL",
            "Report this URL to your security team immediately",
            "Block domain at firewall/proxy level",
            "Run endpoint scan if already visited",
        ]
    if verdict == "suspicious":
        return [
            "Verify URL through official app or bookmark",
            "Contact organization directly before entering data",
            "Enable enhanced browser protection",
        ]
    return [
        "URL appears legitimate based on current threat intelligence",
        "Continue standard security hygiene practices",
        "Re-scan if URL behavior changes",
    ]


def get_threat_categories(verdict, indicators):
    categories = []
    if verdict == "malicious":
        categories.append("phishing")
    for ind in indicators:
        if ind.get("type") == "blacklist" and "phishing" not in categories:
            categories.append("credential_harvest")
        if "ssl" in ind.get("type", "") and ind.get("severity") in ("high", "critical"):
            if "mitm" not in categories:
                categories.append("mitm")
    return categories
