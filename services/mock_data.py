"""
Mock data service for frontend demonstration.
Replace with MySQL queries and real analysis results when backend modules integrate.
"""

from datetime import datetime, timedelta
import random
import uuid


def _generate_scan_id():
    return str(uuid.uuid4())[:8].upper()


def get_demo_scan_result(scan_id=None, decoded_url=None):
    """Return a complete scan result payload for result.html and API."""
    sid = scan_id or _generate_scan_id()
    url = decoded_url or "https://secure-banking-verify.example/login"

    risk_roll = random.random()
    if risk_roll > 0.7:
        risk_level = "critical"
        phishing_prob = round(random.uniform(78, 96), 1)
        risk_score = random.randint(82, 98)
        verdict = "malicious"
    elif risk_roll > 0.4:
        risk_level = "medium"
        phishing_prob = round(random.uniform(35, 65), 1)
        risk_score = random.randint(45, 72)
        verdict = "suspicious"
    else:
        risk_level = "low"
        phishing_prob = round(random.uniform(2, 18), 1)
        risk_score = random.randint(8, 28)
        verdict = "safe"

    indicators = []
    if verdict != "safe":
        indicators = [
            {"type": "domain", "severity": "high", "message": "Domain registered within last 14 days"},
            {"type": "ssl", "severity": "medium", "message": "SSL certificate issuer not in trusted CA list"},
            {"type": "url", "severity": "high", "message": "URL contains homoglyph characters mimicking brand"},
            {"type": "blacklist", "severity": "critical", "message": "Domain found on PhishTank feed"},
        ]
    else:
        indicators = [
            {"type": "domain", "severity": "low", "message": "Established domain with valid WHOIS history"},
            {"type": "ssl", "severity": "low", "message": "Valid EV SSL certificate detected"},
        ]

    return {
        "scan_id": sid,
        "decoded_url": url,
        "phishing_probability": phishing_prob,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "ssl_status": "invalid" if verdict == "malicious" else ("warning" if verdict == "suspicious" else "valid"),
        "ssl_details": "Certificate expired or self-signed" if verdict == "malicious" else "Valid TLS 1.3",
        "blacklist_status": "listed" if verdict == "malicious" else ("monitoring" if verdict == "suspicious" else "clean"),
        "blacklist_sources": ["PhishTank", "OpenPhish"] if verdict == "malicious" else [],
        "suspicious_indicators": indicators,
        "recommendations": _recommendations(verdict),
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_ms": random.randint(420, 1850),
        "domain_age_days": random.randint(3, 1200) if verdict != "safe" else random.randint(800, 5000),
        "redirect_chain": ["bit.ly/xyz", url] if verdict != "safe" else [url],
        "threat_categories": ["phishing", "credential_harvest"] if verdict == "malicious" else [],
    }


def _recommendations(verdict):
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


def get_scan_history(page=1, per_page=10, search="", risk_filter="all"):
    """Paginated scan history for history.html and API."""
    all_scans = []
    base_time = datetime.utcnow()

    samples = [
        ("https://paypal-secure-login.xyz/verify", "malicious", 94),
        ("https://github.com/safenet-qr", "safe", 12),
        ("https://amazon-deals-offer.tk/checkout", "suspicious", 67),
        ("https://google.com", "safe", 5),
        ("https://microsoft-account-update.ru/auth", "malicious", 89),
        ("https://linkedin.com/in/profile", "safe", 8),
        ("https://netflix-billing-alert.co/update", "suspicious", 58),
        ("https://stripe.com/docs", "safe", 3),
        ("https://apple-id-verify.click/unlock", "malicious", 91),
        ("https://cloudflare.com", "safe", 7),
        ("https://dropbox-share-files.ml/view", "suspicious", 62),
        ("https://notion.so", "safe", 4),
        ("https://whatsapp-verify-number.ga/otp", "malicious", 87),
        ("https://vercel.com", "safe", 6),
        ("https://dhl-package-tracking.info/track", "suspicious", 55),
    ]

    for i, (url, verdict, score) in enumerate(samples):
        all_scans.append({
            "scan_id": f"SN{i+1001:04d}",
            "url": url,
            "verdict": verdict,
            "risk_score": score,
            "scanned_at": (base_time - timedelta(hours=i * 3 + random.randint(0, 120))).strftime("%Y-%m-%d %H:%M"),
            "source": random.choice(["upload", "webcam", "api"]),
            "user": "demo@safenet.io",
        })

    if search:
        q = search.lower()
        all_scans = [s for s in all_scans if q in s["url"].lower() or q in s["scan_id"].lower()]

    if risk_filter != "all":
        all_scans = [s for s in all_scans if s["verdict"] == risk_filter]

    total = len(all_scans)
    start = (page - 1) * per_page
    end = start + per_page
    items = all_scans[start:end]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


def get_dashboard_stats():
    """Dashboard analytics for dashboard.html and API."""
    return {
        "total_scans": 12847,
        "scans_today": 342,
        "threats_blocked": 1847,
        "safe_urls": 10912,
        "avg_scan_time_ms": 687,
        "active_users": 156,
        "malicious_rate": 14.4,
        "recent_activity": [
            {"action": "Malicious QR blocked", "detail": "paypal-secure-login.xyz", "time": "2 min ago", "type": "danger"},
            {"action": "Scan completed", "detail": "github.com/safenet-qr", "time": "5 min ago", "type": "success"},
            {"action": "Suspicious URL flagged", "detail": "amazon-deals-offer.tk", "time": "12 min ago", "type": "warning"},
            {"action": "New user registered", "detail": "analyst@corp.security", "time": "18 min ago", "type": "info"},
            {"action": "Webcam scan", "detail": "Safe URL verified", "time": "24 min ago", "type": "success"},
            {"action": "Admin policy updated", "detail": "Strict SSL enforcement", "time": "1 hr ago", "type": "info"},
        ],
        "chart_labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "chart_scans": [420, 512, 489, 601, 578, 312, 342],
        "chart_threats": [58, 72, 65, 89, 81, 44, 49],
        "verdict_distribution": {"safe": 72, "suspicious": 14, "malicious": 14},
    }


def get_admin_stats():
    """Admin panel analytics."""
    return {
        "total_users": 1248,
        "active_sessions": 89,
        "total_scans_all_time": 89432,
        "malicious_trend": [12, 15, 18, 14, 22, 19, 24],
        "users_growth": [980, 1020, 1080, 1120, 1180, 1210, 1248],
        "top_threat_domains": [
            {"domain": "paypal-secure-login.xyz", "count": 234},
            {"domain": "microsoft-account-update.ru", "count": 189},
            {"domain": "apple-id-verify.click", "count": 156},
            {"domain": "whatsapp-verify-number.ga", "count": 142},
            {"domain": "netflix-billing-alert.co", "count": 98},
        ],
        "users": [
            {"id": 1, "email": "admin@safenet.io", "role": "admin", "scans": 1240, "status": "active", "last_login": "2026-05-28 09:15"},
            {"id": 2, "email": "analyst@corp.security", "role": "analyst", "scans": 892, "status": "active", "last_login": "2026-05-28 08:42"},
            {"id": 3, "email": "demo@user.io", "role": "user", "scans": 156, "status": "active", "last_login": "2026-05-27 22:10"},
            {"id": 4, "email": "test@example.com", "role": "user", "scans": 45, "status": "suspended", "last_login": "2026-05-20 14:30"},
            {"id": 5, "email": "soc@enterprise.com", "role": "analyst", "scans": 2103, "status": "active", "last_login": "2026-05-28 07:55"},
        ],
        "system_health": {
            "api": 99.9,
            "database": 99.5,
            "ml_service": 98.2,
            "storage": 87.4,
        },
    }


def get_live_stats():
    """Homepage live stats counters."""
    return {
        "scans_processed": 12847,
        "threats_detected": 1847,
        "urls_analyzed": 89432,
        "uptime_percent": 99.97,
    }
