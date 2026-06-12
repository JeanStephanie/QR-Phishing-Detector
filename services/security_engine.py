from services.url_analyzer import (
    check_https,
    detect_homograph,
    detect_obfuscation,
    detect_redirects,
    count_subdomains,
    count_suspicious_words,
    extract_domain,
    get_domain_age_days,
    is_ip_url,
    is_private_or_local_url,
    is_url_shortener,
)
from services.database_service import is_domain_blacklisted


def run_security_analysis(url):
    indicators = []
    security_score = 0
    domain = extract_domain(url)

    if is_private_or_local_url(url):
        security_score += 40
        indicators.append({
            "type": "url", "severity": "critical",
            "message": "URL targets private or local network address",
        })

    if is_ip_url(url):
        security_score += 25
        indicators.append({
            "type": "url", "severity": "high",
            "message": "Direct IP address URL detected",
        })

    ssl_result = check_https(url)
    if ssl_result["status"] == "invalid":
        security_score += 20
        indicators.append({
            "type": "ssl", "severity": "high",
            "message": ssl_result["details"],
        })
    elif ssl_result["status"] == "warning":
        security_score += 10
        indicators.append({
            "type": "ssl", "severity": "medium",
            "message": ssl_result["details"],
        })
    else:
        indicators.append({
            "type": "ssl", "severity": "low",
            "message": "Valid HTTPS certificate detected",
        })

    redirect_count, redirect_chain = detect_redirects(url)
    if redirect_count >= 3:
        security_score += 15
        indicators.append({
            "type": "url", "severity": "medium",
            "message": f"Excessive redirects detected ({redirect_count})",
        })

    susp_words = count_suspicious_words(url)
    if susp_words >= 3:
        security_score += 15
        indicators.append({
            "type": "url", "severity": "high",
            "message": f"URL contains {susp_words} suspicious keywords",
        })
    elif susp_words >= 1:
        security_score += 5
        indicators.append({
            "type": "url", "severity": "medium",
            "message": "URL contains suspicious keywords",
        })

    if detect_homograph(url):
        security_score += 20
        indicators.append({
            "type": "url", "severity": "high",
            "message": "Homograph attack characters detected in domain",
        })

    if is_url_shortener(url):
        security_score += 10
        indicators.append({
            "type": "url", "severity": "medium",
            "message": "URL shortening service detected",
        })

    subdomains = count_subdomains(url)
    if subdomains >= 4:
        security_score += 10
        indicators.append({
            "type": "domain", "severity": "medium",
            "message": f"Excessive subdomains detected ({subdomains})",
        })

    obfuscation = detect_obfuscation(url)
    if obfuscation >= 2:
        security_score += 15
        indicators.append({
            "type": "url", "severity": "high",
            "message": "Obfuscated URL encoding detected",
        })

    try:
        from services.url_analyzer import fetch_page_signals
        page = fetch_page_signals(url)
        if page.get("title_keywords", 0) >= 2:
            security_score += 10
            indicators.append({
                "type": "url", "severity": "medium",
                "message": "Page title contains suspicious keywords",
            })
        if page.get("has_form"):
            security_score += 5
    except Exception:
        pass

    listed, threat_level = is_domain_blacklisted(domain)
    blacklist_status = "clean"
    blacklist_sources = []
    if listed:
        security_score += 30 if threat_level == "critical" else 20
        blacklist_status = "listed"
        blacklist_sources = ["Local Blacklist"]
        indicators.append({
            "type": "blacklist", "severity": "critical" if threat_level == "critical" else "high",
            "message": f"Domain found on local blacklist ({threat_level})",
        })

    domain_age = get_domain_age_days(domain) if domain else 0
    if domain_age < 30:
        security_score += 15
        indicators.append({
            "type": "domain", "severity": "high",
            "message": f"Domain registered within last {domain_age} days",
        })
    elif domain_age < 180:
        security_score += 5
        indicators.append({
            "type": "domain", "severity": "medium",
            "message": f"Relatively new domain ({domain_age} days old)",
        })
    else:
        indicators.append({
            "type": "domain", "severity": "low",
            "message": "Established domain with valid WHOIS history",
        })

    security_score = min(100, security_score)

    return {
        "security_score": security_score,
        "indicators": indicators,
        "ssl_status": ssl_result["status"],
        "ssl_details": ssl_result["details"],
        "blacklist_status": blacklist_status,
        "blacklist_sources": blacklist_sources,
        "redirect_chain": redirect_chain,
        "redirect_count": redirect_count,
        "domain_age_days": domain_age,
        "domain": domain,
    }
