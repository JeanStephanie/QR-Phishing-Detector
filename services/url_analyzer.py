import re
import socket
import ssl
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

import requests

from utils.cache import ssl_cache, whois_cache, url_cache_key

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "bank", "paypal", "wallet", "free", "gift", "crypto",
    "account", "secure", "update", "confirm", "password", "signin", "otp",
}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

HOMOGRAPH_CHARS = re.compile(r"[^\x00-\x7F]")
IP_URL_PATTERN = re.compile(
    r"^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(/|$)"
)
HEX_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")
EXCESSIVE_SUBDOMAINS = 4

REQUEST_HEADERS = {
    "User-Agent": "SafeNet-QR-Shield/1.0 (+security-scanner)",
    "Accept": "text/html,application/xhtml+xml",
}


def extract_domain(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.lower().strip(".")
    except Exception:
        return ""


def is_private_or_local_url(url):
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return True
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return True
        try:
            addr = ipaddress.ip_address(host)
            for net in PRIVATE_NETWORKS:
                if addr in net:
                    return True
        except ValueError:
            if host.endswith(".local") or host.endswith(".internal"):
                return True
        return False
    except Exception:
        return True


def check_https(url, timeout=5):
    cache_key = f"ssl:{extract_domain(url)}"
    cached = ssl_cache.get(cache_key)
    if cached is not None:
        return cached

    result = {"valid": False, "status": "invalid", "details": "No HTTPS"}
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            result["details"] = "URL does not use HTTPS"
            ssl_cache.set(cache_key, result)
            return result
        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result = {"valid": True, "status": "valid", "details": "Valid TLS certificate"}
                else:
                    result = {"valid": False, "status": "warning", "details": "Certificate not verified"}
    except ssl.SSLError:
        result = {"valid": False, "status": "invalid", "details": "SSL certificate error"}
    except Exception:
        result = {"valid": False, "status": "invalid", "details": "SSL verification failed"}

    ssl_cache.set(cache_key, result)
    return result


def get_domain_age_days(domain, timeout=5):
    cache_key = f"whois:{domain}"
    cached = whois_cache.get(cache_key)
    if cached is not None:
        return cached

    age_days = 365
    try:
        import whois

        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo:
                created = created.replace(tzinfo=None)
            age_days = (datetime.now() - created).days
    except Exception:
        age_days = 30

    whois_cache.set(cache_key, age_days)
    return age_days


def detect_redirects(url, max_redirects=5, timeout=5):
    chain = [url]
    redirect_count = 0
    try:
        resp = requests.head(
            url, allow_redirects=True, timeout=timeout,
            headers=REQUEST_HEADERS, verify=True,
        )
        if resp.history:
            redirect_count = len(resp.history)
            chain = [r.url for r in resp.history] + [resp.url]
        elif resp.url != url:
            redirect_count = 1
            chain = [url, resp.url]
    except requests.RequestException:
        try:
            resp = requests.get(
                url, allow_redirects=True, timeout=timeout,
                headers=REQUEST_HEADERS, verify=True, stream=True,
            )
            redirect_count = len(resp.history)
            chain = [r.url for r in resp.history] + [resp.url] if resp.history else [url, resp.url]
            resp.close()
        except requests.RequestException:
            pass
    return redirect_count, chain[:max_redirects + 1]


def count_suspicious_words(url):
    lower = unquote(url).lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower)


def detect_homograph(url):
    domain = extract_domain(url)
    return bool(HOMOGRAPH_CHARS.search(domain))


def is_ip_url(url):
    return bool(IP_URL_PATTERN.match(url))


def is_url_shortener(url):
    domain = extract_domain(url)
    return domain in SHORTENERS or any(s in domain for s in SHORTENERS)


def count_subdomains(url):
    domain = extract_domain(url)
    parts = domain.split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def detect_obfuscation(url):
    score = 0
    if HEX_ENCODED.search(url):
        score += 1
    decoded = unquote(url)
    if decoded != url:
        score += 1
    if re.search(r"0x[0-9a-fA-F]+", url):
        score += 1
    return score


def url_entropy(url):
    if not url:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(url)
    length = len(url)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_url_features(url):
    domain = extract_domain(url)
    parsed = urlparse(url)
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphen": url.count("-"),
        "contains_ip": 1 if is_ip_url(url) else 0,
        "has_https": 1 if parsed.scheme == "https" else 0,
        "domain_age": get_domain_age_days(domain) if domain else 0,
        "suspicious_words": count_suspicious_words(url),
        "redirect_count": 0,
        "entropy_score": round(url_entropy(url), 4),
        "domain": domain,
    }


def fetch_page_signals(url, timeout=5):
    """Fetch page title/meta for supplemental keyword analysis."""
    from bs4 import BeautifulSoup

    signals = {"title_keywords": 0, "has_form": False}
    try:
        resp = requests.get(url, timeout=timeout, headers=REQUEST_HEADERS, verify=True, stream=True)
        chunk = resp.raw.read(8192, decode_content=True)
        resp.close()
        soup = BeautifulSoup(chunk, "html.parser")
        title = (soup.title.string or "") if soup.title else ""
        combined = title.lower()
        signals["title_keywords"] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in combined)
        signals["has_form"] = soup.find("form") is not None
    except Exception:
        pass
    return signals


def normalize_url_from_qr(content):
    content = (content or "").strip()
    if not content:
        return None
    if content.startswith(("http://", "https://")):
        return content
    if content.startswith("www."):
        return f"https://{content}"
    if "://" not in content and "." in content and " " not in content:
        return f"https://{content}"
    return None
