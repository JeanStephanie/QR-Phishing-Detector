import time
import threading
import ipaddress
from collections import defaultdict

from flask import request, jsonify, current_app

from extensions import limiter


_request_timestamps = defaultdict(list)
_debounce_cache = {}
_debounce_lock = threading.Lock()


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded and current_app.config.get("TRUST_PROXY_HEADERS", False):
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def is_local_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return ip.lower() == "localhost"


def is_duplicate_request(key):
    now = time.time()
    window = current_app.config.get("REQUEST_DEBOUNCE_SECONDS", 2)
    with _debounce_lock:
        last = _debounce_cache.get(key)
        if last and (now - last) < window:
            return True
        _debounce_cache[key] = now
        if len(_debounce_cache) > 10000:
            cutoff = now - window
            stale = [k for k, v in _debounce_cache.items() if v < cutoff]
            for k in stale:
                del _debounce_cache[k]
    return False


def track_burst(ip):
    now = time.time()
    window = current_app.config.get("BURST_WINDOW_SECONDS", 5)
    threshold = current_app.config.get("BURST_THRESHOLD", 20)
    _request_timestamps[ip].append(now)
    _request_timestamps[ip] = [t for t in _request_timestamps[ip] if now - t <= window]
    return len(_request_timestamps[ip]) >= threshold


def rate_limit_exceeded_handler(e):
    return jsonify({"error": "request failed", "message": "Too many requests"}), 429
