import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

from flask import current_app

from services.url_analyzer import (
    extract_url_features,
    normalize_url_from_qr,
    detect_redirects,
    is_private_or_local_url,
)
from services.ml_predictor import predict_phishing
from services.risk_engine import (
    compute_risk_score,
    risk_to_verdict,
    get_recommendations,
    get_threat_categories,
)
from services.database_service import save_scan
from services.logger import log_event
from utils.cache import scan_cache, url_cache_key

scan_semaphore = threading.Semaphore(5)


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def analyze_qr_content(qr_content, user_id=None, source="upload", preview_image=None):
    if not scan_semaphore.acquire(blocking=False):
        return None, "Server busy. Too many concurrent scans."

    try:
        return _run_analysis(qr_content, user_id, source, preview_image)
    finally:
        scan_semaphore.release()


def _run_analysis(qr_content, user_id, source, preview_image):
    from services.security_engine import run_security_analysis

    start = time.time()
    timeout = current_app.config.get("SCAN_TIMEOUT_SECONDS", 10)

    url = normalize_url_from_qr(qr_content)
    if not url:
        return None, "No valid URL found in QR code"

    if is_private_or_local_url(url):
        log_event("blocked_private_url", user_id=user_id, details=url[:200])
        return None, "URL targets restricted network address"

    cache_key = url_cache_key(url)
    cached = scan_cache.get(cache_key)
    if cached:
        result = dict(cached)
        result["scan_id"] = uuid.uuid4().hex[:8].upper()
        result["scanned_at"] = _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        if preview_image:
            result["preview_image"] = preview_image
        save_scan(user_id, result, source=source)
        return result, None

    try:
        app = current_app._get_current_object()

        def _run(fn, *args):
            with app.app_context():
                return fn(*args)

        with ThreadPoolExecutor(max_workers=4) as executor:
            features_future = executor.submit(_run, _build_features, url)
            security_future = executor.submit(_run, run_security_analysis, url)

            features = features_future.result(timeout=timeout)
            security = security_future.result(timeout=timeout)

            redirect_future = executor.submit(_run, detect_redirects, url)
            redirect_count, redirect_chain = redirect_future.result(timeout=timeout)
            features["redirect_count"] = redirect_count

            ml_future = executor.submit(predict_phishing, features)
            ml_prob = ml_future.result(timeout=timeout)
    except FuturesTimeout:
        return _fallback_result(url, qr_content, user_id, source, preview_image, start), None
    except Exception:
        return _fallback_result(url, qr_content, user_id, source, preview_image, start), None

    risk_score = compute_risk_score(security["security_score"], ml_prob)
    verdict, risk_level = risk_to_verdict(risk_score)

    elapsed_ms = int((time.time() - start) * 1000)
    scan_id = uuid.uuid4().hex[:8].upper()

    result = {
        "scan_id": scan_id,
        "decoded_url": url,
        "final_url": security.get("redirect_chain", [url])[-1] if security.get("redirect_chain") else url,
        "qr_content": qr_content,
        "domain": security["domain"],
        "phishing_probability": ml_prob,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "ssl_status": security["ssl_status"],
        "ssl_details": security["ssl_details"],
        "blacklist_status": security["blacklist_status"],
        "blacklist_sources": security["blacklist_sources"],
        "suspicious_indicators": security["indicators"],
        "recommendations": get_recommendations(verdict),
        "scanned_at": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_ms": elapsed_ms,
        "domain_age_days": security["domain_age_days"],
        "redirect_chain": security["redirect_chain"],
        "redirect_count": security.get("redirect_count", 0),
        "analysis_components": _analysis_components(security, ml_prob, risk_score),
        "threat_categories": get_threat_categories(verdict, security["indicators"]),
    }

    if preview_image:
        result["preview_image"] = preview_image

    scan_cache.set(cache_key, result)
    save_scan(user_id, result, source=source)

    if verdict == "malicious":
        log_event("malicious_url_detected", user_id=user_id, details=url[:200])
    else:
        log_event("scan_completed", user_id=user_id, details=f"{scan_id}:{verdict}")

    return result, None


def _build_features(url):
    features = extract_url_features(url)
    return features


def _analysis_components(security, ml_prob, risk_score):
    ssl_component = 0
    if security.get("ssl_status") == "invalid":
        ssl_component = 20
    elif security.get("ssl_status") == "warning":
        ssl_component = 10

    blacklist_component = 30 if security.get("blacklist_status") == "listed" else 0
    redirect_component = min(20, int(security.get("redirect_count", 0) or 0) * 5)
    domain_age = security.get("domain_age_days")
    domain_component = 0
    if isinstance(domain_age, int):
        if domain_age < 30:
            domain_component = 15
        elif domain_age < 180:
            domain_component = 5

    return {
        "ml": round(float(ml_prob or 0), 1),
        "security": int(security.get("security_score", 0) or 0),
        "ssl": ssl_component,
        "redirects": redirect_component,
        "domain_age": domain_component,
        "blacklist": blacklist_component,
        "final": int(risk_score),
    }


def _fallback_result(url, qr_content, user_id, source, preview_image, start):
    from services.url_analyzer import (
        count_suspicious_words,
        extract_domain,
        is_ip_url,
        is_url_shortener,
    )

    domain = extract_domain(url)
    score = 10
    indicators = [{
        "type": "analysis",
        "severity": "medium",
        "message": "Live network checks were limited, so this result uses offline URL signals.",
    }]
    if not url.startswith("https://"):
        score += 20
        indicators.append({
            "type": "ssl",
            "severity": "high",
            "message": "URL does not use HTTPS",
        })
    if is_ip_url(url):
        score += 25
        indicators.append({
            "type": "url",
            "severity": "high",
            "message": "Direct IP address URL detected",
        })
    suspicious_words = count_suspicious_words(url)
    if suspicious_words:
        score += min(25, suspicious_words * 8)
        indicators.append({
            "type": "url",
            "severity": "medium",
            "message": "URL contains suspicious keywords",
        })
    if is_url_shortener(url):
        score += 10
        indicators.append({
            "type": "url",
            "severity": "medium",
            "message": "URL shortening service detected",
        })

    risk_score = min(100, score)
    verdict, risk_level = risk_to_verdict(risk_score)
    scan_id = uuid.uuid4().hex[:8].upper()
    result = {
        "scan_id": scan_id,
        "decoded_url": url,
        "final_url": url,
        "qr_content": qr_content,
        "domain": domain,
        "phishing_probability": round(risk_score / 100, 2),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "ssl_status": "valid" if url.startswith("https://") else "invalid",
        "ssl_details": "Offline fallback result; certificate was not verified live.",
        "blacklist_status": "unknown",
        "blacklist_sources": [],
        "suspicious_indicators": indicators,
        "recommendations": get_recommendations(verdict),
        "scanned_at": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_ms": int((time.time() - start) * 1000),
        "domain_age_days": 0,
        "redirect_chain": [url],
        "redirect_count": 0,
        "analysis_components": {
            "ml": round(risk_score / 100, 2),
            "security": risk_score,
            "ssl": 0 if url.startswith("https://") else 20,
            "redirects": 0,
            "domain_age": 0,
            "blacklist": 0,
            "final": risk_score,
        },
        "threat_categories": get_threat_categories(verdict, indicators),
    }
    if preview_image:
        result["preview_image"] = preview_image
    save_scan(user_id, result, source=source)
    log_event("scan_completed_fallback", user_id=user_id, details=f"{scan_id}:{verdict}")
    return result


def process_uploaded_image(image_bytes, user_id=None, preview_url=None):
    from services.qr_decoder import decode_qr_from_bytes

    qr_content = decode_qr_from_bytes(image_bytes)
    if not qr_content:
        return None, "No QR code detected in image"
    return analyze_qr_content(qr_content, user_id=user_id, source="upload", preview_image=preview_url)


def process_webcam_payload(data, user_id=None):
    import base64
    import binascii
    from services.qr_decoder import validate_image_bytes

    if data.get("url"):
        return analyze_qr_content(data["url"], user_id=user_id, source="webcam")

    image_b64 = data.get("image")
    if image_b64:
        try:
            if "," in image_b64:
                image_b64 = image_b64.split(",", 1)[1]
            image_bytes = base64.b64decode(image_b64, validate=True)
            valid, error = validate_image_bytes(image_bytes, current_app.config)
            if not valid:
                return None, error or "Invalid image data"
            return process_uploaded_image(image_bytes, user_id=user_id)
        except (ValueError, binascii.Error):
            return None, "Invalid image data"

    return None, "No QR data received"
