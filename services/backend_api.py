"""Client for the real QR phishing backend API."""

from datetime import datetime
import os

import requests


class BackendAPIError(RuntimeError):
    """Raised when the backend API cannot complete a scan."""


def _endpoint(base_url, path):
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _post(config, path, **kwargs):
    try:
        response = requests.post(
            _endpoint(config["BACKEND_API_URL"], path),
            timeout=config["BACKEND_TIMEOUT_SECONDS"],
            **kwargs,
        )
    except requests.RequestException as exc:
        raise BackendAPIError(f"Backend API is unreachable: {exc}") from exc

    if not response.ok:
        body = response.text[:300] if response.text else response.reason
        raise BackendAPIError(f"Backend API returned {response.status_code}: {body}")

    try:
        return response.json()
    except ValueError as exc:
        raise BackendAPIError("Backend API did not return valid JSON") from exc


def analyze_qr_image(config, image_path, original_filename):
    """Send a QR image to the backend and normalize its scan result."""
    with open(image_path, "rb") as image_file:
        payload = _post(
            config,
            config["BACKEND_SCAN_IMAGE_PATH"],
            files={
                "qr_image": (
                    original_filename or os.path.basename(image_path),
                    image_file,
                    "application/octet-stream",
                )
            },
        )
    return normalize_scan_result(payload)


def analyze_url(config, decoded_url):
    """Send an already-decoded URL to the backend and normalize its scan result."""
    payload = _post(
        config,
        config["BACKEND_SCAN_URL_PATH"],
        json={"url": decoded_url},
        headers={"Content-Type": "application/json"},
    )
    return normalize_scan_result(payload)


def normalize_scan_result(payload):
    """Convert common backend response formats into the template contract."""
    result = payload.get("result", payload) if isinstance(payload, dict) else {}
    if not isinstance(result, dict):
        raise BackendAPIError("Backend API returned an unsupported result format")

    verdict = str(result.get("verdict") or result.get("status") or "suspicious").lower()
    if verdict not in {"safe", "suspicious", "malicious"}:
        verdict = "suspicious"

    probability = result.get("phishing_probability", result.get("probability", result.get("confidence", 0)))
    risk_score = result.get("risk_score", result.get("score", probability))

    try:
        probability = round(float(probability), 1)
    except (TypeError, ValueError):
        probability = 0

    try:
        risk_score = int(round(float(risk_score)))
    except (TypeError, ValueError):
        risk_score = 0

    indicators = result.get("suspicious_indicators") or result.get("indicators") or []
    if isinstance(indicators, list):
        indicators = [
            item if isinstance(item, dict) else {"type": "signal", "message": str(item)}
            for item in indicators
        ]
    else:
        indicators = []

    recommendations = result.get("recommendations") or []
    if not isinstance(recommendations, list):
        recommendations = [str(recommendations)]

    return {
        "scan_id": result.get("scan_id") or result.get("id") or payload.get("scan_id", "LIVE"),
        "decoded_url": result.get("decoded_url") or result.get("url") or result.get("target_url") or "No URL decoded",
        "phishing_probability": probability,
        "risk_score": risk_score,
        "risk_level": result.get("risk_level") or _risk_level(risk_score),
        "verdict": verdict,
        "ssl_status": result.get("ssl_status") or result.get("ssl") or "unknown",
        "ssl_details": result.get("ssl_details") or "",
        "blacklist_status": result.get("blacklist_status") or result.get("blacklist") or "unknown",
        "blacklist_sources": result.get("blacklist_sources") or [],
        "suspicious_indicators": indicators,
        "recommendations": recommendations or _default_recommendations(verdict),
        "scanned_at": result.get("scanned_at") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_ms": result.get("scan_duration_ms") or result.get("duration_ms") or 0,
        "domain_age_days": result.get("domain_age_days"),
        "redirect_chain": result.get("redirect_chain") or [],
        "threat_categories": result.get("threat_categories") or [],
    }


def _risk_level(score):
    if score >= 75:
        return "critical"
    if score >= 40:
        return "medium"
    return "low"


def _default_recommendations(verdict):
    if verdict == "malicious":
        return ["Do not open this URL or enter credentials.", "Report it to your security team."]
    if verdict == "suspicious":
        return ["Verify the URL through an official source before continuing."]
    return ["URL appears safe based on the backend analysis."]
