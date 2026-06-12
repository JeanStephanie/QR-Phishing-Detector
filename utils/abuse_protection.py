import os
import time
import threading
from datetime import datetime, timedelta, timezone

from flask import request, jsonify, current_app

from extensions import db
from models.logs import BlockedIP, AuditLog
from utils.rate_limit import get_client_ip, is_local_ip, track_burst


_lockdown_until = None
_lockdown_lock = threading.Lock()
_abuse_counter = {}
_abuse_lock = threading.Lock()


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_ip_blocked(ip):
    if is_local_ip(ip):
        return False
    blocked = BlockedIP.query.filter_by(ip_address=ip).first()
    if not blocked:
        return False
    if blocked.blocked_until <= _utcnow():
        db.session.delete(blocked)
        db.session.commit()
        return False
    return True


def block_ip(ip, reason, minutes=None):
    if is_local_ip(ip):
        return
    minutes = minutes or current_app.config.get("BURST_BLOCK_MINUTES", 15)
    until = _utcnow() + timedelta(minutes=minutes)
    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        existing.reason = reason
        existing.blocked_until = until
    else:
        db.session.add(BlockedIP(ip_address=ip, reason=reason, blocked_until=until))
    db.session.commit()


def is_lockdown_active():
    global _lockdown_until
    with _lockdown_lock:
        if _lockdown_until and _utcnow() < _lockdown_until:
            return True
        _lockdown_until = None
        return False


def activate_lockdown():
    global _lockdown_until
    duration = current_app.config.get("LOCKDOWN_DURATION_MINUTES", 10)
    with _lockdown_lock:
        _lockdown_until = _utcnow() + timedelta(minutes=duration)


def record_abuse(ip, event_type):
    threshold = current_app.config.get("LOCKDOWN_THRESHOLD", 100)
    with _abuse_lock:
        key = f"{ip}:{event_type}"
        _abuse_counter[key] = _abuse_counter.get(key, 0) + 1
        if _abuse_counter[key] >= threshold:
            activate_lockdown()
            _abuse_counter[key] = 0


def check_abuse_before_request():
    ip = get_client_ip()
    if is_local_ip(ip) or current_app.config.get("DEVELOPMENT_MODE", False):
        return None
    if request.endpoint == "static" or request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if is_ip_blocked(ip):
        return jsonify({"error": "request failed", "message": "Access temporarily blocked"}), 403
    if is_lockdown_active() and request.endpoint in ("main.upload", "api.webcam_complete"):
        return jsonify({"error": "request failed", "message": "Service temporarily unavailable"}), 503
    if track_burst(ip):
        block_ip(ip, "Burst attack detected")
        record_abuse(ip, "burst")
        return jsonify({"error": "request failed", "message": "Access temporarily blocked"}), 429
    return None


def log_abuse_event(event, details=None):
    ip = get_client_ip()
    log = AuditLog(
        event=event,
        ip_address=ip,
        user_agent=(request.headers.get("User-Agent") or "")[:512],
        details=details,
    )
    db.session.add(log)
    db.session.commit()
    record_abuse(ip, event)


def get_upload_folder_size(upload_folder):
    total = 0
    if not os.path.isdir(upload_folder):
        return 0
    for entry in os.scandir(upload_folder):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total


def cleanup_oldest_uploads(upload_folder, target_free_bytes):
    if not os.path.isdir(upload_folder):
        return
    files = []
    for entry in os.scandir(upload_folder):
        if entry.is_file():
            try:
                stat = entry.stat()
                files.append((entry.path, stat.st_mtime, stat.st_size))
            except OSError:
                pass
    files.sort(key=lambda x: x[1])
    for path, _, size in files:
        if get_upload_folder_size(upload_folder) <= target_free_bytes:
            break
        try:
            os.remove(path)
        except OSError:
            pass
