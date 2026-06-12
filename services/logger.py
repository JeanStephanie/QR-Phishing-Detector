from flask import request

from extensions import db
from models.logs import AuditLog


def log_event(event, user_id=None, details=None):
    try:
        entry = AuditLog(
            event=event,
            ip_address=_get_ip(),
            user_agent=(request.headers.get("User-Agent") or "")[:512] if request else None,
            user_id=user_id,
            details=(details or "")[:1000] if details else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def log_batch(events):
    try:
        for evt in events:
            db.session.add(AuditLog(**evt))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _get_ip():
    if not request:
        return None
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr
