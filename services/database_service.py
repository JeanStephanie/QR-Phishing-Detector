import os
import uuid
from datetime import datetime, timezone, timedelta

from sqlalchemy import func, case, and_, cast, Date

from extensions import db
from models import User, ScanHistory, AuditLog, BlockedDomain, BlockedIP


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def init_database(app):
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["LOG_FOLDER"], exist_ok=True)
    with app.app_context():
        db.create_all()
        _seed_defaults()


def _seed_defaults():
    BlockedIP.query.filter(
        BlockedIP.ip_address.in_(["127.0.0.1", "::1", "localhost"])
    ).delete(synchronize_session=False)
    db.session.commit()

    if BlockedDomain.query.count() == 0:
        defaults = [
            ("paypal-secure-login.xyz", "critical"),
            ("microsoft-account-update.ru", "critical"),
            ("apple-id-verify.click", "high"),
            ("whatsapp-verify-number.ga", "high"),
            ("netflix-billing-alert.co", "medium"),
            ("bit.ly", "medium"),
            ("tinyurl.com", "medium"),
            ("goo.gl", "medium"),
        ]
        for domain, level in defaults:
            db.session.add(BlockedDomain(domain=domain, threat_level=level))
        db.session.commit()

    if User.query.filter_by(email="admin@safenet.io").first() is None:
        admin = User(
            username="admin",
            email="admin@safenet.io",
            role="admin",
            is_active=True,
        )
        admin.set_password("Admin@SafeNet123!")
        db.session.add(admin)
        db.session.commit()


def save_scan(user_id, scan_result, source="upload"):
    import json

    record = ScanHistory(
        scan_id=scan_result["scan_id"],
        user_id=user_id,
        qr_content=scan_result.get("qr_content", ""),
        scanned_url=scan_result["decoded_url"],
        domain=scan_result.get("domain", ""),
        prediction=scan_result["verdict"],
        phishing_probability=scan_result["phishing_probability"],
        risk_score=scan_result["risk_score"],
        source=source,
        scan_duration_ms=scan_result.get("scan_duration_ms", 0),
        result_json=json.dumps(scan_result),
    )
    db.session.add(record)
    db.session.commit()
    return record


def get_scan_by_id(scan_id):
    return ScanHistory.query.filter_by(scan_id=scan_id).first()


def get_scan_result_from_db(scan_id):
    import json

    record = get_scan_by_id(scan_id)
    if not record:
        return None
    if record.result_json:
        return json.loads(record.result_json)
    return _record_to_result(record)


def get_scan_result_for_user(scan_id, user_id, is_admin=False):
    record = get_scan_by_id(scan_id)
    if not record:
        return None
    if not is_admin and record.user_id != user_id:
        return None
    return get_scan_result_from_db(scan_id)


def _record_to_result(record):
    verdict = record.prediction
    risk_level = "low"
    if record.risk_score >= 76:
        risk_level = "critical"
    elif record.risk_score >= 51:
        risk_level = "medium"
    return {
        "scan_id": record.scan_id,
        "decoded_url": record.scanned_url,
        "final_url": record.scanned_url,
        "phishing_probability": record.phishing_probability,
        "risk_score": record.risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "scanned_at": record.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_duration_ms": record.scan_duration_ms,
    }


def get_scan_history(page=1, per_page=10, search="", risk_filter="all", user_id=None):
    per_page = min(max(per_page, 1), 50)
    page = max(page, 1)

    base_query = ScanHistory.query
    if user_id:
        base_query = base_query.filter(ScanHistory.user_id == user_id)

    distribution = {
        verdict: base_query.filter(ScanHistory.prediction == verdict).count()
        for verdict in ("safe", "suspicious", "malicious")
    }

    query = base_query

    if search:
        q = f"%{search}%"
        query = query.filter(
            ScanHistory.scanned_url.ilike(q) | ScanHistory.scan_id.ilike(q)
        )

    if risk_filter and risk_filter != "all":
        query = query.filter(ScanHistory.prediction == risk_filter)

    total = query.count()
    items_raw = (
        query.order_by(ScanHistory.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    user_emails = {}
    user_ids = {r.user_id for r in items_raw if r.user_id}
    if user_ids:
        users = User.query.with_entities(User.id, User.email).filter(User.id.in_(user_ids)).all()
        user_emails = {u.id: u.email for u in users}

    items = []
    for row in items_raw:
        display_url = row.scanned_url
        try:
            import json
            if row.result_json:
                parsed = json.loads(row.result_json)
                display_url = parsed.get("final_url") or parsed.get("decoded_url") or row.scanned_url
        except Exception:
            display_url = row.scanned_url
        items.append({
            "scan_id": row.scan_id,
            "url": display_url,
            "qr_url": row.scanned_url,
            "verdict": row.prediction,
            "risk_score": row.risk_score,
            "scanned_at": row.timestamp.strftime("%Y-%m-%d %H:%M"),
            "source": row.source,
            "user": user_emails.get(row.user_id, "anonymous"),
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "verdict_distribution": distribution,
    }


def get_dashboard_stats():
    today_start = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    totals = db.session.query(
        func.count(ScanHistory.id).label("total_scans"),
        func.sum(case((ScanHistory.prediction == "malicious", 1), else_=0)).label("threats"),
        func.sum(case((ScanHistory.prediction == "safe", 1), else_=0)).label("safe"),
        func.avg(ScanHistory.scan_duration_ms).label("avg_time"),
    ).one()

    total_scans = totals.total_scans or 0
    threats = int(totals.threats or 0)
    safe = int(totals.safe or 0)
    avg_time = int(totals.avg_time or 650)

    scans_today = ScanHistory.query.filter(ScanHistory.timestamp >= today_start).count()
    active_users = User.query.filter(User.is_active.is_(True)).count()

    malicious_rate = round((threats / total_scans * 100), 1) if total_scans else 0.0

    chart_data = _chart_last_7_days()
    verdict_dist = _verdict_distribution()
    recent = _recent_activity()

    return {
        "total_scans": total_scans,
        "scans_today": scans_today,
        "threats_blocked": threats,
        "safe_urls": safe,
        "avg_scan_time_ms": avg_time,
        "active_users": active_users,
        "malicious_rate": malicious_rate,
        "recent_activity": recent,
        "chart_labels": chart_data["labels"],
        "chart_scans": chart_data["scans"],
        "chart_threats": chart_data["threats"],
        "verdict_distribution": verdict_dist,
    }


def _chart_last_7_days():
    labels = []
    scans = []
    threats = []
    for i in range(6, -1, -1):
        day = (_utcnow() - timedelta(days=i)).date()
        labels.append(day.strftime("%a"))
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        day_scans = ScanHistory.query.filter(
            and_(ScanHistory.timestamp >= day_start, ScanHistory.timestamp < day_end)
        ).count()
        day_threats = ScanHistory.query.filter(
            and_(
                ScanHistory.timestamp >= day_start,
                ScanHistory.timestamp < day_end,
                ScanHistory.prediction == "malicious",
            )
        ).count()
        scans.append(day_scans)
        threats.append(day_threats)
    return {"labels": labels, "scans": scans, "threats": threats}


def _verdict_distribution():
    safe = ScanHistory.query.filter_by(prediction="safe").count()
    suspicious = ScanHistory.query.filter_by(prediction="suspicious").count()
    malicious = ScanHistory.query.filter_by(prediction="malicious").count()
    return {
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious,
    }


def _recent_activity():
    logs = (
        AuditLog.query.with_entities(AuditLog.event, AuditLog.details, AuditLog.timestamp)
        .order_by(AuditLog.timestamp.desc())
        .limit(6)
        .all()
    )
    activity = []
    for log in logs:
        act_type = "info"
        if "failed" in log.event or "blocked" in log.event or "malicious" in log.event:
            act_type = "danger"
        elif "suspicious" in log.event:
            act_type = "warning"
        elif "scan" in log.event and "completed" in log.event:
            act_type = "success"
        delta = _utcnow() - log.timestamp
        if delta.total_seconds() < 3600:
            time_str = f"{int(delta.total_seconds() // 60)} min ago"
        elif delta.days == 0:
            time_str = f"{int(delta.total_seconds() // 3600)} hr ago"
        else:
            time_str = log.timestamp.strftime("%Y-%m-%d %H:%M")
        activity.append({
            "action": log.event.replace("_", " ").title(),
            "detail": (log.details or "")[:80],
            "time": time_str,
            "type": act_type,
        })
    return activity


def get_admin_stats():
    total_users = User.query.count()
    total_scans = ScanHistory.query.count()

    week_ago = _utcnow() - timedelta(days=7)
    malicious_trend = []
    for i in range(6, -1, -1):
        day = (_utcnow() - timedelta(days=i)).date()
        day_start = datetime.combine(day, datetime.min.time())
        day_end = day_start + timedelta(days=1)
        count = ScanHistory.query.filter(
            and_(
                ScanHistory.timestamp >= day_start,
                ScanHistory.timestamp < day_end,
                ScanHistory.prediction == "malicious",
            )
        ).count()
        malicious_trend.append(count)

    users_growth = _users_growth()

    top_domains = (
        db.session.query(ScanHistory.domain, func.count(ScanHistory.id).label("cnt"))
        .filter(ScanHistory.prediction.in_(["malicious", "suspicious"]))
        .group_by(ScanHistory.domain)
        .order_by(func.count(ScanHistory.id).desc())
        .limit(5)
        .all()
    )

    users = (
        User.query.with_entities(
            User.id, User.email, User.role, User.is_active, User.last_login
        )
        .order_by(User.created_at.desc())
        .limit(20)
        .all()
    )

    user_list = []
    for u in users:
        scan_count = ScanHistory.query.filter_by(user_id=u.id).count()
        user_list.append({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "scans": scan_count,
            "status": "active" if u.is_active else "suspended",
            "last_login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never",
        })

    return {
        "total_users": total_users,
        "active_sessions": User.query.filter(User.last_login >= week_ago).count(),
        "total_scans_all_time": total_scans,
        "malicious_trend": malicious_trend or [0] * 7,
        "users_growth": users_growth,
        "top_threat_domains": [
            {"domain": d.domain, "count": d.cnt} for d in top_domains
        ],
        "users": user_list,
        "system_health": {
            "api": 100.0,
            "database": 100.0,
            "ml_service": 100.0 if os.path.exists(os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml", "model.pkl")) else 0.0,
            "storage": _storage_health(),
        },
    }


def _storage_health():
    try:
        from flask import current_app
        upload_folder = current_app.config["UPLOAD_FOLDER"]
        max_bytes = current_app.config.get("MAX_UPLOAD_FOLDER_BYTES", 200 * 1024 * 1024)
        used = 0
        for root, _dirs, files in os.walk(upload_folder):
            for filename in files:
                path = os.path.join(root, filename)
                if os.path.isfile(path):
                    used += os.path.getsize(path)
        if max_bytes <= 0:
            return 0.0
        return round(max(0.0, 100 - (used / max_bytes * 100)), 1)
    except Exception:
        return 0.0


def _users_growth():
    counts = []
    for weeks in range(6, 0, -1):
        cutoff = _utcnow() - timedelta(weeks=weeks)
        counts.append(User.query.filter(User.created_at <= cutoff).count())
    counts.append(User.query.count())
    return counts or [0] * 7


def get_live_stats():
    total_scans = ScanHistory.query.count()
    threats = ScanHistory.query.filter_by(prediction="malicious").count()
    urls = ScanHistory.query.with_entities(func.count(func.distinct(ScanHistory.domain))).scalar() or 0
    return {
        "scans_processed": total_scans,
        "threats_detected": threats,
        "urls_analyzed": urls,
        "uptime_percent": 99.97,
    }


def is_domain_blacklisted(domain):
    if not domain:
        return False, None
    domain = domain.lower().strip(".")
    exact = BlockedDomain.query.filter_by(domain=domain).first()
    if exact:
        return True, exact.threat_level
    entries = BlockedDomain.query.with_entities(
        BlockedDomain.domain, BlockedDomain.threat_level
    ).all()
    for bd_domain, level in entries:
        if domain == bd_domain or domain.endswith("." + bd_domain) or bd_domain in domain:
            return True, level
    return False, None
