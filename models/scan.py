from datetime import datetime, timezone

from extensions import db


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(16), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    qr_content = db.Column(db.Text, nullable=True)
    scanned_url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), nullable=False, index=True)
    prediction = db.Column(db.String(20), nullable=False)
    phishing_probability = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    source = db.Column(db.String(20), nullable=False, default="upload")
    scan_duration_ms = db.Column(db.Integer, nullable=False, default=0)
    result_json = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=_utcnow, index=True)

    __table_args__ = (
        db.Index("ix_scan_history_user_timestamp", "user_id", "timestamp"),
    )
