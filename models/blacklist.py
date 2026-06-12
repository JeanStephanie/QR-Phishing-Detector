from extensions import db


class BlockedDomain(db.Model):
    __tablename__ = "blocked_domains"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    threat_level = db.Column(db.String(20), nullable=False, default="high")
