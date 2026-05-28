import os
from datetime import timedelta


class Config:
    """Application configuration for SafeNet QR Shield."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "safenet-qr-shield-dev-key-change-in-production")
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}

    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Demo mode: frontend uses mock scan data until ML/cyber modules integrate
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
