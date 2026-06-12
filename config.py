import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration for SafeNet QR Shield."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "safenet-qr-shield-dev-key-change-in-production")
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'database.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    LOG_FOLDER = os.path.join(BASE_DIR, "logs")
    ML_MODEL_PATH = os.path.join(BASE_DIR, "ml", "model.pkl")

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    MAX_UPLOAD_FOLDER_BYTES = 200 * 1024 * 1024
    MAX_IMAGE_WIDTH = 4000
    MAX_IMAGE_HEIGHT = 4000
    MAX_IMAGE_PIXELS = 16_000_000
    UPLOAD_DELETE_DELAY_SECONDS = 30
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/webp"}

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    SCAN_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT_SCANS = 5
    SCAN_CACHE_TTL_SECONDS = 3600
    SSL_CACHE_TTL_SECONDS = 6 * 3600
    WHOIS_CACHE_TTL_SECONDS = 24 * 3600
    REQUEST_DEBOUNCE_SECONDS = 2

    BURST_THRESHOLD = 20
    BURST_WINDOW_SECONDS = 5
    BURST_BLOCK_MINUTES = 15
    LOCKDOWN_THRESHOLD = 100
    LOCKDOWN_DURATION_MINUTES = 10

    RATE_LIMIT_LOGIN = "5 per minute"
    RATE_LIMIT_REGISTER = "3 per minute"
    RATE_LIMIT_SCAN = "10 per minute"
    RATE_LIMIT_WEBCAM = "10 per minute"
    RATE_LIMIT_ADMIN = "20 per hour"
    RATE_LIMIT_HOME = "100 per hour"
    RATE_LIMIT_PREDICT = "10 per minute"

    PASSWORD_MIN_LENGTH = 12

    LOCKDOWN_MODE = False
    DEVELOPMENT_MODE = os.environ.get("FLASK_ENV", "development").lower() != "production"
    TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"
