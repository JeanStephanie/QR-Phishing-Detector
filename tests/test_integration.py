import base64
import io
import os
import re
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import cv2

from app import create_app
from config import Config
from extensions import db
from models import BlockedIP, ScanHistory, User
from utils.cache import scan_cache


CSRF_PATTERN = re.compile(
    r'name="(?:csrf_token|csrf-token)" (?:value|content)="([^"]+)"'
)


class TestConfig(Config):
    TESTING = True
    DEVELOPMENT_MODE = False
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = False
    SERVER_NAME = "localhost"
    UPLOAD_DELETE_DELAY_SECONDS = 0


class SafeNetIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        TestConfig.SQLALCHEMY_DATABASE_URI = (
            "sqlite:///" + os.path.join(cls.temp_dir.name, "test.db").replace("\\", "/")
        )
        TestConfig.UPLOAD_FOLDER = os.path.join(cls.temp_dir.name, "uploads")
        TestConfig.LOG_FOLDER = os.path.join(cls.temp_dir.name, "logs")
        cls.app = create_app(TestConfig)

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            ScanHistory.query.delete()
            User.query.filter(User.email != "admin@safenet.io").delete()
            BlockedIP.query.delete()
            db.session.commit()
        scan_cache._store.clear()

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        match = CSRF_PATTERN.search(response.get_data(as_text=True))
        self.assertIsNotNone(
            match,
            f"CSRF token missing from {path}: status={response.status_code} "
            f"body={response.get_data(as_text=True)[:200]}",
        )
        return match.group(1)

    def register(self, email="person@example.com"):
        token = self.csrf_token("/register")
        return self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "email": email,
                "password": "StrongPassword@123",
                "confirm_password": "StrongPassword@123",
            },
            follow_redirects=False,
        )

    def login(self, email="person@example.com", password="StrongPassword@123", remember=False):
        token = self.csrf_token("/login")
        data = {"csrf_token": token, "email": email, "password": password}
        if remember:
            data["remember"] = "on"
        return self.client.post("/login", data=data, follow_redirects=False)

    @staticmethod
    def qr_image(extension):
        encoder = cv2.QRCodeEncoder_create()
        image = encoder.encode("https://example.com/security-check")
        image = cv2.copyMakeBorder(image, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
        image = cv2.resize(image, None, fx=12, fy=12, interpolation=cv2.INTER_NEAREST)
        ok, encoded = cv2.imencode(extension, image)
        if not ok:
            raise AssertionError(f"Could not create {extension} test image")
        return encoded.tobytes()

    def analysis_patches(self):
        security = {
            "security_score": 5,
            "domain": "example.com",
            "ssl_status": "valid",
            "ssl_details": "Valid TLS certificate",
            "blacklist_status": "clean",
            "blacklist_sources": [],
            "indicators": [{"type": "ssl", "severity": "low", "message": "Valid HTTPS"}],
            "domain_age_days": 9000,
            "redirect_chain": ["https://example.com/security-check"],
        }
        features = {
            "url_length": 34,
            "num_dots": 1,
            "num_hyphen": 1,
            "contains_ip": 0,
            "has_https": 1,
            "domain_age": 9000,
            "suspicious_words": 0,
            "redirect_count": 0,
            "entropy_score": 3.5,
            "domain": "example.com",
        }
        stack = ExitStack()
        stack.enter_context(patch("services.scan_pipeline._build_features", return_value=features))
        stack.enter_context(
            patch("services.security_engine.run_security_analysis", return_value=security)
        )
        stack.enter_context(
            patch(
                "services.scan_pipeline.detect_redirects",
                return_value=(0, ["https://example.com/security-check"]),
            )
        )
        stack.enter_context(patch("services.scan_pipeline.predict_phishing", return_value=4.0))
        return stack

    def test_public_pages_and_localhost_never_blocked(self):
        for _ in range(30):
            self.assertEqual(self.client.get("/").status_code, 200)
        for path in ("/login", "/register", "/scan", "/webcam"):
            self.assertEqual(self.client.get(path).status_code, 200)
        with self.app.app_context():
            self.assertIsNone(BlockedIP.query.filter_by(ip_address="127.0.0.1").first())

    def test_csrf_is_required(self):
        response = self.client.post(
            "/upload",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["message"], "Invalid or expired CSRF token")

    def test_registration_login_remember_logout_and_protected_pages(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/dashboard"))
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/history").status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 403)

        self.assertEqual(self.client.get("/logout").status_code, 302)
        response = self.login(remember=True)
        self.assertEqual(response.status_code, 302)
        self.assertIn("remember_token=", response.headers.get("Set-Cookie", ""))
        self.assertEqual(self.client.get("/logout").status_code, 302)

        invalid = self.login(password="wrong-password")
        self.assertEqual(invalid.status_code, 200)
        self.assertIn("Invalid credentials", invalid.get_data(as_text=True))

    def test_protected_apis_return_json_unauthorized(self):
        for path in ("/api/dashboard", "/api/history", "/api/scan/UNKNOWN"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.get_json()["error"], "authentication required")
        self.assertEqual(self.client.get("/api/stats/live").status_code, 200)

    def test_png_jpeg_webp_upload_webcam_and_database_flow(self):
        self.assertEqual(self.register().status_code, 302)
        uploaded_scan_ids = []

        with self.analysis_patches():
            for extension, filename, mimetype in (
                (".png", "code.png", "image/png"),
                (".jpg", "code.jpg", "image/jpeg"),
                (".webp", "code.webp", "image/webp"),
            ):
                token = self.csrf_token("/scan")
                response = self.client.post(
                    "/upload",
                    data={
                        "csrf_token": token,
                        "qr_image": (io.BytesIO(self.qr_image(extension)), filename, mimetype),
                    },
                    headers={
                        "X-Requested-With": "XMLHttpRequest",
                        "X-CSRFToken": token,
                    },
                    content_type="multipart/form-data",
                )
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                payload = response.get_json()
                self.assertTrue(payload["success"])
                uploaded_scan_ids.append(payload["scan_id"])
                self.assertEqual(self.client.get(payload["redirect"]).status_code, 200)

            token = self.csrf_token("/webcam")
            webcam_image = base64.b64encode(self.qr_image(".jpg")).decode("ascii")
            response = self.client.post(
                "/api/webcam/complete",
                json={"image": f"data:image/jpeg;base64,{webcam_image}"},
                headers={"X-CSRFToken": token},
            )
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
            webcam_scan_id = response.get_json()["scan_id"]

        history = self.client.get("/api/history").get_json()
        self.assertEqual(history["total"], 4)
        self.assertEqual(history["verdict_distribution"]["safe"], 4)
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        self.assertEqual(self.client.get(f"/api/scan/{uploaded_scan_ids[0]}").status_code, 200)
        self.assertEqual(self.client.get(f"/result/{webcam_scan_id}").status_code, 200)

    def test_admin_access(self):
        response = self.login("admin@safenet.io", "Admin@SafeNet123!")
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 200)
        self.assertIn("System overview", page.get_data(as_text=True))

    def test_admin_user_management(self):
        self.assertEqual(self.register("managed@example.com").status_code, 302)
        self.assertEqual(self.client.get("/logout").status_code, 302)
        self.assertEqual(self.login("admin@safenet.io", "Admin@SafeNet123!").status_code, 302)

        with self.app.app_context():
            managed_id = User.query.filter_by(email="managed@example.com").first().id

        token = self.csrf_token("/admin")
        response = self.client.post(
            f"/admin/users/{managed_id}/reset-password",
            data={
                "csrf_token": token,
                "password": "NewStrongPass@123",
                "confirm_password": "NewStrongPass@123",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        self.assertEqual(self.client.get("/logout").status_code, 302)
        self.assertEqual(
            self.login("managed@example.com", "NewStrongPass@123").status_code,
            302,
        )
        self.assertEqual(self.client.get("/logout").status_code, 302)
        self.assertEqual(self.login("admin@safenet.io", "Admin@SafeNet123!").status_code, 302)

        token = self.csrf_token("/admin")
        response = self.client.post(
            f"/admin/users/{managed_id}/toggle-status",
            data={"csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertFalse(db.session.get(User, managed_id).is_active)

        token = self.csrf_token("/admin")
        response = self.client.post(
            f"/admin/users/{managed_id}/delete",
            data={"csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, managed_id))


if __name__ == "__main__":
    unittest.main()
