import os
from flask import Flask, jsonify, request, redirect, url_for, flash
from flask_login import current_user
from flask_wtf.csrf import CSRFError, generate_csrf
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config
from extensions import db, login_manager, csrf, compress, limiter
from routes.main import main_bp, api_bp
from services.database_service import init_database
from services.ml_predictor import load_model
from utils.security_headers import apply_security_headers
from utils.rate_limit import rate_limit_exceeded_handler, get_client_ip, is_local_ip
from utils.abuse_protection import check_abuse_before_request


def create_app(config_class=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["LOG_FOLDER"], exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    compress.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api"):
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("main.login", next=request.full_path.rstrip("?")))

    @login_manager.user_loader
    def load_user(user_id):
        from models.user import User
        return db.session.get(User, int(user_id))

    with app.app_context():
        init_database(app)
        model_path = app.config["ML_MODEL_PATH"]
        if not os.path.exists(model_path):
            from ml.train_model import train
            train()
        load_model(model_path)

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    @limiter.request_filter
    def exempt_development_and_local_requests():
        return app.config.get("DEVELOPMENT_MODE", False) or is_local_ip(get_client_ip())

    @app.before_request
    def before_request():
        abuse_response = check_abuse_before_request()
        if abuse_response:
            return abuse_response

    @app.after_request
    def after_request(response):
        return apply_security_headers(response)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_large_request(e):
        if request.path.startswith("/api"):
            return jsonify({"error": "request failed", "message": "Request too large"}), 413
        return "Request Entity Too Large", 413

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api"):
            return jsonify({"error": "request failed"}), 404
        return e

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api"):
            return jsonify({"error": "request failed"}), 403
        return e

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if request.path.startswith("/api") or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "request failed", "message": "Invalid or expired CSRF token"}), 400
        flash("Your form session expired. Please try again.", "warning")
        return redirect(request.referrer or url_for("main.home"))

    @app.errorhandler(429)
    def too_many(e):
        return rate_limit_exceeded_handler(e)

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        if request.path.startswith("/api"):
            return jsonify({"error": "request failed"}), 500
        return "An error occurred", 500

    @app.context_processor
    def inject_globals():
        from flask import session
        return {
            "app_name": "SafeNet QR Shield",
            "user_email": session.get("user_email"),
            "is_logged_in": session.get("logged_in", False),
            "is_admin": current_user.is_authenticated and current_user.role == "admin",
            "csrf_token": generate_csrf,
        }

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
