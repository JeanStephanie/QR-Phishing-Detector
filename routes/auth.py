from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from flask import render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user

from extensions import db, limiter
from models.user import User
from routes.blueprints import main_bp
from services.database_service import get_live_stats
from services.logger import log_event
from utils.validators import validate_email, validate_password_strength, contains_dangerous_chars
from utils.sanitizers import sanitize_text


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _safe_next_url(target):
    if not target:
        return None
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    if redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc:
        suffix = f"?{redirect_url.query}" if redirect_url.query else ""
        return redirect_url.path + suffix
    return None


@main_bp.route("/")
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_HOME", "100 per hour"))
def home():
    return render_template("index.html", live_stats=get_live_stats())


@main_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_LOGIN", "5 per minute"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = sanitize_text(request.form.get("email", ""), 255).lower()
        password = request.form.get("password", "")

        honeypot = request.form.get("website", "")
        if honeypot:
            log_event("bot_detected_login", details="honeypot triggered")
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        if contains_dangerous_chars(email):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user and user.is_active and user.check_password(password):
            remember = request.form.get("remember") == "on"
            login_user(user, remember=remember)
            user.last_login = _utcnow()
            db.session.commit()
            session["user_email"] = user.email
            session["logged_in"] = True
            session.permanent = True
            log_event("login_success", user_id=user.id)
            flash("Welcome back to SafeNet QR Shield.", "success")
            return redirect(_safe_next_url(request.args.get("next")) or url_for("main.dashboard"))

        log_event("login_failed", details=email[:100])
        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@main_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_REGISTER", "3 per minute"))
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = sanitize_text(request.form.get("email", ""), 255).lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        honeypot = request.form.get("website", "")
        if honeypot:
            log_event("bot_detected_register", details="honeypot triggered")
            flash("Registration failed.", "danger")
            return render_template("register.html")

        if not validate_email(email):
            flash("Invalid email address.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif not validate_password_strength(password):
            flash(
                "Password must be at least 12 characters with uppercase, lowercase, number, and symbol.",
                "danger",
            )
        elif User.query.filter_by(email=email).first():
            flash("Registration failed. Please try again.", "danger")
        else:
            username = email.split("@")[0][:32]
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"[:32]
                counter += 1

            user = User(username=username, email=email, role="user", is_active=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=False)
            session["user_email"] = user.email
            session["logged_in"] = True
            session.permanent = True
            log_event("register_success", user_id=user.id)
            flash("Account created successfully. Welcome to SafeNet!", "success")
            return redirect(url_for("main.dashboard"))

    return render_template("register.html")


@main_bp.route("/logout")
@login_required
def logout():
    log_event("logout", user_id=current_user.id)
    logout_user()
    session.pop("user_email", None)
    session.pop("logged_in", None)
    session.permanent = False
    flash("You have been logged out.", "info")
    return redirect(url_for("main.home"))
