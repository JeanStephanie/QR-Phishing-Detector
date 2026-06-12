from flask import render_template, abort, current_app, flash, redirect, request, url_for
from flask_login import login_required, current_user

from extensions import db, limiter
from models import ScanHistory, User
from routes.blueprints import main_bp
from services.database_service import get_admin_stats
from services.logger import log_event
from utils.validators import validate_password_strength


def _require_admin():
    if not current_user.is_authenticated or current_user.role != "admin":
        abort(403)


@main_bp.route("/admin")
@login_required
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_ADMIN", "20 per hour"))
def admin():
    _require_admin()
    admin_data = get_admin_stats()
    return render_template("admin.html", admin=admin_data)


def _get_managed_user(user_id):
    _require_admin()
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    return user


def _admin_redirect():
    return redirect(url_for("main.admin"))


@main_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
def admin_reset_password(user_id):
    user = _get_managed_user(user_id)
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    if password != confirm:
        flash("Passwords do not match.", "danger")
        return _admin_redirect()
    if not validate_password_strength(password):
        flash("Password must be at least 12 characters with uppercase, lowercase, number, and symbol.", "danger")
        return _admin_redirect()
    user.set_password(password)
    db.session.commit()
    log_event("admin_password_reset", user_id=current_user.id, details=user.email[:120])
    flash(f"Password reset for {user.email}.", "success")
    return _admin_redirect()


@main_bp.route("/admin/users/<int:user_id>/toggle-status", methods=["POST"])
@login_required
def admin_toggle_user_status(user_id):
    user = _get_managed_user(user_id)
    if user.id == current_user.id:
        flash("You cannot suspend your own admin account.", "warning")
        return _admin_redirect()
    if user.role == "admin" and user.is_active:
        active_admins = User.query.filter_by(role="admin", is_active=True).count()
        if active_admins <= 1:
            flash("At least one active admin account is required.", "warning")
            return _admin_redirect()
    user.is_active = not user.is_active
    db.session.commit()
    action = "activated" if user.is_active else "suspended"
    log_event(f"admin_user_{action}", user_id=current_user.id, details=user.email[:120])
    flash(f"{user.email} has been {action}.", "success")
    return _admin_redirect()


@main_bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    user = _get_managed_user(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own admin account.", "warning")
        return _admin_redirect()
    if user.role == "admin":
        admin_count = User.query.filter_by(role="admin").count()
        if admin_count <= 1:
            flash("At least one admin account is required.", "warning")
            return _admin_redirect()
    email = user.email
    ScanHistory.query.filter_by(user_id=user.id).update({"user_id": None})
    db.session.delete(user)
    db.session.commit()
    log_event("admin_user_deleted", user_id=current_user.id, details=email[:120])
    flash(f"{email} has been deleted. Existing scans were kept anonymously.", "success")
    return _admin_redirect()
