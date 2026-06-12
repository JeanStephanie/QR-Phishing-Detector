from flask import request, jsonify, session, current_app
from flask_login import current_user, login_required

from extensions import limiter
from routes.blueprints import api_bp
from services.database_service import (
    get_live_stats, get_dashboard_stats, get_scan_history, get_scan_result_for_user,
)
from services.scan_pipeline import process_webcam_payload
from utils.abuse_protection import is_lockdown_active
from services.logger import log_event


@api_bp.route("/stats/live")
def live_stats():
    return jsonify(get_live_stats())


@api_bp.route("/dashboard")
@login_required
def dashboard_data():
    return jsonify(get_dashboard_stats())


@api_bp.route("/history")
@login_required
def history_data():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "")
    risk_filter = request.args.get("risk", "all")
    user_id = current_user.id if current_user.is_authenticated else None
    return jsonify(get_scan_history(
        page=page, per_page=10, search=search, risk_filter=risk_filter, user_id=user_id,
    ))


@api_bp.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    if f"scan_{scan_id}" in session:
        return jsonify(session[f"scan_{scan_id}"])
    result = get_scan_result_for_user(
        scan_id, current_user.id, is_admin=current_user.role == "admin"
    )
    if result:
        return jsonify(result)
    return jsonify({"error": "request failed"}), 404


@api_bp.route("/webcam/complete", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_WEBCAM", "10 per minute"))
def webcam_complete():
    if is_lockdown_active():
        return jsonify({"success": False, "error": "request failed"}), 503

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Invalid JSON payload"}), 400
    user_id = current_user.id if current_user.is_authenticated else None

    result, error = process_webcam_payload(data, user_id=user_id)
    if error:
        log_event("webcam_scan_failed", user_id=user_id, details=error)
        return jsonify({"success": False, "error": error}), 400

    session[f"scan_{result['scan_id']}"] = result
    return jsonify({"success": True, "scan_id": result["scan_id"], "result": result})


@api_bp.errorhandler(Exception)
def api_error_handler(e):
    return jsonify({"error": "request failed"}), 500
