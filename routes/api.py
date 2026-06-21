"""JSON API endpoints for AJAX frontend interactions."""

import os
import uuid

from flask import Blueprint, request, jsonify, session, current_app
from werkzeug.utils import secure_filename

from services.backend_api import BackendAPIError, analyze_qr_image, analyze_url
from services.mock_data import (
    get_demo_scan_result,
    get_scan_history,
    get_dashboard_stats,
    get_live_stats,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/stats/live")
def live_stats():
    return jsonify(get_live_stats())


@api_bp.route("/dashboard")
def dashboard_data():
    return jsonify(get_dashboard_stats())


@api_bp.route("/history")
def history_data():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "")
    risk_filter = request.args.get("risk", "all")
    return jsonify(get_scan_history(page=page, per_page=10, search=search, risk_filter=risk_filter))


@api_bp.route("/scan/<scan_id>")
def scan_detail(scan_id):
    if f"scan_{scan_id}" in session:
        return jsonify(session[f"scan_{scan_id}"])
    return jsonify(get_demo_scan_result(scan_id=scan_id))


@api_bp.route("/webcam/complete", methods=["POST"])
def webcam_complete():
    """Complete webcam scan using demo data or the real backend API."""
    if current_app.config.get("DEMO_MODE", True):
        data = request.get_json(silent=True) or {}
        url = data.get("url", "https://scanned-via-webcam.example/path")
        result = get_demo_scan_result(decoded_url=url)
        session[f"scan_{result['scan_id']}"] = result
        return jsonify({"success": True, "scan_id": result["scan_id"], "result": result})

    try:
        if "qr_image" in request.files:
            file = request.files["qr_image"]
            if not file or file.filename == "":
                return jsonify({"success": False, "error": "No webcam frame provided"}), 400

            filename = secure_filename(file.filename or "webcam-frame.jpg")
            unique_name = f"webcam_{uuid.uuid4().hex[:12]}_{filename}"
            upload_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
            os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
            file.save(upload_path)
            result = analyze_qr_image(current_app.config, upload_path, filename)
            result["preview_image"] = f"/static/uploads/{unique_name}"
        else:
            data = request.get_json(silent=True) or {}
            url = data.get("url")
            if not url:
                return jsonify({"success": False, "error": "No QR image or decoded URL provided"}), 400
            result = analyze_url(current_app.config, url)
    except BackendAPIError as exc:
        return jsonify({"success": False, "error": str(exc)}), 502

    session[f"scan_{result['scan_id']}"] = result
    return jsonify({"success": True, "scan_id": result["scan_id"], "result": result})
