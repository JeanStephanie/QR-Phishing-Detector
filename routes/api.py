"""JSON API endpoints for AJAX frontend interactions."""

from flask import Blueprint, request, jsonify, session
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
    """Simulate webcam scan completion for frontend demo."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "https://scanned-via-webcam.example/path")
    result = get_demo_scan_result(decoded_url=url)
    session[f"scan_{result['scan_id']}"] = result
    return jsonify({"success": True, "scan_id": result["scan_id"], "result": result})
