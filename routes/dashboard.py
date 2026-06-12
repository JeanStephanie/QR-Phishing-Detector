from flask import render_template, request
from flask_login import login_required, current_user

from routes.blueprints import main_bp
from services.database_service import get_dashboard_stats, get_scan_history


@main_bp.route("/dashboard")
@login_required
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@main_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "")
    risk_filter = request.args.get("risk", "all")
    history_data = get_scan_history(
        page=page, per_page=10, search=search, risk_filter=risk_filter,
        user_id=current_user.id,
    )
    return render_template(
        "history.html", history=history_data, search=search, risk_filter=risk_filter,
    )
