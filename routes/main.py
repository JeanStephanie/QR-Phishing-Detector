import os
import uuid
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    current_app,
)
from werkzeug.utils import secure_filename

from services.mock_data import (
    get_demo_scan_result,
    get_scan_history,
    get_dashboard_stats,
    get_admin_stats,
    get_live_stats,
)

main_bp = Blueprint("main", __name__)


def allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config.get("ALLOWED_EXTENSIONS", set())


@main_bp.route("/")
def home():
    return render_template("index.html", live_stats=get_live_stats())


@main_bp.route("/scan")
def scan():
    return render_template("scan.html")


@main_bp.route("/webcam")
def webcam():
    return render_template("webcam.html")


@main_bp.route("/upload", methods=["POST"])
def upload():
    """Handle QR image upload via AJAX or form post."""
    if "qr_image" not in request.files:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "No file provided"}), 400
        flash("No file selected.", "danger")
        return redirect(url_for("main.scan"))

    file = request.files["qr_image"]
    if not file or file.filename == "":
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": "No file selected"}), 400
        flash("No file selected.", "danger")
        return redirect(url_for("main.scan"))

    if not allowed_file(file.filename):
        msg = "Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP, BMP"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("main.scan"))

    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex[:12]}_{filename}"
    upload_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
    file.save(upload_path)

    scan_id = uuid.uuid4().hex[:8].upper()
    preview_url = url_for("static", filename=f"uploads/{unique_name}")

    # Demo result until ML/cyber modules integrate (Member 2+)
    result = get_demo_scan_result(scan_id=scan_id)
    result["preview_image"] = preview_url
    session[f"scan_{scan_id}"] = result

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "redirect": url_for("main.result", scan_id=scan_id),
            "preview_url": preview_url,
        })

    return redirect(url_for("main.result", scan_id=scan_id))


@main_bp.route("/result")
@main_bp.route("/result/<scan_id>")
def result(scan_id=None):
    scan_id = scan_id or request.args.get("scan_id")
    scan_result = None

    if scan_id and f"scan_{scan_id}" in session:
        scan_result = session[f"scan_{scan_id}"]
    elif scan_id:
        scan_result = get_demo_scan_result(scan_id=scan_id)
    else:
        scan_result = get_demo_scan_result()

    return render_template("result.html", result=scan_result)


@main_bp.route("/history")
def history():
    page = request.args.get("page", 1, type=int)
    search = request.args.get("q", "")
    risk_filter = request.args.get("risk", "all")
    history_data = get_scan_history(page=page, per_page=10, search=search, risk_filter=risk_filter)
    return render_template("history.html", history=history_data, search=search, risk_filter=risk_filter)


@main_bp.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@main_bp.route("/admin")
def admin():
    admin_data = get_admin_stats()
    return render_template("admin.html", admin=admin_data)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if email and password:
            session["user_email"] = email
            session["logged_in"] = True
            flash("Welcome back to SafeNet QR Shield.", "success")
            return redirect(url_for("main.dashboard"))
        flash("Invalid credentials. Please try again.", "danger")
    return render_template("login.html")


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not email or not password:
            flash("All fields are required.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            session["user_email"] = email
            session["logged_in"] = True
            flash("Account created successfully. Welcome to SafeNet!", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("register.html")


@main_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.home"))
