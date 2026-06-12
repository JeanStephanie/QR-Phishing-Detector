import os

from flask import (
    render_template, request, redirect, url_for,
    flash, session, jsonify, current_app, url_for as flask_url_for,
)
from flask_login import current_user

from extensions import limiter
from routes.blueprints import main_bp
from services.qr_decoder import (
    validate_extension, validate_mime, validate_image_bytes,
    save_temp_upload, schedule_file_deletion,
)
from services.scan_pipeline import process_uploaded_image
from services.database_service import get_scan_result_from_db
from utils.abuse_protection import is_lockdown_active, log_abuse_event, get_upload_folder_size, cleanup_oldest_uploads
from services.logger import log_event


@main_bp.route("/scan")
def scan():
    return render_template("scan.html")


@main_bp.route("/webcam")
def webcam():
    return render_template("webcam.html")


@main_bp.route("/upload", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATE_LIMIT_SCAN", "10 per minute"))
def upload():
    if is_lockdown_active():
        return _upload_error("Service temporarily unavailable", 503)

    if "qr_image" not in request.files:
        return _upload_error("No file provided", 400)

    file = request.files["qr_image"]
    if not file or file.filename == "":
        return _upload_error("No file selected", 400)

    allowed_ext = current_app.config.get("ALLOWED_EXTENSIONS", set())
    if not validate_extension(file.filename, allowed_ext):
        log_abuse_event("invalid_file_extension", file.filename[:100])
        return _upload_error("Invalid file type. Allowed: PNG, JPG, JPEG, WEBP", 400)

    allowed_mimes = current_app.config.get("ALLOWED_MIME_TYPES", set())
    mime_ok, _ = validate_mime(file, allowed_mimes)
    if not mime_ok:
        log_abuse_event("invalid_mime_type")
        return _upload_error("Invalid file type", 400)

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    max_folder = current_app.config.get("MAX_UPLOAD_FOLDER_BYTES", 200 * 1024 * 1024)
    if get_upload_folder_size(upload_folder) >= max_folder:
        cleanup_oldest_uploads(upload_folder, int(max_folder * 0.8))
        if get_upload_folder_size(upload_folder) >= max_folder:
            return _upload_error("Upload quota exceeded", 503)

    filepath, image_bytes, _unique_name = save_temp_upload(file, upload_folder)

    valid, err = validate_image_bytes(image_bytes, current_app.config)
    if not valid:
        try:
            os.remove(filepath)
        except OSError:
            pass
        log_abuse_event("invalid_image", err)
        return _upload_error(err or "Invalid image", 400)

    schedule_file_deletion(filepath, current_app.config.get("UPLOAD_DELETE_DELAY_SECONDS", 30))

    user_id = current_user.id if current_user.is_authenticated else None

    result, error = process_uploaded_image(image_bytes, user_id=user_id)
    if error:
        log_event("scan_failed", user_id=user_id, details=error)
        return _upload_error(error, 400)

    session[f"scan_{result['scan_id']}"] = result

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "success": True,
            "scan_id": result["scan_id"],
            "redirect": flask_url_for("main.result", scan_id=result["scan_id"]),
        })

    return redirect(url_for("main.result", scan_id=result["scan_id"]))


@main_bp.route("/result")
@main_bp.route("/result/<scan_id>")
def result(scan_id=None):
    scan_id = scan_id or request.args.get("scan_id")
    scan_result = None

    if scan_id and f"scan_{scan_id}" in session:
        scan_result = session[f"scan_{scan_id}"]
    elif scan_id:
        scan_result = get_scan_result_from_db(scan_id)

    if not scan_result:
        flash("Scan result not found.", "warning")
        return redirect(url_for("main.scan"))

    return render_template("result.html", result=scan_result)


def _upload_error(msg, code):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": False, "error": msg}), code
    flash(msg, "danger")
    return redirect(url_for("main.scan"))
