import io
import uuid
import threading
import time
from PIL import Image, ImageFile

ImageFile.LOAD_TRUNCATED_IMAGES = True
Image.MAX_IMAGE_PIXELS = 16_000_000

MAGIC_BYTES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "webp": b"RIFF",
}


def decode_qr_from_bytes(image_bytes):
    """Decode QR code from raw image bytes. Returns decoded string or None."""
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("RGB")
        results = pyzbar_decode(img)
        if results:
            return results[0].data.decode("utf-8", errors="replace").strip()
    except Exception:
        pass

    try:
        import cv2
        import numpy as np

        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if image is None:
            return None
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image)
        if data:
            return data.strip()
    except Exception:
        pass

    return None


def decode_qr_from_path(image_path):
    try:
        with open(image_path, "rb") as f:
            return decode_qr_from_bytes(f.read())
    except Exception:
        return None


def validate_image_bytes(image_bytes, config):
    if not image_bytes or len(image_bytes) > config.get("MAX_CONTENT_LENGTH", 5 * 1024 * 1024):
        return False, "File too large"

    if not _check_magic_bytes(image_bytes):
        return False, "Invalid file signature"

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()
    except Exception:
        return False, "Corrupted or invalid image"

    try:
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        max_w = config.get("MAX_IMAGE_WIDTH", 4000)
        max_h = config.get("MAX_IMAGE_HEIGHT", 4000)
        max_pixels = config.get("MAX_IMAGE_PIXELS", 16_000_000)
        if width > max_w or height > max_h:
            return False, "Image dimensions exceed limit"
        if width * height > max_pixels:
            return False, "Image pixel count exceeds limit"
        fmt = (img.format or "").upper()
        if fmt not in ("PNG", "JPEG", "WEBP"):
            return False, "Unsupported image format"
    except Exception:
        return False, "Invalid image"

    return True, None


def _check_magic_bytes(data):
    if data[:8] == MAGIC_BYTES["png"]:
        return True
    if data[:3] == MAGIC_BYTES["jpeg"]:
        return True
    if len(data) >= 12 and data[:4] == MAGIC_BYTES["webp"] and data[8:12] == b"WEBP":
        return True
    return False


def validate_extension(filename, allowed):
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[-1].lower()
    blocked = {"exe", "php", "bat", "sh", "py", "js", "zip", "rar", "7z", "svg", "gif", "pdf", "txt"}
    if ext in blocked:
        return False
    return ext in allowed


def validate_mime(file_storage, allowed_mimes):
    file_storage.stream.seek(0)
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if header[:8] == MAGIC_BYTES["png"]:
        mime = "image/png"
    elif header[:3] == MAGIC_BYTES["jpeg"]:
        mime = "image/jpeg"
    elif len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        mime = "image/webp"
    else:
        mime = file_storage.mimetype or ""
    return mime in allowed_mimes, mime


def save_temp_upload(file_storage, upload_folder):
    file_storage.stream.seek(0)
    data = file_storage.read()
    unique_name = f"{uuid.uuid4().hex}.bin"
    import os
    os.makedirs(upload_folder, exist_ok=True)
    path = os.path.join(upload_folder, unique_name)
    with open(path, "wb") as f:
        f.write(data)
    return path, data, unique_name


def schedule_file_deletion(filepath, delay_seconds=30):
    def _delete():
        time.sleep(delay_seconds)
        try:
            import os
            if os.path.exists(filepath):
                os.remove(filepath)
        except OSError:
            pass

    threading.Thread(target=_delete, daemon=True).start()
