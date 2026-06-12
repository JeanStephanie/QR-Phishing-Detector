import html
import re

_SCRIPT_PATTERN = re.compile(r"<\s*script", re.IGNORECASE)
_TAG_PATTERN = re.compile(r"<[^>]+>")


def sanitize_text(value, max_length=512):
    if value is None:
        return ""
    text = str(value).strip()
    text = _TAG_PATTERN.sub("", text)
    text = html.escape(text)
    if len(text) > max_length:
        text = text[:max_length]
    return text


def sanitize_search_query(query, max_length=100):
    if not query:
        return ""
    cleaned = re.sub(r"[^\w\s.\-/@:]", "", str(query).strip())
    return cleaned[:max_length]


def sanitize_filename(filename):
    if not filename:
        return ""
    name = filename.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^\w.\-]", "_", name)
    return name[:128]
