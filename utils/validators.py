import re

DANGEROUS_PATTERNS = re.compile(
    r"[<>;|&]|(\.\./)|(\.\\)|(\.\.)|(\/\/)|(\x00)|(\$\()|(`)"
)
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>_\-\[\]\\\/]).{12,128}$"
)


def contains_dangerous_chars(value):
    if not value:
        return False
    return bool(DANGEROUS_PATTERNS.search(str(value)))


def validate_email(email):
    if not email or contains_dangerous_chars(email):
        return False
    return bool(EMAIL_PATTERN.match(email.strip()))


def validate_username(username):
    if not username or contains_dangerous_chars(username):
        return False
    return bool(USERNAME_PATTERN.match(username.strip()))


def validate_password_strength(password):
    if not password or contains_dangerous_chars(password):
        return False
    return bool(PASSWORD_PATTERN.match(password))


def validate_url_input(url):
    if not url or len(url) > 2048:
        return False
    if contains_dangerous_chars(url):
        return False
    return url.startswith(("http://", "https://"))
